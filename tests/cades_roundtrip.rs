//! Round trip: whatever goes into a CAdES B-B through the two phases comes back out of `decode`.

mod common;

use der::asn1::{Any, ObjectIdentifier, OctetString, Utf8StringRef};
use der::{Decode, Encode, Reader, SliceReader};
use ecdsa::signature::hazmat::PrehashVerifier;
use proptest::prelude::*;
use rades::cades::{
    self, Certificates, Content, ContentHints, ContentReference, Options, SigningCertificate,
};
use rades::{DigestAlgorithm, SignatureAlgorithm, SigningTime};
use rsa::pkcs8::DecodePublicKey;
use rsa::{Pkcs1v15Sign, Pss, RsaPublicKey};
use sha2::Digest as _;

const SIGNERS: [&str; 4] = [
    "signer-rsa",
    "signer-ecdsa",
    "signer-ecdsa-p384",
    "signer-ecdsa-p521",
];
const DIGESTS: [DigestAlgorithm; 6] = [
    DigestAlgorithm::Sha256,
    DigestAlgorithm::Sha384,
    DigestAlgorithm::Sha512,
    DigestAlgorithm::Sha3_256,
    DigestAlgorithm::Sha3_384,
    DigestAlgorithm::Sha3_512,
];
/// Per digest: its OID, then the OIDs of RSA PKCS#1 v1.5 and ECDSA with it.
const OIDS: [(&str, &str, &str); 6] = [
    (
        "2.16.840.1.101.3.4.2.1",
        "1.2.840.113549.1.1.11",
        "1.2.840.10045.4.3.2",
    ),
    (
        "2.16.840.1.101.3.4.2.2",
        "1.2.840.113549.1.1.12",
        "1.2.840.10045.4.3.3",
    ),
    (
        "2.16.840.1.101.3.4.2.3",
        "1.2.840.113549.1.1.13",
        "1.2.840.10045.4.3.4",
    ),
    (
        "2.16.840.1.101.3.4.2.8",
        "2.16.840.1.101.3.4.3.14",
        "2.16.840.1.101.3.4.3.10",
    ),
    (
        "2.16.840.1.101.3.4.2.9",
        "2.16.840.1.101.3.4.3.15",
        "2.16.840.1.101.3.4.3.11",
    ),
    (
        "2.16.840.1.101.3.4.2.10",
        "2.16.840.1.101.3.4.3.16",
        "2.16.840.1.101.3.4.3.12",
    ),
];
/// The P-521 prehash signer of the test helpers rejects digests under 33 bytes.
const P521: usize = 3;
const SHORT_DIGESTS: [usize; 2] = [0, 3];
const ID_RSASSA_PSS: &str = "1.2.840.113549.1.1.10";
const MIME_TYPE: &str = "0.4.0.1733.2.1";
const CONTENT_HINTS: &str = "1.2.840.113549.1.9.16.2.4";
const CONTENT_IDENTIFIER: &str = "1.2.840.113549.1.9.16.2.7";
const CONTENT_REFERENCE: &str = "1.2.840.113549.1.9.16.2.10";

/// From 2026-10-21T12:00:00Z, after the test signers' `notBefore`, to the year 2122.
const SIGNING_TIMES: std::ops::Range<u64> = 1_792_584_000..4_800_000_000;
/// 2050-01-01T00:00:00Z, where `UTCTime` gives way to `GeneralizedTime`.
const YEAR_2050: u64 = 2_524_608_000;

fn oid(text: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(text)
}

fn content() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(Vec::new()),
        prop::collection::vec(any::<u8>(), 1..256),
        (any::<u8>(), 20_000..70_000usize).prop_map(|(byte, len)| vec![byte; len]),
    ]
}

fn signing_time() -> impl Strategy<Value = u64> {
    prop_oneof![
        SIGNING_TIMES,
        (YEAR_2050 - 5)..(YEAR_2050 + 5),
        Just(SIGNING_TIMES.start),
    ]
}

fn object_identifier() -> impl Strategy<Value = ObjectIdentifier> {
    (
        0..3u32,
        1..40u32,
        prop::collection::vec(1..100_000u32, 0..5),
    )
        .prop_map(|(first, second, rest)| {
            let arcs: Vec<String> = [first, second]
                .into_iter()
                .chain(rest)
                .map(|arc| arc.to_string())
                .collect();
            oid(&arcs.join("."))
        })
}

fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..40)
}

fn text() -> impl Strategy<Value = String> {
    "[ -~]{0,30}"
}

#[derive(Debug, Clone)]
struct Case {
    attached: bool,
    content: Vec<u8>,
    signing_time: u64,
    signer: usize,
    pss: bool,
    digest: usize,
    mime_type: Option<String>,
    hints: Option<(Option<String>, ObjectIdentifier)>,
    identifier: Option<Vec<u8>>,
    reference: Option<(ObjectIdentifier, Vec<u8>, Vec<u8>)>,
    /// 0 signer only, 1 with its chain, 2 none.
    certificates: u8,
}

fn case() -> impl Strategy<Value = Case> {
    let basics = (
        any::<bool>(),
        content(),
        signing_time(),
        0..SIGNERS.len(),
        any::<bool>(),
        0..DIGESTS.len(),
    );
    let attributes = (
        prop::option::of(text()),
        prop::option::of((prop::option::of(text()), object_identifier())),
        prop::option::of(bytes()),
        prop::option::of((object_identifier(), bytes(), bytes())),
        0..3u8,
    );
    (basics, attributes).prop_map(
        |(
            (attached, content, signing_time, signer, pss, digest),
            (mime_type, hints, identifier, reference, certificates),
        )| Case {
            attached,
            content,
            signing_time,
            signer,
            pss,
            digest: if signer == P521 && SHORT_DIGESTS.contains(&digest) {
                digest + 1
            } else {
                digest
            },
            mime_type,
            hints,
            identifier,
            reference,
            certificates,
        },
    )
}

fn hash(digest: DigestAlgorithm, data: &[u8]) -> Vec<u8> {
    match digest {
        DigestAlgorithm::Sha256 => sha2::Sha256::digest(data).to_vec(),
        DigestAlgorithm::Sha384 => sha2::Sha384::digest(data).to_vec(),
        DigestAlgorithm::Sha512 => sha2::Sha512::digest(data).to_vec(),
        DigestAlgorithm::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
        DigestAlgorithm::Sha3_384 => sha3::Sha3_384::digest(data).to_vec(),
        DigestAlgorithm::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
        _ => unreachable!(),
    }
}

/// The children of a DER `SEQUENCE`, each as its full encoding.
fn children(sequence: &[u8]) -> Vec<Vec<u8>> {
    let any = Any::from_der(sequence).unwrap();
    let mut reader = SliceReader::new(any.value()).unwrap();
    let mut out = Vec::new();
    while !reader.is_finished() {
        out.push(Any::decode(&mut reader).unwrap().to_der().unwrap());
    }
    out
}

fn octets(der: &[u8]) -> Vec<u8> {
    OctetString::from_der(der).unwrap().into_bytes().into_vec()
}

fn der_wrap(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap());
    } else {
        out.extend([0x81, u8::try_from(len).unwrap()]);
    }
    out.extend_from_slice(content);
    out
}

/// RFC 4055 `RSASSA-PSS-params`: hash and MGF1 with NULL parameters, salt as long as the digest.
fn pss_params(digest_oid: &str, salt_len: usize) -> Vec<u8> {
    let mut hash = oid(digest_oid).to_der().unwrap();
    hash.extend([5, 0]);
    let hash = der_wrap(0x30, &hash);
    let mut mgf1 = oid("1.2.840.113549.1.1.8").to_der().unwrap();
    mgf1.extend(&hash);
    let mut body = der_wrap(0xa0, &hash);
    body.extend(der_wrap(0xa1, &der_wrap(0x30, &mgf1)));
    body.extend(der_wrap(
        0xa2,
        &der_wrap(0x02, &[u8::try_from(salt_len).unwrap()]),
    ));
    der_wrap(0x30, &body)
}

/// PKCS#1 v1.5 `DigestInfo`, built here from the digest's OID.
fn digest_info(digest_oid: &str, hash: &[u8]) -> Vec<u8> {
    let mut algorithm = oid(digest_oid).to_der().unwrap();
    algorithm.extend([5, 0]);
    let mut body = der_wrap(0x30, &algorithm);
    body.extend(der_wrap(0x04, hash));
    der_wrap(0x30, &body)
}

fn verify(
    signer: &str,
    algorithm: SignatureAlgorithm,
    digest_oid: &str,
    hash: &[u8],
    value: &[u8],
) {
    let spki = common::certificate_spki(signer);
    match algorithm {
        SignatureAlgorithm::RsaPkcs1v15(_) => {
            RsaPublicKey::from_public_key_der(&spki)
                .unwrap()
                .verify(
                    Pkcs1v15Sign::new_unprefixed(),
                    &digest_info(digest_oid, hash),
                    value,
                )
                .unwrap();
        }
        SignatureAlgorithm::RsaPss(digest) => {
            let scheme = match digest {
                DigestAlgorithm::Sha256 => Pss::new::<sha2_10::Sha256>(),
                DigestAlgorithm::Sha384 => Pss::new::<sha2_10::Sha384>(),
                DigestAlgorithm::Sha512 => Pss::new::<sha2_10::Sha512>(),
                DigestAlgorithm::Sha3_256 => Pss::new::<sha3_10::Sha3_256>(),
                DigestAlgorithm::Sha3_384 => Pss::new::<sha3_10::Sha3_384>(),
                DigestAlgorithm::Sha3_512 => Pss::new::<sha3_10::Sha3_512>(),
                _ => unreachable!(),
            };
            RsaPublicKey::from_public_key_der(&spki)
                .unwrap()
                .verify(scheme, hash, value)
                .unwrap();
        }
        SignatureAlgorithm::Ecdsa(_) => {
            let point = common::certificate_point(signer);
            macro_rules! check {
                ($curve:ident) => {{
                    let key = $curve::ecdsa::VerifyingKey::from_sec1_bytes(&point).unwrap();
                    let signature = $curve::ecdsa::Signature::from_der(value).unwrap();
                    key.verify_prehash(hash, &signature).unwrap();
                }};
            }
            match signer {
                "signer-ecdsa" => check!(p256),
                "signer-ecdsa-p384" => check!(p384),
                _ => check!(p521),
            }
        }
        _ => unreachable!(),
    }
}

fn options(case: &Case) -> Options {
    let mut options = Options::default();
    if let Some(mime_type) = &case.mime_type {
        options = options.mime_type(mime_type.clone());
    }
    if let Some((description, content_type)) = &case.hints {
        options = options.content_hints(ContentHints::new(description.clone(), *content_type));
    }
    if let Some(identifier) = &case.identifier {
        options = options.content_identifier(identifier.clone());
    }
    if let Some((content_type, identifier, originator)) = &case.reference {
        options = options.content_reference(ContentReference {
            content_type: *content_type,
            signed_content_identifier: identifier.clone(),
            originator_signature_value: originator.clone(),
        });
    }
    options.certificates(match case.certificates {
        0 => Certificates::Signer,
        1 => Certificates::Chain(vec![
            common::certificate("intermediate"),
            common::certificate("root"),
        ]),
        _ => Certificates::None,
    })
}

fn check_hints(expected: Option<&(Option<String>, ObjectIdentifier)>, found: Option<Vec<u8>>) {
    match (expected, found) {
        (None, None) => {}
        (Some((description, content_type)), Some(der)) => {
            let parts = children(&der);
            let kind = if let Some(text) = description {
                assert_eq!(parts.len(), 2);
                let decoded = Utf8StringRef::from_der(&parts[0]).unwrap();
                assert_eq!(decoded.as_str(), text);
                &parts[1]
            } else {
                assert_eq!(parts.len(), 1);
                &parts[0]
            };
            assert_eq!(ObjectIdentifier::from_der(kind).unwrap(), *content_type);
        }
        (expected, found) => panic!("content-hints: expected {expected:?}, found {found:?}"),
    }
}

fn check_reference(
    expected: Option<&(ObjectIdentifier, Vec<u8>, Vec<u8>)>,
    found: Option<Vec<u8>>,
) {
    match (expected, found) {
        (None, None) => {}
        (Some((content_type, identifier, originator)), Some(der)) => {
            let parts = children(&der);
            assert_eq!(parts.len(), 3);
            assert_eq!(
                ObjectIdentifier::from_der(&parts[0]).unwrap(),
                *content_type
            );
            assert_eq!(&octets(&parts[1]), identifier);
            assert_eq!(&octets(&parts[2]), originator);
        }
        (expected, found) => panic!("content-reference: expected {expected:?}, found {found:?}"),
    }
}

fn round_trip(case: &Case) {
    let signer = SIGNERS[case.signer];
    let digest = DIGESTS[case.digest];
    let (digest_oid, rsa_oid, ecdsa_oid) = OIDS[case.digest];
    let (algorithm, signature_oid, signature_parameters) = match (case.signer, case.pss) {
        (0, false) => (
            SignatureAlgorithm::RsaPkcs1v15(digest),
            rsa_oid,
            Some(vec![5, 0]),
        ),
        (0, true) => (
            SignatureAlgorithm::RsaPss(digest),
            ID_RSASSA_PSS,
            Some(pss_params(digest_oid, hash(digest, &[]).len())),
        ),
        _ => (SignatureAlgorithm::Ecdsa(digest), ecdsa_oid, None),
    };
    let input = if case.attached {
        Content::Attached(&case.content)
    } else {
        Content::Detached(&case.content)
    };
    let time = SigningTime::from_unix_seconds(case.signing_time).unwrap();

    let pending = cades::sign(
        input,
        &common::certificate(signer),
        algorithm,
        time,
        &options(case),
    )
    .unwrap();
    let data = pending.data_to_sign()[0].clone();
    let value = match algorithm {
        SignatureAlgorithm::RsaPkcs1v15(_) => common::sign_rsa_pkcs1(signer, &data),
        SignatureAlgorithm::RsaPss(_) => common::sign_rsa_pss(signer, &data),
        _ => common::sign_ecdsa(signer, &data),
    };
    let decoded = cades::decode(&pending.complete(&[value]).unwrap()).unwrap();

    assert_eq!(
        decoded.content(),
        case.attached.then_some(case.content.as_slice())
    );
    let [info] = decoded.signers() else {
        panic!("one signer expected")
    };
    assert_eq!(info.digest_algorithm().oid(), oid(digest_oid));
    assert_eq!(info.signature_algorithm().oid(), oid(signature_oid));
    assert_eq!(
        info.signature_algorithm().parameters(),
        signature_parameters.as_deref()
    );
    assert_eq!(
        info.message_digest(),
        Some(hash(digest, &case.content).as_slice())
    );
    assert_eq!(info.signing_time(), Some(time));

    let Some(SigningCertificate::V2(ids)) = info.signing_certificate() else {
        panic!("signing-certificate-v2 expected")
    };
    let [id] = ids.as_slice() else {
        panic!("one certificate expected")
    };
    assert_eq!(id.hash(), hash(digest, &common::certificate_der(signer)));

    if case.certificates == 2 {
        assert_eq!(info.certificate(), None);
    } else {
        assert_eq!(info.certificate(), Some(&common::certificate(signer)));
    }

    let single = |text: &str| {
        info.signed_attribute(oid(text)).map(|a| {
            assert_eq!(a.values().len(), 1);
            a.values()[0].clone()
        })
    };
    assert_eq!(
        single(MIME_TYPE),
        case.mime_type
            .as_ref()
            .map(|m| Utf8StringRef::new(m).unwrap().to_der().unwrap())
    );
    check_hints(case.hints.as_ref(), single(CONTENT_HINTS));
    assert_eq!(
        single(CONTENT_IDENTIFIER).map(|der| octets(&der)),
        case.identifier
    );
    check_reference(case.reference.as_ref(), single(CONTENT_REFERENCE));

    verify(
        signer,
        algorithm,
        digest_oid,
        &hash(digest, data.bytes()),
        info.signature_value(),
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn what_goes_into_a_signature_comes_back_out(case in case()) {
        round_trip(&case);
    }
}
