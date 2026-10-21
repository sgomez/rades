//! CAdES B-B through the two-phase API.

mod common;

use der::asn1::{ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use der::{Any, Decode, Encode};
use rades::cades::{
    self, Certificates, Content, ContentHints, ContentReference, Options, PendingSignature,
};
use rades::{DigestAlgorithm, Error, SignatureAlgorithm, SignatureValue, SigningTime};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};
use x509_cert::attr::Attribute;

const RSA_SHA256: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15(DigestAlgorithm::Sha256);
/// 2026-10-21T12:00:00Z, within the test signers' validity.
const SIGNING_TIME: u64 = 1_792_584_000;

/// Digest, its OID, its RSA PKCS#1 v1.5 signature OID and the golden vector's name.
const DIGESTS: [(DigestAlgorithm, &str, &str, &str); 6] = [
    (
        DigestAlgorithm::Sha256,
        "2.16.840.1.101.3.4.2.1",
        "1.2.840.113549.1.1.11",
        "sha256",
    ),
    (
        DigestAlgorithm::Sha384,
        "2.16.840.1.101.3.4.2.2",
        "1.2.840.113549.1.1.12",
        "sha384",
    ),
    (
        DigestAlgorithm::Sha512,
        "2.16.840.1.101.3.4.2.3",
        "1.2.840.113549.1.1.13",
        "sha512",
    ),
    (
        DigestAlgorithm::Sha3_256,
        "2.16.840.1.101.3.4.2.8",
        "2.16.840.1.101.3.4.3.14",
        "sha3-256",
    ),
    (
        DigestAlgorithm::Sha3_384,
        "2.16.840.1.101.3.4.2.9",
        "2.16.840.1.101.3.4.3.15",
        "sha3-384",
    ),
    (
        DigestAlgorithm::Sha3_512,
        "2.16.840.1.101.3.4.2.10",
        "2.16.840.1.101.3.4.3.16",
        "sha3-512",
    ),
];

fn expected_digest(digest: DigestAlgorithm, data: &[u8]) -> Vec<u8> {
    match digest {
        DigestAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        DigestAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
        DigestAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
        DigestAlgorithm::Sha3_256 => Sha3_256::digest(data).to_vec(),
        DigestAlgorithm::Sha3_384 => Sha3_384::digest(data).to_vec(),
        DigestAlgorithm::Sha3_512 => Sha3_512::digest(data).to_vec(),
        _ => unreachable!(),
    }
}

fn sign_detached(signer: &str) -> Result<PendingSignature, Error> {
    sign_detached_with(signer, RSA_SHA256)
}

fn sign_detached_with(
    signer: &str,
    algorithm: SignatureAlgorithm,
) -> Result<PendingSignature, Error> {
    cades::sign(
        Content::Detached(&common::read("cades/content.txt")),
        &common::certificate(signer),
        algorithm,
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        &Options::default(),
    )
}

fn signed_attribute(pending: &PendingSignature, oid: &str) -> Any {
    let attributes = SetOfVec::<Attribute>::from_der(pending.data_to_sign()[0].bytes()).unwrap();
    let oid = ObjectIdentifier::new_unwrap(oid);
    let attribute = attributes.iter().find(|a| a.oid == oid).unwrap();
    attribute.values.get(0).unwrap().clone()
}

#[test]
fn detached_rsa_sha256_matches_the_golden_vector() {
    let pending = sign_detached("signer-rsa").unwrap();
    let value = common::sign_rsa_pkcs1("signer-rsa", &pending.data_to_sign()[0]);
    let signature = pending.complete(&[value]).unwrap();
    common::assert_golden("cades/bb-detached-rsa-sha256.p7m", &signature);
}

#[test]
fn data_to_sign_offers_its_digest_and_digest_info() {
    let pending = sign_detached("signer-rsa").unwrap();
    let data = &pending.data_to_sign()[0];
    assert_eq!(data.algorithm(), RSA_SHA256);
    assert_eq!(data.digest(), Sha256::digest(data.bytes()).to_vec());
    // RFC 8017 section 9.2, note 1.
    let mut digest_info =
        b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20".to_vec();
    digest_info.extend(data.digest());
    assert_eq!(data.digest_info().unwrap(), digest_info);
}

#[test]
fn signed_attributes_are_those_of_cades_bb() {
    let pending = sign_detached("signer-rsa").unwrap();
    let attributes = SetOfVec::<Attribute>::from_der(pending.data_to_sign()[0].bytes()).unwrap();
    let mut oids: Vec<String> = attributes.iter().map(|a| a.oid.to_string()).collect();
    oids.sort();
    assert_eq!(
        oids,
        [
            "1.2.840.113549.1.9.16.2.47",
            "1.2.840.113549.1.9.3",
            "1.2.840.113549.1.9.4",
            "1.2.840.113549.1.9.5",
            "1.2.840.113549.1.9.52",
        ]
    );
}

#[test]
fn signed_attributes_carry_content_type_digest_and_time() {
    let pending = sign_detached("signer-rsa").unwrap();
    assert_eq!(
        signed_attribute(&pending, "1.2.840.113549.1.9.3")
            .decode_as::<ObjectIdentifier>()
            .unwrap(),
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1")
    );
    let content_digest = Sha256::digest(common::read("cades/content.txt"));
    assert_eq!(
        signed_attribute(&pending, "1.2.840.113549.1.9.4")
            .decode_as::<OctetString>()
            .unwrap()
            .as_bytes(),
        content_digest.as_slice()
    );
    assert_eq!(
        signed_attribute(&pending, "1.2.840.113549.1.9.5")
            .to_der()
            .unwrap(),
        UtcTime::from_der(b"\x17\x0d261021120000Z")
            .unwrap()
            .to_der()
            .unwrap()
    );
}

#[test]
fn signing_certificate_v2_identifies_the_signer_certificate() {
    let pending = sign_detached("signer-rsa").unwrap();
    let pem = std::fs::read_to_string(common::path("pki/signer-rsa.crt")).unwrap();
    let (_, der) = der::pem::decode_vec(pem.as_bytes()).unwrap();
    let mut expected = vec![0x04, 0x20];
    expected.extend(Sha256::digest(&der));
    let value = signed_attribute(&pending, "1.2.840.113549.1.9.16.2.47")
        .to_der()
        .unwrap();
    assert!(value.windows(expected.len()).any(|w| w == expected));
}

#[test]
fn phase_1_rejects_an_algorithm_that_does_not_fit_the_key() {
    let error = sign_detached("signer-ecdsa").unwrap_err();
    assert_eq!(
        error.to_string(),
        "signature algorithm RSA PKCS#1 v1.5 with SHA-256 does not fit the certificate's EC key"
    );
}

#[test]
fn phase_2_rejects_a_wrong_number_of_values() {
    for count in [0, 2] {
        let pending = sign_detached("signer-rsa").unwrap();
        let values = vec![SignatureValue::new(vec![1; 384]); count];
        assert_eq!(
            pending.complete(&values).unwrap_err(),
            Error::SignatureValueCount {
                expected: 1,
                actual: count
            }
        );
    }
}

#[test]
fn phase_2_rejects_an_rsa_value_shorter_than_the_modulus() {
    let pending = sign_detached("signer-rsa").unwrap();
    assert_eq!(
        pending
            .complete(&[SignatureValue::new(vec![1; 383])])
            .unwrap_err(),
        Error::SignatureValueLength {
            expected: 384,
            actual: 383
        }
    );
}

fn der_oid(oid: &str) -> Vec<u8> {
    ObjectIdentifier::new_unwrap(oid).to_der().unwrap()
}

#[test]
fn every_digest_has_a_golden_vector() {
    for (digest, _, _, name) in DIGESTS {
        let pending =
            sign_detached_with("signer-rsa", SignatureAlgorithm::RsaPkcs1v15(digest)).unwrap();
        let value = common::sign_rsa_pkcs1("signer-rsa", &pending.data_to_sign()[0]);
        let signature = pending.complete(&[value]).unwrap();
        common::assert_golden(&format!("cades/bb-detached-rsa-{name}.p7m"), &signature);
    }
}

#[test]
fn every_digest_hashes_the_content_and_the_data_to_sign() {
    let content = common::read("cades/content.txt");
    for (digest, _, _, _) in DIGESTS {
        let pending =
            sign_detached_with("signer-rsa", SignatureAlgorithm::RsaPkcs1v15(digest)).unwrap();
        let data = &pending.data_to_sign()[0];
        assert_eq!(data.digest(), expected_digest(digest, data.bytes()));
        assert_eq!(
            signed_attribute(&pending, "1.2.840.113549.1.9.4")
                .decode_as::<OctetString>()
                .unwrap()
                .as_bytes(),
            expected_digest(digest, &content)
        );
    }
}

#[test]
fn signing_certificate_v2_hashes_with_the_signatures_digest() {
    let pem = std::fs::read_to_string(common::path("pki/signer-rsa.crt")).unwrap();
    let (_, certificate) = der::pem::decode_vec(pem.as_bytes()).unwrap();
    for (digest, oid, _, _) in DIGESTS {
        let pending =
            sign_detached_with("signer-rsa", SignatureAlgorithm::RsaPkcs1v15(digest)).unwrap();
        let value = signed_attribute(&pending, "1.2.840.113549.1.9.16.2.47")
            .to_der()
            .unwrap();
        let hash = expected_digest(digest, &certificate);
        let mut expected = vec![0x04, u8::try_from(hash.len()).unwrap()];
        expected.extend(hash);
        assert!(value.windows(expected.len()).any(|w| w == expected));
        let oid = der_oid(oid);
        // SHA-256 is the DER default, so its identifier is absent.
        assert_eq!(
            value.windows(oid.len()).any(|w| w == oid),
            digest != DigestAlgorithm::Sha256
        );
    }
}

#[test]
fn cms_algorithm_protection_names_the_digest_and_signature_algorithms() {
    for (digest, digest_oid, signature_oid, _) in DIGESTS {
        let pending =
            sign_detached_with("signer-rsa", SignatureAlgorithm::RsaPkcs1v15(digest)).unwrap();
        // RFC 6211: SEQUENCE { digestAlgorithm, [1] IMPLICIT signatureAlgorithm }.
        let digest_algorithm = [&[0x30, 0x0b][..], &der_oid(digest_oid)].concat();
        let signature_algorithm =
            [&[0xa1, 0x0d][..], &der_oid(signature_oid), &[0x05, 0x00]].concat();
        let body = [digest_algorithm, signature_algorithm].concat();
        let mut expected = vec![0x30, u8::try_from(body.len()).unwrap()];
        expected.extend(body);
        assert_eq!(
            signed_attribute(&pending, "1.2.840.113549.1.9.52")
                .to_der()
                .unwrap(),
            expected
        );
    }
}

const MIME_TYPE: &str = "0.4.0.1733.2.1";
const CONTENT_HINTS: &str = "1.2.840.113549.1.9.16.2.4";
const CONTENT_IDENTIFIER: &str = "1.2.840.113549.1.9.16.2.7";
const CONTENT_REFERENCE: &str = "1.2.840.113549.1.9.16.2.10";
const ID_DATA: &str = "1.2.840.113549.1.7.1";

fn attribute_oids(pending: &PendingSignature) -> Vec<String> {
    SetOfVec::<Attribute>::from_der(pending.data_to_sign()[0].bytes())
        .unwrap()
        .iter()
        .map(|a| a.oid.to_string())
        .collect()
}

fn described() -> Options {
    Options::default()
        .mime_type("text/plain")
        .content_hints(ContentHints::new(
            Some("test content".to_owned()),
            ObjectIdentifier::new_unwrap(ID_DATA),
        ))
        .content_identifier(b"rades-content-1".to_vec())
        .content_reference(ContentReference {
            content_type: ObjectIdentifier::new_unwrap(ID_DATA),
            signed_content_identifier: b"rades-content-0".to_vec(),
            originator_signature_value: vec![0xAB; 4],
        })
}

fn sign_with_options(options: &Options) -> PendingSignature {
    cades::sign(
        Content::Detached(&common::read("cades/content.txt")),
        &common::certificate("signer-rsa"),
        RSA_SHA256,
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        options,
    )
    .unwrap()
}

fn embedded_certificates(signature: &[u8]) -> usize {
    ["signer-rsa", "intermediate", "root"]
        .iter()
        .filter(|name| {
            let pem = std::fs::read_to_string(common::path(&format!("pki/{name}.crt"))).unwrap();
            let der = der::pem::decode_vec(pem.as_bytes()).unwrap().1;
            signature.windows(der.len()).any(|w| w == der)
        })
        .count()
}

fn complete(pending: PendingSignature) -> Vec<u8> {
    let value = common::sign_rsa_pkcs1("signer-rsa", &pending.data_to_sign()[0]);
    pending.complete(&[value]).unwrap()
}

#[test]
fn optional_attributes_appear_only_when_set() {
    let oids = attribute_oids(&sign_with_options(&Options::default()));
    for oid in [
        MIME_TYPE,
        CONTENT_HINTS,
        CONTENT_IDENTIFIER,
        CONTENT_REFERENCE,
    ] {
        assert!(!oids.iter().any(|o| o == oid), "{oid}");
    }
    let oids = attribute_oids(&sign_with_options(
        &Options::default().mime_type("text/plain"),
    ));
    assert!(oids.iter().any(|o| o == MIME_TYPE));
    assert!(!oids.iter().any(|o| o == CONTENT_HINTS));
}

#[test]
fn optional_attributes_are_encoded_as_in_en_319_122_1() {
    let pending = sign_with_options(&described());
    assert_eq!(
        signed_attribute(&pending, MIME_TYPE).to_der().unwrap(),
        b"\x0c\x0atext/plain"
    );
    assert_eq!(
        signed_attribute(&pending, CONTENT_HINTS).to_der().unwrap(),
        b"\x30\x19\x0c\x0ctest content\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
    );
    assert_eq!(
        signed_attribute(&pending, CONTENT_IDENTIFIER)
            .to_der()
            .unwrap(),
        b"\x04\x0frades-content-1"
    );
    assert_eq!(
        signed_attribute(&pending, CONTENT_REFERENCE)
            .to_der()
            .unwrap(),
        b"\x30\x22\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01\x04\x0frades-content-0\x04\x04\xab\xab\xab\xab"
    );
}

#[test]
fn content_hints_without_description_is_the_content_type_alone() {
    let options = Options::default().content_hints(ContentHints::new(
        None,
        ObjectIdentifier::new_unwrap(ID_DATA),
    ));
    assert_eq!(
        signed_attribute(&sign_with_options(&options), CONTENT_HINTS)
            .to_der()
            .unwrap(),
        b"\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
    );
}

#[test]
fn the_signer_certificate_is_embedded_by_default() {
    assert_eq!(
        embedded_certificates(&complete(sign_with_options(&Options::default()))),
        1
    );
}

#[test]
fn the_chain_is_embedded_on_request() {
    let options = Options::default().certificates(Certificates::Chain(vec![
        common::certificate("intermediate"),
        common::certificate("root"),
    ]));
    assert_eq!(
        embedded_certificates(&complete(sign_with_options(&options))),
        3
    );
}

#[test]
fn no_certificate_is_embedded_on_request() {
    let options = Options::default().certificates(Certificates::None);
    assert_eq!(
        embedded_certificates(&complete(sign_with_options(&options))),
        0
    );
}

#[test]
fn detached_with_attributes_matches_the_golden_vector() {
    common::assert_golden(
        "cades/bb-detached-rsa-sha256-attributes.p7m",
        &complete(sign_with_options(&described())),
    );
}

#[test]
fn detached_with_chain_matches_the_golden_vector() {
    let options = Options::default().certificates(Certificates::Chain(vec![common::certificate(
        "intermediate",
    )]));
    common::assert_golden(
        "cades/bb-detached-rsa-sha256-chain.p7m",
        &complete(sign_with_options(&options)),
    );
}

#[test]
fn detached_without_certificates_matches_the_golden_vector() {
    let options = Options::default().certificates(Certificates::None);
    common::assert_golden(
        "cades/bb-detached-rsa-sha256-nocert.p7m",
        &complete(sign_with_options(&options)),
    );
}

fn sign_with(content: Content<'_>) -> Result<Vec<u8>, Error> {
    let pending = cades::sign(
        content,
        &common::certificate("signer-rsa"),
        RSA_SHA256,
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        &Options::default(),
    )?;
    let value = common::sign_rsa_pkcs1("signer-rsa", &pending.data_to_sign()[0]);
    pending.complete(&[value])
}

#[test]
fn attached_rsa_sha256_matches_the_golden_vector() {
    let content = common::read("cades/content.txt");
    let signature = sign_with(Content::Attached(&content)).unwrap();
    common::assert_golden("cades/bb-attached-rsa-sha256.p7m", &signature);
    assert!(
        signature.windows(content.len()).any(|w| w == content),
        "the content is embedded"
    );
}

#[test]
fn a_precomputed_digest_signs_like_the_detached_content() {
    let content = common::read("cades/content.txt");
    let digest = Sha256::digest(&content).to_vec();
    let signature = sign_with(Content::Digest {
        algorithm: DigestAlgorithm::Sha256,
        digest: &digest,
    })
    .unwrap();
    assert_eq!(signature, sign_with(Content::Detached(&content)).unwrap());
    common::assert_golden("cades/bb-digest-rsa-sha256.p7m", &signature);
}

#[test]
fn a_digest_of_the_wrong_length_is_rejected() {
    let error = sign_with(Content::Digest {
        algorithm: DigestAlgorithm::Sha256,
        digest: &[0; 20],
    })
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "SHA-256 digest is 20 bytes long, expected 32"
    );
}

#[test]
fn a_digest_of_another_algorithm_is_rejected() {
    let error = sign_with(Content::Digest {
        algorithm: DigestAlgorithm::Sha512,
        digest: &[0; 64],
    })
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "SHA-512 digest given, the signature algorithm digests with SHA-256"
    );
}
