//! CAdES B-B with ECDSA on P-256, P-384 and P-521.

mod common;

use der::asn1::{ObjectIdentifier, SetOfVec};
use der::{Decode, Encode};
use rades::cades::{self, Content, Options, PendingSignature};
use rades::{DigestAlgorithm, Error, SignatureAlgorithm, SignatureValue, SigningTime};
use x509_cert::attr::Attribute;

/// 2026-10-21T12:00:00Z, within the test signers' validity.
const SIGNING_TIME: u64 = 1_792_584_000;

/// Signer, digest, `ecdsa-with-*` OID and the golden vector's name.
const CASES: [(&str, DigestAlgorithm, &str, &str); 4] = [
    (
        "signer-ecdsa",
        DigestAlgorithm::Sha256,
        "1.2.840.10045.4.3.2",
        "p256-sha256",
    ),
    (
        "signer-ecdsa-p384",
        DigestAlgorithm::Sha384,
        "1.2.840.10045.4.3.3",
        "p384-sha384",
    ),
    (
        "signer-ecdsa-p521",
        DigestAlgorithm::Sha512,
        "1.2.840.10045.4.3.4",
        "p521-sha512",
    ),
    (
        "signer-ecdsa-p384",
        DigestAlgorithm::Sha3_384,
        "2.16.840.1.101.3.4.3.11",
        "p384-sha3-384",
    ),
];

fn sign(signer: &str, algorithm: SignatureAlgorithm) -> Result<PendingSignature, Error> {
    cades::sign(
        Content::Detached(&common::read("cades/content.txt")),
        &common::certificate(signer),
        algorithm,
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        &Options::default(),
    )
}

fn signed(signer: &str, digest: DigestAlgorithm) -> Vec<u8> {
    let pending = sign(signer, SignatureAlgorithm::Ecdsa(digest)).unwrap();
    let value = common::sign_ecdsa(signer, &pending.data_to_sign()[0]);
    pending.complete(&[value]).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn every_curve_has_a_golden_vector() {
    for (signer, digest, _, name) in CASES {
        common::assert_golden(
            &format!("cades/bb-detached-ecdsa-{name}.p7m"),
            &signed(signer, digest),
        );
    }
}

#[test]
fn signatures_are_identical_across_runs() {
    for (signer, digest, _, _) in CASES {
        assert_eq!(signed(signer, digest), signed(signer, digest));
    }
}

#[test]
fn the_signature_algorithm_is_ecdsa_with_the_digest() {
    for (signer, digest, oid, _) in CASES {
        let oid = ObjectIdentifier::new_unwrap(oid).to_der().unwrap();
        let count = |bytes: &[u8]| bytes.windows(oid.len()).filter(|w| *w == oid).count();
        let pem = std::fs::read_to_string(common::path(&format!("pki/{signer}.crt"))).unwrap();
        let (_, certificate) = der::pem::decode_vec(pem.as_bytes()).unwrap();
        // The embedded certificate has its own; the rest is the SignerInfo and
        // cms-algorithm-protection.
        assert_eq!(
            count(&signed(signer, digest)) - count(&certificate),
            2,
            "{signer} with {digest}"
        );
    }
}

#[test]
fn signed_attributes_name_the_ecdsa_algorithm() {
    let pending = sign(
        "signer-ecdsa-p384",
        SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha384),
    )
    .unwrap();
    let bytes = pending.data_to_sign()[0].bytes();
    SetOfVec::<Attribute>::from_der(bytes).unwrap();
    let oid = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3")
        .to_der()
        .unwrap();
    assert!(contains(bytes, &oid));
}

#[test]
fn phase_1_rejects_ecdsa_on_an_rsa_key() {
    let error = sign(
        "signer-rsa",
        SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha256),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "signature algorithm ECDSA with SHA-256 does not fit the certificate's RSA key"
    );
}

#[test]
fn phase_1_rejects_an_ec_key_on_another_curve() {
    let error = sign(
        "signer-ecdsa-brainpool",
        SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha256),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "unsupported elliptic curve 1.3.36.3.3.2.8.1.1.7, expected P-256, P-384 or P-521"
    );
}

fn pending(signer: &str) -> PendingSignature {
    sign(signer, SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha256)).unwrap()
}

fn rejected(signer: &str, value: &[u8]) -> String {
    pending(signer)
        .complete(&[SignatureValue::new(value.to_vec())])
        .unwrap_err()
        .to_string()
}

#[test]
fn phase_2_rejects_a_wrong_number_of_values() {
    for count in [0, 2] {
        let values = vec![SignatureValue::new(vec![0x30, 6, 2, 1, 1, 2, 1, 1]); count];
        assert_eq!(
            pending("signer-ecdsa").complete(&values).unwrap_err(),
            Error::SignatureValueCount {
                expected: 1,
                actual: count
            }
        );
    }
}

#[test]
fn phase_2_rejects_a_value_that_is_not_an_ecdsa_sig_value() {
    for value in [
        // Raw r || s instead of DER.
        &[1u8; 64][..],
        // Trailing byte after the SEQUENCE.
        &[0x30, 6, 2, 1, 1, 2, 1, 1, 0],
        // Only r.
        &[0x30, 3, 2, 1, 1],
        // Not minimal: r with a redundant leading zero.
        &[0x30, 7, 2, 2, 0, 1, 2, 1, 1],
        // Zero s.
        &[0x30, 6, 2, 1, 1, 2, 1, 0],
        // Negative r.
        &[0x30, 6, 2, 1, 0x81, 2, 1, 1],
    ] {
        assert!(
            rejected("signer-ecdsa", value).starts_with("malformed ecdsa signature value"),
            "{value:02x?}"
        );
    }
}

#[test]
fn phase_2_rejects_r_or_s_beyond_the_order_size() {
    for (signer, order_len) in [
        ("signer-ecdsa", 32),
        ("signer-ecdsa-p384", 48),
        ("signer-ecdsa-p521", 66),
    ] {
        let oversized = [vec![0x7f], vec![0xff; order_len]].concat();
        let mut body = Vec::new();
        for int in [oversized.as_slice(), &[1]] {
            body.extend([0x02, u8::try_from(int.len()).unwrap()]);
            body.extend(int);
        }
        let mut value = vec![0x30, u8::try_from(body.len()).unwrap()];
        value.extend(body);
        let pending = sign(signer, SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha256)).unwrap();
        assert_eq!(
            pending
                .complete(&[SignatureValue::new(value)])
                .unwrap_err()
                .to_string(),
            format!(
                "malformed ecdsa signature value: integer longer than the {order_len} byte curve order"
            )
        );
    }
}
