//! CAdES B-B signed with RSA-PSS.

mod common;

use der::Encode;
use der::asn1::{ObjectIdentifier, SetOfVec};
use der::{Any, Decode};
use rades::cades::{self, Content, Options, PendingSignature};
use rades::{DigestAlgorithm, Error, SignatureAlgorithm, SigningTime};
use x509_cert::attr::Attribute;

/// 2026-10-21T12:00:00Z, within the test signers' validity.
const SIGNING_TIME: u64 = 1_792_584_000;

/// Digest, its OID, its output length and the golden vector's name.
const DIGESTS: [(DigestAlgorithm, &str, u8, &str); 6] = [
    (
        DigestAlgorithm::Sha256,
        "2.16.840.1.101.3.4.2.1",
        32,
        "sha256",
    ),
    (
        DigestAlgorithm::Sha384,
        "2.16.840.1.101.3.4.2.2",
        48,
        "sha384",
    ),
    (
        DigestAlgorithm::Sha512,
        "2.16.840.1.101.3.4.2.3",
        64,
        "sha512",
    ),
    (
        DigestAlgorithm::Sha3_256,
        "2.16.840.1.101.3.4.2.8",
        32,
        "sha3-256",
    ),
    (
        DigestAlgorithm::Sha3_384,
        "2.16.840.1.101.3.4.2.9",
        48,
        "sha3-384",
    ),
    (
        DigestAlgorithm::Sha3_512,
        "2.16.840.1.101.3.4.2.10",
        64,
        "sha3-512",
    ),
];

fn sign(signer: &str, digest: DigestAlgorithm) -> Result<PendingSignature, Error> {
    cades::sign(
        Content::Detached(&common::read("cades/content.txt")),
        &common::certificate(signer),
        SignatureAlgorithm::RsaPss(digest),
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        &Options::default(),
    )
}

fn complete(pending: PendingSignature) -> Vec<u8> {
    let value = common::sign_rsa_pss("signer-rsa", &pending.data_to_sign()[0]);
    pending.complete(&[value]).unwrap()
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    [&[tag, u8::try_from(body.len()).unwrap()][..], body].concat()
}

fn der_oid(oid: &str) -> Vec<u8> {
    ObjectIdentifier::new_unwrap(oid).to_der().unwrap()
}

/// RFC 4055 `RSASSA-PSS-params` body: hash and MGF1 with NULL parameters, salt as long as the
/// digest, trailer field left at its default.
fn pss_params(digest_oid: &str, salt_len: u8) -> Vec<u8> {
    let hash = tlv(0x30, &[der_oid(digest_oid), vec![0x05, 0x00]].concat());
    let mgf1 = tlv(
        0x30,
        &[der_oid("1.2.840.113549.1.1.8"), hash.clone()].concat(),
    );
    [
        tlv(0xa0, &hash),
        tlv(0xa1, &mgf1),
        tlv(0xa2, &tlv(0x02, &[salt_len])),
    ]
    .concat()
}

/// The `AlgorithmIdentifier` content: `id-RSASSA-PSS` and its parameters.
fn pss_identifier_body(digest_oid: &str, salt_len: u8) -> Vec<u8> {
    [
        der_oid("1.2.840.113549.1.1.10"),
        tlv(0x30, &pss_params(digest_oid, salt_len)),
    ]
    .concat()
}

fn signed_attribute(pending: &PendingSignature, oid: &str) -> Any {
    let attributes = SetOfVec::<Attribute>::from_der(pending.data_to_sign()[0].bytes()).unwrap();
    let oid = ObjectIdentifier::new_unwrap(oid);
    let attribute = attributes.iter().find(|a| a.oid == oid).unwrap();
    attribute.values.get(0).unwrap().clone()
}

fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[test]
fn cms_algorithm_protection_carries_the_pss_parameters() {
    for (digest, oid, salt_len, _) in DIGESTS {
        let pending = sign("signer-rsa", digest).unwrap();
        // RFC 6211: SEQUENCE { digestAlgorithm, [1] IMPLICIT signatureAlgorithm }.
        let body = [
            tlv(0x30, &der_oid(oid)),
            tlv(0xa1, &pss_identifier_body(oid, salt_len)),
        ]
        .concat();
        assert_eq!(
            signed_attribute(&pending, "1.2.840.113549.1.9.52")
                .to_der()
                .unwrap(),
            tlv(0x30, &body),
            "{digest}"
        );
    }
}

#[test]
fn the_signer_info_names_rsa_pss_with_its_parameters() {
    for (digest, oid, salt_len, _) in DIGESTS {
        let signature = complete(sign("signer-rsa", digest).unwrap());
        let identifier = tlv(0x30, &pss_identifier_body(oid, salt_len));
        assert_eq!(occurrences(&signature, &identifier), 1, "{digest}");
    }
}

#[test]
fn every_digest_has_a_pss_golden_vector() {
    for (digest, _, _, name) in DIGESTS {
        let signature = complete(sign("signer-rsa", digest).unwrap());
        common::assert_golden(&format!("cades/bb-detached-rsapss-{name}.p7m"), &signature);
    }
}

#[test]
fn pss_signatures_are_byte_identical_across_runs() {
    let first = complete(sign("signer-rsa", DigestAlgorithm::Sha256).unwrap());
    let second = complete(sign("signer-rsa", DigestAlgorithm::Sha256).unwrap());
    assert_eq!(first, second);
}

#[test]
fn rsa_pss_does_not_fit_an_ec_key() {
    assert_eq!(
        sign("signer-ecdsa", DigestAlgorithm::Sha256)
            .unwrap_err()
            .to_string(),
        "signature algorithm RSA-PSS with SHA-256 does not fit the certificate's EC key"
    );
}
