//! CAdES B-B through the two-phase API.

mod common;

use der::asn1::{ObjectIdentifier, OctetString, SetOfVec, UtcTime};
use der::{Any, Decode, Encode};
use rades::cades::{self, Content, Options, PendingSignature};
use rades::{DigestAlgorithm, Error, SignatureAlgorithm, SignatureValue, SigningTime};
use sha2::{Digest, Sha256};
use x509_cert::attr::Attribute;

const RSA_SHA256: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15(DigestAlgorithm::Sha256);
/// 2026-10-21T12:00:00Z, within the test signers' validity.
const SIGNING_TIME: u64 = 1_792_584_000;

fn sign_detached(signer: &str) -> Result<PendingSignature, Error> {
    cades::sign(
        Content::Detached(&common::read("cades/content.txt")),
        &common::certificate(signer),
        RSA_SHA256,
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
