//! The `signature-policy-identifier` attribute of CAdES B-B (EN 319 122-1, section 5.2.9).

mod common;

use der::asn1::{ObjectIdentifier, SetOfVec};
use der::{Decode, Encode};
use rades::cades::{self, Content, Options};
use rades::{
    DigestAlgorithm, ExplicitPolicy, PolicyHashAlgorithm, PolicyQualifier, SignatureAlgorithm,
    SignaturePolicy, SigningTime,
};
use x509_cert::attr::Attribute;

const RSA_SHA256: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15(DigestAlgorithm::Sha256);
const SIGNING_TIME: u64 = 1_792_584_000;
const ID_SIGNATURE_POLICY: &str = "1.2.840.113549.1.9.16.2.15";
const AGE_OID: &str = "2.16.724.1.3.1.1.2.1.9";
const AGE_URL: &str = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf";

fn age_hash() -> Vec<u8> {
    vec![
        0x1b, 0xba, 0xe8, 0xb9, 0xc7, 0xfa, 0xd3, 0x4f, 0x9f, 0xd3, 0x7a, 0xff, 0xa3, 0x46, 0xc0,
        0x39, 0x0e, 0x96, 0x02, 0xcd,
    ]
}

fn pending(policy: Option<SignaturePolicy>) -> cades::PendingSignature {
    let options = policy.map_or_else(Options::default, |p| Options::default().signature_policy(p));
    cades::sign(
        Content::Detached(&common::read("cades/content.txt")),
        &common::certificate("signer-rsa"),
        RSA_SHA256,
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        &options,
    )
    .unwrap()
}

fn sign(policy: Option<SignaturePolicy>) -> Vec<u8> {
    let pending = pending(policy);
    let value = common::sign_rsa_pkcs1("signer-rsa", &pending.data_to_sign()[0]);
    pending.complete(&[value]).unwrap()
}

fn policy_attribute(pending: &cades::PendingSignature) -> Option<Vec<u8>> {
    let attributes = SetOfVec::<Attribute>::from_der(pending.data_to_sign()[0].bytes()).unwrap();
    let oid = ObjectIdentifier::new_unwrap(ID_SIGNATURE_POLICY);
    let attribute = attributes.iter().find(|a| a.oid == oid)?;
    Some(attribute.values.get(0).unwrap().to_der().unwrap())
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = content.len();
    let mut der = vec![tag];
    if len < 0x80 {
        der.push(u8::try_from(len).unwrap());
    } else {
        der.extend([0x81, u8::try_from(len).unwrap()]);
    }
    der.extend(content);
    der
}

/// `SignaturePolicyId` of the AGE policy, written out from EN 319 122-1 section 5.2.9.
fn age_der() -> Vec<u8> {
    let id = [
        0x06, 0x0a, 0x60, 0x85, 0x54, 0x01, 0x03, 0x01, 0x01, 0x02, 0x01, 0x09,
    ];
    // SHA-1 without parameters, then the hash
    let sha1 = tlv(0x30, &[0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a]);
    let hash = tlv(0x30, &[sha1, tlv(0x04, &age_hash())].concat());
    let spuri_id = [
        0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x05, 0x01,
    ];
    let spuri = tlv(
        0x30,
        &[&spuri_id[..], &tlv(0x16, AGE_URL.as_bytes())].concat(),
    );
    tlv(0x30, &[&id[..], &hash, &tlv(0x30, &spuri)].concat())
}

#[test]
fn the_age_policy_matches_the_golden_vector() {
    let signature = sign(Some(SignaturePolicy::age_v1_9()));
    common::assert_golden("cades/bb-detached-rsa-sha256-age.p7m", &signature);
}

#[test]
fn the_tampered_age_policy_signature_matches_its_golden_vector() {
    let mut signature = sign(Some(SignaturePolicy::age_v1_9()));
    let at = signature
        .windows(10)
        .position(|w| w == b"2610211200")
        .unwrap()
        + 3;
    signature[at] = b'1';
    common::assert_golden("cades/bb-detached-rsa-sha256-age-tampered.p7m", &signature);
}

#[test]
fn the_age_policy_is_encoded_as_in_en_319_122_1() {
    let attribute = policy_attribute(&pending(Some(SignaturePolicy::age_v1_9()))).unwrap();
    assert_eq!(attribute, age_der());
}

#[test]
fn without_a_policy_the_attribute_is_absent() {
    assert_eq!(policy_attribute(&pending(None)), None);
}

#[test]
fn decode_returns_the_age_policy() {
    let decoded = cades::decode(&sign(Some(SignaturePolicy::age_v1_9()))).unwrap();
    let policy = decoded.signers()[0].signature_policy().unwrap();
    let SignaturePolicy::Explicit(policy) = policy else {
        panic!("explicit policy expected")
    };
    assert_eq!(policy.identifier(), ObjectIdentifier::new_unwrap(AGE_OID));
    assert_eq!(policy.hash_algorithm(), PolicyHashAlgorithm::Sha1);
    assert_eq!(policy.hash(), age_hash());
    assert_eq!(
        policy.qualifiers(),
        [PolicyQualifier::Spuri(AGE_URL.to_owned())]
    );
}

#[test]
fn decode_returns_no_policy_when_the_signature_has_none() {
    let decoded = cades::decode(&sign(None)).unwrap();
    assert_eq!(decoded.signers()[0].signature_policy(), None);
}

#[test]
fn a_policy_without_qualifiers_omits_the_sequence() {
    let policy = ExplicitPolicy::new(
        ObjectIdentifier::new_unwrap(AGE_OID),
        PolicyHashAlgorithm::Digest(DigestAlgorithm::Sha256),
        vec![7; 32],
    );
    let attribute = policy_attribute(&pending(Some(policy.clone().into()))).unwrap();
    // the SignaturePolicyId holds the identifier and the hash only
    assert_eq!(attribute[0], 0x30);
    assert!(!attribute.windows(3).any(|w| w == [0x2a, 0x86, 0x48]));
    let decoded = cades::decode(&sign(Some(policy.clone().into()))).unwrap();
    assert_eq!(
        decoded.signers()[0].signature_policy(),
        Some(&SignaturePolicy::Explicit(policy))
    );
}

#[test]
fn a_hash_that_does_not_fit_its_algorithm_is_rejected_in_phase_1() {
    let policy = ExplicitPolicy::new(
        ObjectIdentifier::new_unwrap(AGE_OID),
        PolicyHashAlgorithm::Sha1,
        vec![7; 32],
    );
    let result = cades::sign(
        Content::Detached(b"content"),
        &common::certificate("signer-rsa"),
        RSA_SHA256,
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        &Options::default().signature_policy(policy.into()),
    );
    assert_eq!(
        result.unwrap_err().to_string(),
        "SHA-1 policy hash is 32 bytes long, expected 20"
    );
}

#[test]
fn decode_rejects_a_malformed_policy_attribute() {
    let mut signature = sign(Some(SignaturePolicy::age_v1_9()));
    let at = signature
        .windows(AGE_URL.len())
        .position(|w| w == AGE_URL.as_bytes())
        .unwrap();
    // IA5String tag turned into a UTF8String tag
    signature[at - 2] = 0x0c;
    assert!(cades::decode(&signature).is_err());
}
