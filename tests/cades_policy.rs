//! The `signature-policy-identifier` attribute of CAdES B-B (EN 319 122-1, section 5.2.9).

mod common;

use der::asn1::{ObjectIdentifier, SetOfVec};
use der::{Decode, Encode};
use rades::cades::{self, Certificates, Content, Options};
use rades::{
    DigestAlgorithm, ExplicitPolicy, PolicyHashAlgorithm, PolicyQualifier, SignatureAlgorithm,
    SignaturePolicy, SigningTime,
};
use sha2::Digest;
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

const ECDSA_SHA256: SignatureAlgorithm = SignatureAlgorithm::Ecdsa(DigestAlgorithm::Sha256);

fn age() -> Options {
    Options::default().signature_policy(SignaturePolicy::age_v1_9())
}

fn sign_ecdsa(content: Content<'_>, options: &Options) -> Vec<u8> {
    let pending = cades::sign(
        content,
        &common::certificate("signer-ecdsa"),
        ECDSA_SHA256,
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        options,
    )
    .unwrap();
    let value = common::sign_ecdsa("signer-ecdsa", &pending.data_to_sign()[0]);
    pending.complete(&[value]).unwrap()
}

fn sign_rsa(content: Content<'_>, options: &Options) -> Vec<u8> {
    let pending = cades::sign(
        content,
        &common::certificate("signer-rsa"),
        RSA_SHA256,
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        options,
    )
    .unwrap();
    let value = common::sign_rsa_pkcs1("signer-rsa", &pending.data_to_sign()[0]);
    pending.complete(&[value]).unwrap()
}

fn tampered(signature: &[u8]) -> Vec<u8> {
    let mut signature = signature.to_vec();
    let at = signature
        .windows(10)
        .position(|w| w == b"2610211200")
        .unwrap()
        + 3;
    signature[at] = b'1';
    signature
}

fn assert_age(signature: &[u8]) {
    let decoded = cades::decode(signature).unwrap();
    assert_eq!(
        decoded.signers()[0].signature_policy(),
        Some(&SignaturePolicy::age_v1_9())
    );
}

#[test]
fn the_age_policy_signs_attached_content() {
    let content = common::read("cades/content.txt");
    let signature = sign_rsa(Content::Attached(&content), &age());
    common::assert_golden("cades/bb-attached-rsa-sha256-age.p7m", &signature);
    common::assert_golden(
        "cades/bb-attached-rsa-sha256-age-tampered.p7m",
        &tampered(&signature),
    );
    assert_age(&signature);
}

#[test]
fn the_age_policy_signs_a_precomputed_digest() {
    let content = common::read("cades/content.txt");
    let digest = sha2::Sha256::digest(&content).to_vec();
    let signature = sign_rsa(
        Content::Digest {
            algorithm: DigestAlgorithm::Sha256,
            digest: &digest,
        },
        &age(),
    );
    assert_eq!(signature, sign(Some(SignaturePolicy::age_v1_9())));
    common::assert_golden("cades/bb-digest-rsa-sha256-age.p7m", &signature);
    common::assert_golden(
        "cades/bb-digest-rsa-sha256-age-tampered.p7m",
        &tampered(&signature),
    );
    assert_age(&signature);
}

#[test]
fn the_age_policy_signs_with_ecdsa() {
    let content = common::read("cades/content.txt");
    let signature = sign_ecdsa(Content::Detached(&content), &age());
    common::assert_golden("cades/bb-detached-ecdsa-p256-sha256-age.p7m", &signature);
    common::assert_golden(
        "cades/bb-detached-ecdsa-p256-sha256-age-tampered.p7m",
        &tampered(&signature),
    );
    assert_age(&signature);
}

fn embeds(signature: &[u8], signer: &str) -> bool {
    let der = common::certificate_der(signer);
    signature.windows(der.len()).any(|w| w == der)
}

#[test]
fn the_policy_composes_with_the_optional_attributes_and_the_chain() {
    let options = age()
        .mime_type("text/plain")
        .content_identifier(b"rades-content-1".to_vec())
        .certificates(Certificates::Chain(vec![
            common::certificate("intermediate"),
            common::certificate("root"),
        ]));
    let signature = sign_rsa(
        Content::Detached(&common::read("cades/content.txt")),
        &options,
    );
    common::assert_golden("cades/bb-detached-rsa-sha256-age-chain.p7m", &signature);
    assert!(embeds(&signature, "intermediate") && embeds(&signature, "root"));
    let decoded = cades::decode(&signature).unwrap();
    let oids: Vec<String> = decoded.signers()[0]
        .signed_attributes()
        .iter()
        .map(|a| a.oid().to_string())
        .collect();
    for expected in [
        "0.4.0.1733.2.1",
        "1.2.840.113549.1.9.16.2.7",
        ID_SIGNATURE_POLICY,
    ] {
        assert!(oids.iter().any(|o| o == expected), "{expected} in {oids:?}");
    }
    assert_age(&signature);
}

#[test]
fn an_autofirma_signature_with_exp_policy_firma_age_decodes_to_the_age_policy() {
    for file in ["attached-rsa-age.p7s", "attached-ecdsa-age.p7s"] {
        assert_age(&common::read(&format!("autofirma/{file}")));
    }
}

#[test]
fn a_malformed_policy_attribute_is_an_error_not_a_panic() {
    let signature = sign(Some(SignaturePolicy::age_v1_9()));
    let url = signature
        .windows(AGE_URL.len())
        .position(|w| w == AGE_URL.as_bytes())
        .unwrap();
    let sha1 = signature
        .windows(5)
        .position(|w| w == [0x2b, 0x0e, 0x03, 0x02, 0x1a])
        .unwrap();
    let hash = signature
        .windows(20)
        .position(|w| w == age_hash().as_slice())
        .unwrap();
    for (name, at, byte) in [
        ("qualifier id tag", url - 15, 0x04),
        ("sha-1 algorithm id", sha1 - 2, 0x04),
        ("hash tag", hash - 2, 0x05),
        ("hash length", hash - 1, 0x13),
    ] {
        let mut copy = signature.clone();
        copy[at] = byte;
        assert!(cades::decode(&copy).is_err(), "{name}");
    }
}
