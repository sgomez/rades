//! `AutoFirma`'s bare CMS mode: a `SignedData` without the ETSI attributes.

mod common;

use der::Decode;
use der::asn1::SetOfVec;
use rades::cades::{self, Certificates, Content};
use rades::{DigestAlgorithm, SignatureAlgorithm, SigningTime};
use x509_cert::attr::Attribute;

const RSA_SHA256: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15(DigestAlgorithm::Sha256);
/// 2026-10-21T12:00:00Z, within the test signers' validity.
const SIGNING_TIME: u64 = 1_792_584_000;

fn sign_bare(content: Content<'_>) -> cades::PendingSignature {
    cades::sign_bare(
        content,
        &common::certificate("signer-rsa"),
        RSA_SHA256,
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        &Certificates::Signer,
    )
    .unwrap()
}

#[test]
fn bare_cms_signs_content_type_message_digest_and_signing_time_only() {
    let content = common::read("cades/content.txt");
    let pending = sign_bare(Content::Detached(&content));
    let attributes = SetOfVec::<Attribute>::from_der(pending.data_to_sign()[0].bytes()).unwrap();
    let mut oids: Vec<String> = attributes.iter().map(|a| a.oid.to_string()).collect();
    oids.sort();
    assert_eq!(
        oids,
        [
            "1.2.840.113549.1.9.3",
            "1.2.840.113549.1.9.4",
            "1.2.840.113549.1.9.5",
        ]
    );
}

#[test]
fn bare_cms_detached_matches_the_golden_vector() {
    let content = common::read("cades/content.txt");
    let pending = sign_bare(Content::Detached(&content));
    let value = common::sign_rsa_pkcs1("signer-rsa", &pending.data_to_sign()[0]);
    common::assert_golden(
        "cades/cms-detached-rsa-sha256.p7m",
        &pending.complete(&[value]).unwrap(),
    );
}

#[test]
fn bare_cms_attached_matches_the_golden_vector() {
    let content = common::read("cades/content.txt");
    let pending = sign_bare(Content::Attached(&content));
    let value = common::sign_rsa_pkcs1("signer-rsa", &pending.data_to_sign()[0]);
    let signature = pending.complete(&[value]).unwrap();
    assert!(signature.windows(content.len()).any(|w| w == content));
    common::assert_golden("cades/cms-attached-rsa-sha256.p7m", &signature);
}
