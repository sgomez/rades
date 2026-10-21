//! `AutoFirma`'s raw PKCS#1 mode (`NONE`): the signature value over the content as is.

mod common;

use der::{DecodePem, Encode};
use rades::{Error, SignatureValue, pkcs1};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use x509_cert::Certificate;

fn public_key(signer: &str) -> RsaPublicKey {
    let pem = std::fs::read_to_string(common::path(&format!("pki/{signer}.crt"))).unwrap();
    let certificate = Certificate::from_pem(pem).unwrap();
    let spki = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap();
    RsaPublicKey::from_public_key_der(&spki).unwrap()
}

fn sign(content: &[u8]) -> Vec<u8> {
    let pem = std::fs::read_to_string(common::path("pki/signer-rsa.key")).unwrap();
    RsaPrivateKey::from_pkcs8_pem(&pem)
        .unwrap()
        .sign(Pkcs1v15Sign::new_unprefixed(), content)
        .unwrap()
}

#[test]
fn the_data_to_sign_is_the_content() {
    let content = common::read("cades/content.txt");
    let pending = pkcs1::sign(&content, &common::certificate("signer-rsa")).unwrap();
    assert_eq!(pending.data_to_sign(), content);
}

#[test]
fn the_result_is_the_signature_value_unchanged_and_verifies_against_the_public_key() {
    let content = common::read("cades/content.txt");
    let pending = pkcs1::sign(&content, &common::certificate("signer-rsa")).unwrap();
    let value = sign(pending.data_to_sign());
    let result = pending
        .complete(&SignatureValue::new(value.clone()))
        .unwrap();
    assert_eq!(result, value);
    public_key("signer-rsa")
        .verify(Pkcs1v15Sign::new_unprefixed(), &content, &result)
        .unwrap();
}

#[test]
fn a_value_shorter_than_the_modulus_is_rejected() {
    let pending = pkcs1::sign(b"content", &common::certificate("signer-rsa")).unwrap();
    assert_eq!(
        pending
            .complete(&SignatureValue::new(vec![1; 383]))
            .unwrap_err(),
        Error::SignatureValueLength {
            expected: 384,
            actual: 383
        }
    );
}

#[test]
fn an_ec_certificate_is_rejected() {
    let error = pkcs1::sign(b"content", &common::certificate("signer-ecdsa")).unwrap_err();
    assert_eq!(
        error.to_string(),
        "raw PKCS#1 needs an RSA key, the certificate has an EC key"
    );
}
