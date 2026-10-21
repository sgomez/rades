//! Test PKI, test keys and golden vectors shared by the integration tests.
#![allow(dead_code)]

use std::path::PathBuf;

use rades::{Certificate, DataToSign, SignatureValue};
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, RsaPrivateKey};

pub fn path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(relative)
}

pub fn read(relative: &str) -> Vec<u8> {
    std::fs::read(path(relative)).unwrap()
}

pub fn certificate(signer: &str) -> Certificate {
    let pem = std::fs::read_to_string(path(&format!("pki/{signer}.crt"))).unwrap();
    Certificate::from_pem(&pem).unwrap()
}

pub fn sign_rsa_pkcs1(signer: &str, data: &DataToSign) -> SignatureValue {
    let pem = std::fs::read_to_string(path(&format!("pki/{signer}.key"))).unwrap();
    let key = RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
    let value = key
        .sign(Pkcs1v15Sign::new_unprefixed(), &data.digest_info().unwrap())
        .unwrap();
    SignatureValue::new(value)
}

/// Compares with the committed file; `RADES_BLESS=1` rewrites it instead.
pub fn assert_golden(relative: &str, bytes: &[u8]) {
    if std::env::var_os("RADES_BLESS").is_some() {
        std::fs::write(path(relative), bytes).unwrap();
        return;
    }
    assert!(
        read(relative) == bytes,
        "{relative} differs from the golden vector; RADES_BLESS=1 rewrites it"
    );
}
