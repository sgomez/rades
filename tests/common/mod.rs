//! Test PKI, test keys and golden vectors shared by the integration tests.
#![allow(dead_code)]

use std::path::PathBuf;

use rades::{Certificate, DataToSign, DigestAlgorithm, SignatureValue};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{Pkcs1v15Sign, Pss, RsaPrivateKey};

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

/// RSA-PSS with a seeded RNG, so the salt and the signature are the same on every run.
pub fn sign_rsa_pss(signer: &str, data: &DataToSign) -> SignatureValue {
    let pem = std::fs::read_to_string(path(&format!("pki/{signer}.key"))).unwrap();
    let key = RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
    let scheme = match data.algorithm().digest_algorithm() {
        DigestAlgorithm::Sha256 => Pss::new::<sha2_10::Sha256>(),
        DigestAlgorithm::Sha384 => Pss::new::<sha2_10::Sha384>(),
        DigestAlgorithm::Sha512 => Pss::new::<sha2_10::Sha512>(),
        DigestAlgorithm::Sha3_256 => Pss::new::<sha3_10::Sha3_256>(),
        DigestAlgorithm::Sha3_384 => Pss::new::<sha3_10::Sha3_384>(),
        DigestAlgorithm::Sha3_512 => Pss::new::<sha3_10::Sha3_512>(),
        _ => unreachable!(),
    };
    let mut rng = ChaCha20Rng::seed_from_u64(0);
    SignatureValue::new(key.sign_with_rng(&mut rng, scheme, &data.digest()).unwrap())
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
