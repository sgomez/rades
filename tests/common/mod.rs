//! Test PKI, test keys and golden vectors shared by the integration tests.
#![allow(dead_code)]

use std::path::PathBuf;

use rades::{Certificate, DataToSign, DigestAlgorithm, SignatureValue};
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

pub fn certificate_der(signer: &str) -> Vec<u8> {
    let pem = std::fs::read_to_string(path(&format!("pki/{signer}.crt"))).unwrap();
    der::pem::decode_vec(pem.as_bytes()).unwrap().1
}

/// The DER `SubjectPublicKeyInfo` of the signer's certificate.
pub fn certificate_spki(signer: &str) -> Vec<u8> {
    use der::{Decode, Encode};
    x509_cert::Certificate::from_der(&certificate_der(signer))
        .unwrap()
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .unwrap()
}

/// The SEC1 point of the signer's EC public key.
pub fn certificate_point(signer: &str) -> Vec<u8> {
    use der::Decode;
    x509_cert::Certificate::from_der(&certificate_der(signer))
        .unwrap()
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes()
        .to_vec()
}

pub fn sign_rsa_pkcs1(signer: &str, data: &DataToSign) -> SignatureValue {
    let pem = std::fs::read_to_string(path(&format!("pki/{signer}.key"))).unwrap();
    let key = RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
    let value = key
        .sign(Pkcs1v15Sign::new_unprefixed(), &data.digest_info().unwrap())
        .unwrap();
    SignatureValue::new(value)
}

/// A DER `ECDSA-Sig-Value` on the curve of the signer's key, with an RFC 6979 nonce.
pub fn sign_ecdsa(signer: &str, data: &DataToSign) -> SignatureValue {
    macro_rules! rfc6979 {
        ($curve:ident, $curve_type:ty, $hash:ty, $pem:expr) => {{
            use $curve::pkcs8::DecodePrivateKey;
            let secret = $curve::SecretKey::from_pkcs8_pem($pem).unwrap();
            let digest = data.digest();
            let mut z = $curve::FieldBytes::default();
            let len = digest.len().min(z.len());
            let start = z.len() - len;
            z[start..].copy_from_slice(&digest[..len]);
            let (signature, _) = ecdsa::hazmat::sign_prehashed_rfc6979::<$curve_type, $hash>(
                &secret.to_nonzero_scalar(),
                &z,
                &[],
            );
            signature.to_der().as_bytes().to_vec()
        }};
    }
    let pem = std::fs::read_to_string(path(&format!("pki/{signer}.key"))).unwrap();
    let value = if signer.ends_with("p384") {
        rfc6979!(p384, p384::NistP384, sha2::Sha384, &pem)
    } else if signer.ends_with("p521") {
        rfc6979!(p521, p521::NistP521, sha2::Sha512, &pem)
    } else {
        rfc6979!(p256, p256::NistP256, sha2::Sha256, &pem)
    };
    SignatureValue::new(value)
}

/// RSA-PSS with a seeded RNG, so the salt and the signature are the same on every run.
pub fn sign_rsa_pss(signer: &str, data: &DataToSign) -> SignatureValue {
    use rand_chacha::rand_core::SeedableRng;
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
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0);
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
