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

/// A DER `ECDSA-Sig-Value` on the curve of the signer's key.
///
/// P-256 and P-384 use RFC 6979 nonces; `RustCrypto` has none for P-521, which draws its nonce from
/// a seeded RNG instead. Either way the same inputs give the same bytes.
pub fn sign_ecdsa(signer: &str, data: &DataToSign) -> SignatureValue {
    macro_rules! rfc6979 {
        ($curve:ident, $hash:ty, $pem:expr) => {{
            use ecdsa::hazmat::SignPrimitive;
            use $curve::pkcs8::DecodePrivateKey;
            let secret = $curve::SecretKey::from_pkcs8_pem($pem).unwrap();
            let digest = data.digest();
            let mut z = $curve::FieldBytes::default();
            let len = digest.len().min(z.len());
            let start = z.len() - len;
            z[start..].copy_from_slice(&digest[..len]);
            let (signature, _) = secret
                .to_nonzero_scalar()
                .try_sign_prehashed_rfc6979::<$hash>(&z, &[])
                .unwrap();
            signature.to_der().as_bytes().to_vec()
        }};
    }
    let pem = std::fs::read_to_string(path(&format!("pki/{signer}.key"))).unwrap();
    let value = if signer.ends_with("p384") {
        rfc6979!(p384, sha2_10::Sha384, &pem)
    } else if signer.ends_with("p521") {
        use p521::ecdsa::SigningKey;
        use p521::ecdsa::signature::hazmat::RandomizedPrehashSigner;
        use p521::pkcs8::DecodePrivateKey;
        let secret = p521::SecretKey::from_pkcs8_pem(&pem).unwrap();
        let key = SigningKey::from_bytes(&secret.to_bytes()).unwrap();
        let mut rng = ChaCha20Rng::from_seed([0x52; 32]);
        let signature: p521::ecdsa::Signature =
            key.sign_prehash_with_rng(&mut rng, &data.digest()).unwrap();
        signature.to_der().as_bytes().to_vec()
    } else {
        rfc6979!(p256, sha2_10::Sha256, &pem)
    };
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
