//! The crate's error type.

use std::fmt;

use crate::{DigestAlgorithm, PolicyHashAlgorithm, SignatureAlgorithm};

/// Why rades could not produce a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The certificate is not a DER or PEM X.509 certificate.
    InvalidCertificate(String),
    /// The signature algorithm does not fit the certificate's key.
    AlgorithmMismatch {
        /// The algorithm the caller named.
        algorithm: SignatureAlgorithm,
        /// The certificate's key type.
        key: String,
    },
    /// Raw PKCS#1 needs an RSA key.
    NotRsaKey {
        /// The certificate's key type.
        key: String,
    },
    /// The signing time cannot be encoded.
    SigningTimeOutOfRange,
    /// The number of signature values differs from the number of data to sign.
    SignatureValueCount {
        /// Data to sign in the pending signature.
        expected: usize,
        /// Signature values handed back.
        actual: usize,
    },
    /// An RSA signature value is not as long as the key's modulus.
    SignatureValueLength {
        /// Modulus length in bytes.
        expected: usize,
        /// Signature value length in bytes.
        actual: usize,
    },
    /// The certificate's EC key is on a curve other than P-256, P-384 or P-521.
    UnsupportedCurve {
        /// The curve's object identifier.
        curve: String,
    },
    /// An ECDSA signature value is not an `ECDSA-Sig-Value` within the curve's order size.
    InvalidEcdsaSignature(String),
    /// A precomputed digest is not as long as its algorithm's output.
    DigestLength {
        /// The algorithm the caller named.
        algorithm: DigestAlgorithm,
        /// Output length in bytes.
        expected: usize,
        /// Digest length in bytes.
        actual: usize,
    },
    /// A precomputed digest's algorithm is not the signature algorithm's.
    DigestAlgorithmMismatch {
        /// The algorithm that produced the digest.
        given: DigestAlgorithm,
        /// The signature algorithm's digest algorithm.
        expected: DigestAlgorithm,
    },
    /// A signature policy hash is not as long as its algorithm's output.
    PolicyHashLength {
        /// The algorithm the caller named.
        algorithm: PolicyHashAlgorithm,
        /// Output length in bytes.
        expected: usize,
        /// Hash length in bytes.
        actual: usize,
    },
    /// The bytes to decode are not a CMS signature.
    MalformedSignature(String),
    /// A decoded signature uses a broken digest algorithm.
    RejectedDigestAlgorithm(String),
    /// A DER structure could not be encoded.
    Encoding(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCertificate(reason) => write!(f, "invalid certificate: {reason}"),
            Self::AlgorithmMismatch { algorithm, key } => {
                write!(
                    f,
                    "signature algorithm {algorithm} does not fit the certificate's {key} key"
                )
            }
            Self::NotRsaKey { key } => {
                write!(
                    f,
                    "raw PKCS#1 needs an RSA key, the certificate has an {key} key"
                )
            }
            Self::SigningTimeOutOfRange => f.write_str("signing time out of range"),
            Self::SignatureValueCount { expected, actual } => {
                write!(f, "expected {expected} signature values, got {actual}")
            }
            Self::SignatureValueLength { expected, actual } => write!(
                f,
                "signature value is {actual} bytes long, the RSA modulus {expected}"
            ),
            Self::UnsupportedCurve { curve } => write!(
                f,
                "unsupported elliptic curve {curve}, expected P-256, P-384 or P-521"
            ),
            Self::InvalidEcdsaSignature(reason) => {
                write!(f, "malformed ecdsa signature value: {reason}")
            }
            Self::DigestLength {
                algorithm,
                expected,
                actual,
            } => write!(
                f,
                "{algorithm} digest is {actual} bytes long, expected {expected}"
            ),
            Self::DigestAlgorithmMismatch { given, expected } => write!(
                f,
                "{given} digest given, the signature algorithm digests with {expected}"
            ),
            Self::PolicyHashLength {
                algorithm,
                expected,
                actual,
            } => write!(
                f,
                "{algorithm} policy hash is {actual} bytes long, expected {expected}"
            ),
            Self::MalformedSignature(reason) => write!(f, "malformed signature: {reason}"),
            Self::RejectedDigestAlgorithm(name) => write!(f, "rejected digest algorithm {name}"),
            Self::Encoding(reason) => write!(f, "der encoding failed: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<der::Error> for Error {
    fn from(error: der::Error) -> Self {
        Self::Encoding(error.to_string())
    }
}
