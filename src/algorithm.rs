//! Digest and signature algorithms shared by every format.

use std::fmt;

use der::asn1::{Any, Null, ObjectIdentifier};
use sha2::Digest as _;
use x509_cert::spki::AlgorithmIdentifierOwned;

const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// Digest algorithm of a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256 (FIPS 180-4).
    Sha256,
}

impl DigestAlgorithm {
    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
        }
    }

    pub(crate) fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
        }
    }

    pub(crate) fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => SHA256,
        }
    }

    /// Identifier with absent parameters, as RFC 5754 asks for CMS.
    pub(crate) fn identifier(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: None,
        }
    }

    /// Identifier with NULL parameters, as the PKCS#1 `DigestInfo` encodes it.
    pub(crate) fn identifier_with_null(self) -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            oid: self.oid(),
            parameters: Some(Any::from(Null)),
        }
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sha256 => "SHA-256",
        })
    }
}

/// Signature algorithm: a signature scheme with its digest algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 (RFC 8017).
    RsaPkcs1v15(DigestAlgorithm),
}

impl SignatureAlgorithm {
    /// The digest algorithm the scheme hashes with.
    #[must_use]
    pub fn digest_algorithm(self) -> DigestAlgorithm {
        match self {
            Self::RsaPkcs1v15(digest) => digest,
        }
    }

    pub(crate) fn identifier(self) -> AlgorithmIdentifierOwned {
        match self {
            Self::RsaPkcs1v15(DigestAlgorithm::Sha256) => AlgorithmIdentifierOwned {
                oid: SHA256_WITH_RSA,
                parameters: Some(Any::from(Null)),
            },
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RsaPkcs1v15(digest) => write!(f, "RSA PKCS#1 v1.5 with {digest}"),
        }
    }
}
