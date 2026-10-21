//! Digest and signature algorithms shared by every format.

use std::fmt;

use der::Sequence;
use der::asn1::{Any, Null, ObjectIdentifier};
use sha2::Digest as _;
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::Error;

/// Digest algorithm of a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DigestAlgorithm {
    /// SHA-256 (FIPS 180-4).
    Sha256,
    /// SHA-384 (FIPS 180-4).
    Sha384,
    /// SHA-512 (FIPS 180-4).
    Sha512,
    /// SHA3-256 (FIPS 202).
    Sha3_256,
    /// SHA3-384 (FIPS 202).
    Sha3_384,
    /// SHA3-512 (FIPS 202).
    Sha3_512,
}

impl DigestAlgorithm {
    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
            Self::Sha3_256 => sha3::Sha3_256::digest(data).to_vec(),
            Self::Sha3_384 => sha3::Sha3_384::digest(data).to_vec(),
            Self::Sha3_512 => sha3::Sha3_512::digest(data).to_vec(),
        }
    }

    pub(crate) fn output_len(self) -> usize {
        match self {
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha384 | Self::Sha3_384 => 48,
            Self::Sha512 | Self::Sha3_512 => 64,
        }
    }

    pub(crate) fn oid(self) -> ObjectIdentifier {
        ObjectIdentifier::new_unwrap(match self {
            Self::Sha256 => "2.16.840.1.101.3.4.2.1",
            Self::Sha384 => "2.16.840.1.101.3.4.2.2",
            Self::Sha512 => "2.16.840.1.101.3.4.2.3",
            Self::Sha3_256 => "2.16.840.1.101.3.4.2.8",
            Self::Sha3_384 => "2.16.840.1.101.3.4.2.9",
            Self::Sha3_512 => "2.16.840.1.101.3.4.2.10",
        })
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
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Sha3_256 => "SHA3-256",
            Self::Sha3_384 => "SHA3-384",
            Self::Sha3_512 => "SHA3-512",
        })
    }
}

/// Signature algorithm: a signature scheme with its digest algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 (RFC 8017).
    RsaPkcs1v15(DigestAlgorithm),
    /// RSASSA-PSS (RFC 8017), MGF1 with the same digest and a salt as long as the digest.
    RsaPss(DigestAlgorithm),
}

impl SignatureAlgorithm {
    /// The digest algorithm the scheme hashes with.
    #[must_use]
    pub fn digest_algorithm(self) -> DigestAlgorithm {
        match self {
            Self::RsaPkcs1v15(digest) | Self::RsaPss(digest) => digest,
        }
    }

    pub(crate) fn identifier(self) -> Result<AlgorithmIdentifierOwned, Error> {
        match self {
            Self::RsaPkcs1v15(digest) => Ok(AlgorithmIdentifierOwned {
                oid: ObjectIdentifier::new_unwrap(match digest {
                    DigestAlgorithm::Sha256 => "1.2.840.113549.1.1.11",
                    DigestAlgorithm::Sha384 => "1.2.840.113549.1.1.12",
                    DigestAlgorithm::Sha512 => "1.2.840.113549.1.1.13",
                    DigestAlgorithm::Sha3_256 => "2.16.840.1.101.3.4.3.14",
                    DigestAlgorithm::Sha3_384 => "2.16.840.1.101.3.4.3.15",
                    DigestAlgorithm::Sha3_512 => "2.16.840.1.101.3.4.3.16",
                }),
                parameters: Some(Any::from(Null)),
            }),
            Self::RsaPss(digest) => Ok(AlgorithmIdentifierOwned {
                oid: ID_RSASSA_PSS,
                parameters: Some(Any::encode_from(&RsaPssParams {
                    hash_algorithm: digest.identifier_with_null(),
                    mask_gen_algorithm: AlgorithmIdentifierOwned {
                        oid: ID_MGF1,
                        parameters: Some(Any::encode_from(&digest.identifier_with_null())?),
                    },
                    salt_length: u32::try_from(digest.output_len())
                        .map_err(|e| Error::Encoding(e.to_string()))?,
                })?),
            }),
        }
    }
}

const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const ID_MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");

/// RFC 4055 `RSASSA-PSS-params`; hashes keep NULL parameters, as its section 2.1 asks, and the
/// trailer field its default.
#[derive(Sequence)]
struct RsaPssParams {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    hash_algorithm: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    mask_gen_algorithm: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT")]
    salt_length: u32,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RsaPkcs1v15(digest) => write!(f, "RSA PKCS#1 v1.5 with {digest}"),
            Self::RsaPss(digest) => write!(f, "RSA-PSS with {digest}"),
        }
    }
}
