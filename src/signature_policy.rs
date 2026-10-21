//! Signature policy values shared by every format (EN 319 122-1, section 5.2.9).

use std::fmt;

use der::asn1::{Any, Ia5String, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Sequence, Tag, Tagged};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::{DigestAlgorithm, Error};

const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const ID_SPURI: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.5.1");
pub(crate) const ID_SIGNATURE_POLICY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.15");

const AGE_V1_9_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.724.1.3.1.1.2.1.9");
/// `G7roucf600+f03r/o0bAOQ6WAs0=`
const AGE_V1_9_SHA1: [u8; 20] = [
    0x1b, 0xba, 0xe8, 0xb9, 0xc7, 0xfa, 0xd3, 0x4f, 0x9f, 0xd3, 0x7a, 0xff, 0xa3, 0x46, 0xc0, 0x39,
    0x0e, 0x96, 0x02, 0xcd,
];
const AGE_V1_9_URL: &str = "https://sede.administracion.gob.es/politica_de_firma_anexo_1.pdf";

/// The hash algorithm of a policy document's hash.
///
/// SHA-1 is only admitted here: rades never hashes with it, the value identifies a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PolicyHashAlgorithm {
    /// SHA-1 (FIPS 180-4).
    Sha1,
    /// One of the digest algorithms signatures use.
    Digest(DigestAlgorithm),
}

impl PolicyHashAlgorithm {
    fn output_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Digest(digest) => digest.output_len(),
        }
    }

    fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha1 => SHA1,
            Self::Digest(digest) => digest.oid(),
        }
    }

    fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        if oid == SHA1 {
            return Some(Self::Sha1);
        }
        DigestAlgorithm::ALL
            .into_iter()
            .find(|digest| digest.oid() == oid)
            .map(Self::Digest)
    }
}

impl fmt::Display for PolicyHashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => f.write_str("SHA-1"),
            Self::Digest(digest) => digest.fmt(f),
        }
    }
}

/// A qualifier of an explicit signature policy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyQualifier {
    /// Where to find the policy document (`SPURI`).
    Spuri(String),
}

/// A signature policy an explicit identifier names, with the hash of its document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplicitPolicy {
    identifier: ObjectIdentifier,
    hash_algorithm: PolicyHashAlgorithm,
    hash: Vec<u8>,
    qualifiers: Vec<PolicyQualifier>,
}

impl ExplicitPolicy {
    /// A policy by its identifier and the hash of its document, which the caller already has.
    #[must_use]
    pub fn new(
        identifier: ObjectIdentifier,
        hash_algorithm: PolicyHashAlgorithm,
        hash: Vec<u8>,
    ) -> Self {
        Self {
            identifier,
            hash_algorithm,
            hash,
            qualifiers: Vec::new(),
        }
    }

    /// Adds a qualifier after the ones already given.
    #[must_use]
    pub fn qualifier(mut self, qualifier: PolicyQualifier) -> Self {
        self.qualifiers.push(qualifier);
        self
    }

    /// The policy's object identifier.
    #[must_use]
    pub fn identifier(&self) -> ObjectIdentifier {
        self.identifier
    }

    /// The algorithm of [`hash`](Self::hash).
    #[must_use]
    pub fn hash_algorithm(&self) -> PolicyHashAlgorithm {
        self.hash_algorithm
    }

    /// The hash of the policy document.
    #[must_use]
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// The qualifiers, in the order they are encoded.
    #[must_use]
    pub fn qualifiers(&self) -> &[PolicyQualifier] {
        &self.qualifiers
    }
}

/// The signature policy a signature claims.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignaturePolicy {
    /// A policy named by its identifier.
    Explicit(ExplicitPolicy),
}

impl SignaturePolicy {
    /// The AGE signature policy, version 1.9, as `AutoFirma` signs it.
    #[must_use]
    pub fn age_v1_9() -> Self {
        ExplicitPolicy::new(
            AGE_V1_9_OID,
            PolicyHashAlgorithm::Sha1,
            AGE_V1_9_SHA1.to_vec(),
        )
        .qualifier(PolicyQualifier::Spuri(AGE_V1_9_URL.to_owned()))
        .into()
    }

    pub(crate) fn to_der(&self) -> Result<Vec<u8>, Error> {
        let Self::Explicit(policy) = self;
        let expected = policy.hash_algorithm.output_len();
        if policy.hash.len() != expected {
            return Err(Error::PolicyHashLength {
                algorithm: policy.hash_algorithm,
                expected,
                actual: policy.hash.len(),
            });
        }
        let qualifiers = policy
            .qualifiers
            .iter()
            .map(|PolicyQualifier::Spuri(uri)| {
                Ok(SigPolicyQualifierInfo {
                    id: ID_SPURI,
                    qualifier: Any::encode_from(&Ia5String::new(uri)?)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(SignaturePolicyId {
            id: policy.identifier,
            hash: OtherHashAlgAndValue {
                algorithm: AlgorithmIdentifierOwned {
                    oid: policy.hash_algorithm.oid(),
                    parameters: None,
                },
                value: OctetString::new(policy.hash.as_slice())?,
            },
            qualifiers: (!qualifiers.is_empty()).then_some(qualifiers),
        }
        .to_der()?)
    }
}

impl<'a> Decode<'a> for SignaturePolicy {
    type Error = der::Error;

    fn decode<R: der::Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        let id = SignaturePolicyId::decode(reader)?;
        let hash_algorithm = PolicyHashAlgorithm::from_oid(id.hash.algorithm.oid)
            .ok_or_else(|| Tag::ObjectIdentifier.value_error())?;
        let qualifiers = id
            .qualifiers
            .unwrap_or_default()
            .into_iter()
            .map(|info| {
                if info.id != ID_SPURI || info.qualifier.tag() != Tag::Ia5String {
                    return Err(Tag::Sequence.value_error().into());
                }
                let uri: Ia5String = info.qualifier.decode_as()?;
                Ok(PolicyQualifier::Spuri(uri.as_str().to_owned()))
            })
            .collect::<der::Result<_>>()?;
        Ok(ExplicitPolicy {
            identifier: id.id,
            hash_algorithm,
            hash: id.hash.value.into_bytes().into_vec(),
            qualifiers,
        }
        .into())
    }
}

impl From<ExplicitPolicy> for SignaturePolicy {
    fn from(policy: ExplicitPolicy) -> Self {
        Self::Explicit(policy)
    }
}

#[derive(Sequence)]
struct SignaturePolicyId {
    id: ObjectIdentifier,
    hash: OtherHashAlgAndValue,
    #[asn1(optional = "true")]
    qualifiers: Option<Vec<SigPolicyQualifierInfo>>,
}

#[derive(Sequence)]
struct OtherHashAlgAndValue {
    algorithm: AlgorithmIdentifierOwned,
    value: OctetString,
}

#[derive(Sequence)]
struct SigPolicyQualifierInfo {
    id: ObjectIdentifier,
    qualifier: Any,
}
