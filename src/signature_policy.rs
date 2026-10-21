//! Signature policy values shared by every format (EN 319 122-1, section 5.2.9).

use std::fmt;

use der::asn1::{Any, BmpString, Ia5String, Null, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Sequence, Tag, Tagged};
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::{DigestAlgorithm, Error};

const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const ID_SPURI: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.5.1");
const ID_SP_USER_NOTICE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.5.2");
const ID_SP_DOC_SPECIFICATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.19122.2.1");
const NOTICE_TEXT_CHARS: std::ops::RangeInclusive<usize> = 1..=200;
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
    /// A notice to show whenever the signature is validated (`SPUserNotice`).
    UserNotice(UserNotice),
    /// The technical specification of the policy document (`SPDocSpecification`).
    DocSpecification(DocSpecification),
}

/// Text of a policy notice, in one of the string types `DisplayText` admits.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DisplayText {
    /// `VisibleString`: printable ASCII.
    Visible(String),
    /// `BMPString`.
    Bmp(String),
    /// `UTF8String`.
    Utf8(String),
}

impl DisplayText {
    fn to_any(&self) -> Result<Any, Error> {
        let (Self::Visible(text) | Self::Bmp(text) | Self::Utf8(text)) = self;
        let chars = text.chars().count();
        if !NOTICE_TEXT_CHARS.contains(&chars) {
            return Err(Error::PolicyNoticeTextLength { actual: chars });
        }
        Ok(match self {
            Self::Visible(text) => {
                if !text.chars().all(|c| (' '..='~').contains(&c)) {
                    return Err(der::Error::from(Tag::VisibleString.value_error()).into());
                }
                Any::new(Tag::VisibleString, text.as_bytes())?
            }
            Self::Bmp(text) => Any::encode_from(&BmpString::from_utf8(text)?)?,
            Self::Utf8(text) => Any::new(Tag::Utf8String, text.as_bytes())?,
        })
    }

    fn from_any(any: &Any) -> der::Result<Self> {
        let text = || String::from_utf8(any.value().to_vec()).map_err(|_| any.tag().value_error());
        match any.tag() {
            Tag::VisibleString => Ok(Self::Visible(text()?)),
            Tag::Utf8String => Ok(Self::Utf8(text()?)),
            Tag::BmpString => Ok(Self::Bmp(any.decode_as::<BmpString>()?.chars().collect())),
            tag => Err(tag.value_error().into()),
        }
    }
}

/// Names a group of notices a notices file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoticeReference {
    /// The organization that prepared the notices.
    pub organization: DisplayText,
    /// The numbers of its notices.
    pub notice_numbers: Vec<u32>,
}

/// A notice to show whenever the signature is validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserNotice {
    /// Notices to look up in a notices file.
    pub notice_ref: Option<NoticeReference>,
    /// The text of the notice.
    pub explicit_text: Option<DisplayText>,
}

/// The technical specification that defines the syntax of the policy document.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DocSpecification {
    /// Identified by an object identifier.
    Oid(ObjectIdentifier),
    /// Identified by a URI.
    Uri(String),
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
    /// A policy that follows from the context.
    Implied,
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
        let Self::Explicit(policy) = self else {
            return Ok(Null.to_der()?);
        };
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
            .map(PolicyQualifier::to_info)
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

impl PolicyQualifier {
    fn to_info(&self) -> Result<SigPolicyQualifierInfo, Error> {
        let (id, qualifier) = match self {
            Self::Spuri(uri) => (ID_SPURI, Any::encode_from(&Ia5String::new(uri)?)?),
            Self::UserNotice(notice) => (
                ID_SP_USER_NOTICE,
                Any::encode_from(&SpUserNotice {
                    notice_ref: notice
                        .notice_ref
                        .as_ref()
                        .map(|reference| {
                            Ok::<_, Error>(DerNoticeReference {
                                organization: reference.organization.to_any()?,
                                notice_numbers: reference.notice_numbers.clone(),
                            })
                        })
                        .transpose()?,
                    explicit_text: notice
                        .explicit_text
                        .as_ref()
                        .map(DisplayText::to_any)
                        .transpose()?,
                })?,
            ),
            Self::DocSpecification(DocSpecification::Oid(oid)) => {
                (ID_SP_DOC_SPECIFICATION, Any::encode_from(oid)?)
            }
            Self::DocSpecification(DocSpecification::Uri(uri)) => (
                ID_SP_DOC_SPECIFICATION,
                Any::encode_from(&Ia5String::new(uri)?)?,
            ),
        };
        Ok(SigPolicyQualifierInfo { id, qualifier })
    }

    fn from_info(info: &SigPolicyQualifierInfo) -> der::Result<Self> {
        let qualifier = &info.qualifier;
        if info.id == ID_SPURI && qualifier.tag() == Tag::Ia5String {
            let uri: Ia5String = qualifier.decode_as()?;
            return Ok(Self::Spuri(uri.as_str().to_owned()));
        }
        if info.id == ID_SP_USER_NOTICE {
            let notice: SpUserNotice = qualifier.decode_as()?;
            return Ok(Self::UserNotice(UserNotice {
                notice_ref: notice
                    .notice_ref
                    .map(|reference| {
                        Ok::<_, der::Error>(NoticeReference {
                            organization: DisplayText::from_any(&reference.organization)?,
                            notice_numbers: reference.notice_numbers,
                        })
                    })
                    .transpose()?,
                explicit_text: notice
                    .explicit_text
                    .as_ref()
                    .map(DisplayText::from_any)
                    .transpose()?,
            }));
        }
        if info.id == ID_SP_DOC_SPECIFICATION {
            match qualifier.tag() {
                Tag::ObjectIdentifier => {
                    return Ok(Self::DocSpecification(DocSpecification::Oid(
                        qualifier.decode_as()?,
                    )));
                }
                Tag::Ia5String => {
                    let uri: Ia5String = qualifier.decode_as()?;
                    return Ok(Self::DocSpecification(DocSpecification::Uri(
                        uri.as_str().to_owned(),
                    )));
                }
                _ => {}
            }
        }
        Err(Tag::Sequence.value_error().into())
    }
}

impl<'a> Decode<'a> for SignaturePolicy {
    type Error = der::Error;

    fn decode<R: der::Reader<'a>>(reader: &mut R) -> der::Result<Self> {
        if Tag::peek(reader)? == Tag::Null {
            Null::decode(reader)?;
            return Ok(Self::Implied);
        }
        let id = SignaturePolicyId::decode(reader)?;
        let hash_algorithm = PolicyHashAlgorithm::from_oid(id.hash.algorithm.oid)
            .ok_or_else(|| Tag::ObjectIdentifier.value_error())?;
        let qualifiers = id
            .qualifiers
            .unwrap_or_default()
            .iter()
            .map(PolicyQualifier::from_info)
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

#[derive(Sequence)]
struct SpUserNotice {
    #[asn1(optional = "true")]
    notice_ref: Option<DerNoticeReference>,
    #[asn1(optional = "true")]
    explicit_text: Option<Any>,
}

#[derive(Sequence)]
struct DerNoticeReference {
    organization: Any,
    notice_numbers: Vec<u32>,
}
