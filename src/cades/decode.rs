//! Decoding a CMS `SignedData` (RFC 5652) into its content and signers, without verifying it.

mod signing_certificate;

pub use signing_certificate::{CertId, IssuerAndSerial, SigningCertificate};

use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Tag, Tagged};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;

use crate::cms::read::{self, ID_COUNTERSIGNATURE, Set};
use crate::cms::{
    ContentInfo, ID_MESSAGE_DIGEST, ID_SIGNED_DATA, ID_SIGNING_TIME, IssuerAndSerialNumber,
};
use crate::{Certificate, Error, SigningTime};

/// `md5` and `md5WithRSAEncryption`.
const MD5: [ObjectIdentifier; 2] = [
    ObjectIdentifier::new_unwrap("1.2.840.113549.2.5"),
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.4"),
];
const SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// A decoded CMS signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSignature {
    content_type: ObjectIdentifier,
    content: Option<Vec<u8>>,
    signers: Vec<Signer>,
}

impl DecodedSignature {
    /// The type of the signed content, `id-data` for plain bytes.
    #[must_use]
    pub fn content_type(&self) -> ObjectIdentifier {
        self.content_type
    }

    /// The signed content when attached, `None` when detached.
    #[must_use]
    pub fn content(&self) -> Option<&[u8]> {
        self.content.as_deref()
    }

    /// The signers of the `SignedData`, in encoding order; countersignatures stay attributes.
    #[must_use]
    pub fn signers(&self) -> &[Signer] {
        &self.signers
    }
}

/// One `SignerInfo` of a decoded signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    identifier: SignerIdentifier,
    certificate: Option<Certificate>,
    digest_algorithm: AlgorithmIdentifier,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: Vec<u8>,
    signed_attributes: Vec<Attribute>,
    unsigned_attributes: Vec<Attribute>,
    message_digest: Option<Vec<u8>>,
    signing_time: Option<SigningTime>,
    signing_certificate: Option<SigningCertificate>,
}

impl Signer {
    /// How the signer names its certificate.
    #[must_use]
    pub fn identifier(&self) -> &SignerIdentifier {
        &self.identifier
    }

    /// The signer's certificate, when the signature embeds it.
    #[must_use]
    pub fn certificate(&self) -> Option<&Certificate> {
        self.certificate.as_ref()
    }

    /// The algorithm that digests the content and the signed attributes.
    #[must_use]
    pub fn digest_algorithm(&self) -> &AlgorithmIdentifier {
        &self.digest_algorithm
    }

    /// The algorithm of the signature value.
    #[must_use]
    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.signature_algorithm
    }

    /// The signature value, unverified.
    #[must_use]
    pub fn signature_value(&self) -> &[u8] {
        &self.signature_value
    }

    /// The signed attributes, in encoding order; empty when the signer signs the content.
    #[must_use]
    pub fn signed_attributes(&self) -> &[Attribute] {
        &self.signed_attributes
    }

    /// The signed attribute of type `oid`, if any.
    #[must_use]
    pub fn signed_attribute(&self, oid: ObjectIdentifier) -> Option<&Attribute> {
        self.signed_attributes.iter().find(|a| a.oid == oid)
    }

    /// The unsigned attributes, in encoding order.
    #[must_use]
    pub fn unsigned_attributes(&self) -> &[Attribute] {
        &self.unsigned_attributes
    }

    /// The `message-digest` signed attribute: the digest of the content.
    #[must_use]
    pub fn message_digest(&self) -> Option<&[u8]> {
        self.message_digest.as_deref()
    }

    /// The `signing-time` signed attribute.
    #[must_use]
    pub fn signing_time(&self) -> Option<SigningTime> {
        self.signing_time
    }

    /// The `signing-certificate-v2` signed attribute, or else the `signing-certificate`.
    #[must_use]
    pub fn signing_certificate(&self) -> Option<&SigningCertificate> {
        self.signing_certificate.as_ref()
    }
}

/// The certificate a signer names (RFC 5652, section 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignerIdentifier {
    /// The issuer, as an RFC 4514 string, and the serial number's bytes.
    IssuerAndSerialNumber {
        /// Issuer distinguished name.
        issuer: String,
        /// Serial number, big-endian.
        serial_number: Vec<u8>,
    },
    /// The certificate's subject key identifier.
    SubjectKeyIdentifier(Vec<u8>),
}

/// An algorithm as the signature encodes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlgorithmIdentifier {
    oid: ObjectIdentifier,
    parameters: Option<Vec<u8>>,
}

impl AlgorithmIdentifier {
    /// The algorithm's object identifier.
    #[must_use]
    pub fn oid(&self) -> ObjectIdentifier {
        self.oid
    }

    /// The DER parameters, `None` when absent.
    #[must_use]
    pub fn parameters(&self) -> Option<&[u8]> {
        self.parameters.as_deref()
    }
}

/// A signed or unsigned attribute: its type and its DER values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    oid: ObjectIdentifier,
    values: Vec<Vec<u8>>,
}

impl Attribute {
    /// The attribute type.
    #[must_use]
    pub fn oid(&self) -> ObjectIdentifier {
        self.oid
    }

    /// Each value, DER-encoded.
    #[must_use]
    pub fn values(&self) -> &[Vec<u8>] {
        &self.values
    }
}

/// Decodes a CMS signature, `.p7s` or `.p7m`, in DER.
///
/// # Errors
/// [`Error::MalformedSignature`] if the bytes are not a CMS `SignedData`,
/// [`Error::RejectedDigestAlgorithm`] if it uses MD5 anywhere.
pub fn decode(der: &[u8]) -> Result<DecodedSignature, Error> {
    let content_info = ContentInfo::from_der(der).map_err(malformed)?;
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(Error::MalformedSignature(format!(
            "content type {} is not signed data",
            content_info.content_type
        )));
    }
    let mut algorithms = Vec::new();
    let decoded = signed_data(&content_info.content, &mut algorithms).map_err(malformed)?;
    if algorithms.iter().any(|oid| MD5.contains(oid)) {
        return Err(Error::RejectedDigestAlgorithm("MD5".to_owned()));
    }
    Ok(decoded)
}

fn malformed(error: der::Error) -> Error {
    Error::MalformedSignature(error.to_string())
}

/// Decodes the `SignedData`, collecting into `algorithms` every algorithm it names.
fn signed_data(
    content: &Any,
    algorithms: &mut Vec<ObjectIdentifier>,
) -> der::Result<DecodedSignature> {
    let signed_data: read::SignedData = content.decode_as()?;
    algorithms.extend(signed_data.digest_algorithms.0.iter().map(|a| a.oid));
    let certificates = certificates(signed_data.certificates)?;
    let signers = signed_data
        .signer_infos
        .0
        .into_iter()
        .map(|info| signer(info, &certificates, algorithms))
        .collect::<der::Result<_>>()?;
    let encap = signed_data.encap_content_info;
    Ok(DecodedSignature {
        content_type: encap.e_content_type,
        content: encap.e_content.map(|c| c.into_bytes().into_vec()),
        signers,
    })
}

fn certificates(set: Option<Set<Any>>) -> der::Result<Vec<x509_cert::Certificate>> {
    set.map_or_else(Vec::new, |set| set.0)
        .into_iter()
        .filter(|choice| choice.tag() == Tag::Sequence)
        .map(|choice| choice.decode_as())
        .collect()
}

fn signer(
    info: read::SignerInfo,
    certificates: &[x509_cert::Certificate],
    algorithms: &mut Vec<ObjectIdentifier>,
) -> der::Result<Signer> {
    let signed_attrs = info.signed_attrs.map_or_else(Vec::new, |set| set.0);
    let unsigned_attrs = info.unsigned_attrs.map_or_else(Vec::new, |set| set.0);
    for countersignature in unsigned_attrs
        .iter()
        .filter(|a| a.oid == ID_COUNTERSIGNATURE)
    {
        for value in countersignature.values.iter() {
            signer(value.decode_as()?, certificates, algorithms)?;
        }
    }
    let certificate = certificates
        .iter()
        .find(|c| identifies(&info.sid, c))
        .cloned()
        .map(Certificate::new);
    let signer = Signer {
        identifier: match info.sid {
            read::SignerIdentifier::IssuerAndSerialNumber(id) => {
                SignerIdentifier::IssuerAndSerialNumber {
                    issuer: id.issuer.to_string(),
                    serial_number: id.serial_number.as_bytes().to_vec(),
                }
            }
            read::SignerIdentifier::SubjectKeyIdentifier(ski) => {
                SignerIdentifier::SubjectKeyIdentifier(ski.into_bytes().into_vec())
            }
        },
        certificate,
        digest_algorithm: algorithm(info.digest_algorithm)?,
        signature_algorithm: algorithm(info.signature_algorithm)?,
        signature_value: info.signature.into_bytes().into_vec(),
        message_digest: single_value::<OctetString>(&signed_attrs, ID_MESSAGE_DIGEST)?
            .map(|digest| digest.into_bytes().into_vec()),
        signing_time: single_value::<Time>(&signed_attrs, ID_SIGNING_TIME)?
            .map(SigningTime::from_time),
        signing_certificate: signing_certificate::decode(&signed_attrs)?,
        signed_attributes: attributes(signed_attrs)?,
        unsigned_attributes: attributes(unsigned_attrs)?,
    };
    algorithms.extend([signer.digest_algorithm.oid, signer.signature_algorithm.oid]);
    if let Some(SigningCertificate::V1(certs) | SigningCertificate::V2(certs)) =
        &signer.signing_certificate
    {
        algorithms.extend(certs.iter().map(|c| c.hash_algorithm().oid));
    }
    Ok(signer)
}

fn identifies(sid: &read::SignerIdentifier, certificate: &x509_cert::Certificate) -> bool {
    let tbs = certificate.tbs_certificate();
    match sid {
        read::SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer,
            serial_number,
        }) => tbs.issuer() == issuer && tbs.serial_number() == serial_number,
        read::SignerIdentifier::SubjectKeyIdentifier(ski) => tbs
            .extensions()
            .into_iter()
            .flatten()
            .filter(|e| e.extn_id == SUBJECT_KEY_IDENTIFIER)
            .any(|e| OctetString::from_der(e.extn_value.as_bytes()).is_ok_and(|v| v == *ski)),
    }
}

/// The value of the attribute of type `oid`, which must have exactly one.
fn single_value<T: for<'a> Decode<'a, Error = der::Error>>(
    attributes: &[x509_cert::attr::Attribute],
    oid: ObjectIdentifier,
) -> der::Result<Option<T>> {
    let Some(attribute) = attributes.iter().find(|a| a.oid == oid) else {
        return Ok(None);
    };
    match attribute.values.as_slice() {
        [value] => T::from_der(&value.to_der()?).map(Some),
        _ => Err(Tag::Set.value_error().into()),
    }
}

fn attributes(attributes: Vec<x509_cert::attr::Attribute>) -> der::Result<Vec<Attribute>> {
    attributes
        .into_iter()
        .map(|attribute| {
            Ok(Attribute {
                oid: attribute.oid,
                values: attribute
                    .values
                    .iter()
                    .map(Encode::to_der)
                    .collect::<der::Result<_>>()?,
            })
        })
        .collect()
}

fn algorithm(identifier: AlgorithmIdentifierOwned) -> der::Result<AlgorithmIdentifier> {
    Ok(AlgorithmIdentifier {
        oid: identifier.oid,
        parameters: identifier.parameters.map(|p| p.to_der()).transpose()?,
    })
}
