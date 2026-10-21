//! CAdES baseline signatures (EN 319 122-1) over CMS `SignedData` (RFC 5652).

use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode};
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::name::GeneralName;

use crate::certificate::PublicKey;
use crate::cms::{
    self, CmsAlgorithmProtection, ContentInfo, EncapsulatedContentInfo, EssCertIdV2,
    ID_CMS_ALGORITHM_PROTECTION, ID_CONTENT_HINTS, ID_CONTENT_IDENTIFIER, ID_CONTENT_REFERENCE,
    ID_CONTENT_TYPE, ID_DATA, ID_MESSAGE_DIGEST, ID_MIME_TYPE, ID_SIGNED_DATA,
    ID_SIGNING_CERTIFICATE_V2, ID_SIGNING_TIME, IssuerAndSerialNumber, IssuerSerial, SignedData,
    SignerInfo, SigningCertificateV2,
};
use crate::{
    Certificate, DataToSign, DigestAlgorithm, Error, SignatureAlgorithm, SignatureValue,
    SigningTime,
};

/// The content a signature covers.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Content<'a> {
    /// Signed but not embedded: the verifier gets it apart.
    Detached(&'a [u8]),
    /// Signed and embedded in the signature.
    Attached(&'a [u8]),
    /// Signed through a digest the caller computed, as a detached signature.
    Digest {
        /// The algorithm that produced `digest`.
        algorithm: DigestAlgorithm,
        /// The digest of the content.
        digest: &'a [u8],
    },
}

/// Which certificates the `SignedData` carries.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum Certificates {
    /// The signer certificate only.
    #[default]
    Signer,
    /// The signer certificate and these, typically its chain.
    Chain(Vec<Certificate>),
    /// No certificate.
    None,
}

/// The `content-hints` attribute: what the signed content is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentHints {
    description: Option<String>,
    content_type: ObjectIdentifier,
}

impl ContentHints {
    /// A description, if any, and the content type of the signed content.
    #[must_use]
    pub fn new(description: Option<String>, content_type: ObjectIdentifier) -> Self {
        Self {
            description,
            content_type,
        }
    }
}

/// The `content-reference` attribute: a link to another message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentReference {
    /// Content type of the referenced message.
    pub content_type: ObjectIdentifier,
    /// Its `content-identifier`.
    pub signed_content_identifier: Vec<u8>,
    /// The signature value of its originator.
    pub originator_signature_value: Vec<u8>,
}

/// CAdES options beyond the signature algorithm and time.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Options {
    mime_type: Option<String>,
    content_hints: Option<ContentHints>,
    content_identifier: Option<Vec<u8>>,
    content_reference: Option<ContentReference>,
    certificates: Certificates,
}

impl Options {
    /// Adds the `mime-type` signed attribute.
    #[must_use]
    pub fn mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.mime_type = Some(mime_type.into());
        self
    }

    /// Adds the `content-hints` signed attribute.
    #[must_use]
    pub fn content_hints(mut self, hints: ContentHints) -> Self {
        self.content_hints = Some(hints);
        self
    }

    /// Adds the `content-identifier` signed attribute.
    #[must_use]
    pub fn content_identifier(mut self, identifier: Vec<u8>) -> Self {
        self.content_identifier = Some(identifier);
        self
    }

    /// Adds the `content-reference` signed attribute.
    #[must_use]
    pub fn content_reference(mut self, reference: ContentReference) -> Self {
        self.content_reference = Some(reference);
        self
    }

    /// Chooses the certificates embedded in the `SignedData`.
    #[must_use]
    pub fn certificates(mut self, certificates: Certificates) -> Self {
        self.certificates = certificates;
        self
    }
}

/// Phase 1 done: the data to sign, waiting for its signature value.
#[derive(Debug)]
pub struct PendingSignature {
    data_to_sign: Vec<DataToSign>,
    signed_attrs: SetOfVec<Attribute>,
    embedded_content: Option<Vec<u8>>,
    certificate: Certificate,
    embedded: Vec<x509_cert::Certificate>,
    modulus_len: usize,
}

/// Phase 1: builds a CAdES B-B up to its data to sign.
///
/// # Errors
/// [`Error::AlgorithmMismatch`] if `algorithm` does not fit the certificate's key.
pub fn sign(
    content: Content<'_>,
    certificate: &Certificate,
    algorithm: SignatureAlgorithm,
    signing_time: SigningTime,
    options: &Options,
) -> Result<PendingSignature, Error> {
    build(
        content,
        certificate,
        algorithm,
        signing_time,
        &options.certificates,
        Some(options),
    )
}

/// Phase 1 of AutoFirma's bare CMS: a `SignedData` signing only `content-type`,
/// `message-digest` and `signing-time`.
///
/// # Errors
/// [`Error::AlgorithmMismatch`] if `algorithm` does not fit the certificate's key.
pub fn sign_bare(
    content: Content<'_>,
    certificate: &Certificate,
    algorithm: SignatureAlgorithm,
    signing_time: SigningTime,
    certificates: &Certificates,
) -> Result<PendingSignature, Error> {
    build(
        content,
        certificate,
        algorithm,
        signing_time,
        certificates,
        None,
    )
}

/// `options` is `None` for bare CMS.
fn build(
    content: Content<'_>,
    certificate: &Certificate,
    algorithm: SignatureAlgorithm,
    signing_time: SigningTime,
    certificates: &Certificates,
    options: Option<&Options>,
) -> Result<PendingSignature, Error> {
    let modulus_len = match (algorithm, certificate.public_key()?) {
        (SignatureAlgorithm::RsaPkcs1v15(_), PublicKey::Rsa { modulus_len }) => modulus_len,
        (_, key) => {
            return Err(Error::AlgorithmMismatch {
                algorithm,
                key: key.name(),
            });
        }
    };
    let digest_algorithm = algorithm.digest_algorithm();
    let (content_digest, embedded) = match content {
        Content::Detached(bytes) => (digest_algorithm.digest(bytes), None),
        Content::Attached(bytes) => (digest_algorithm.digest(bytes), Some(bytes.to_vec())),
        Content::Digest {
            algorithm: given,
            digest,
        } => {
            if digest.len() != given.output_len() {
                return Err(Error::DigestLength {
                    algorithm: given,
                    expected: given.output_len(),
                    actual: digest.len(),
                });
            }
            (digest.to_vec(), None)
        }
    };
    let mut attributes = vec![
        attribute(ID_CONTENT_TYPE, &ID_DATA)?,
        attribute(ID_MESSAGE_DIGEST, &OctetString::new(content_digest)?)?,
        attribute(ID_SIGNING_TIME, &signing_time.to_time())?,
    ];
    if let Some(options) = options {
        attributes.push(attribute(
            ID_SIGNING_CERTIFICATE_V2,
            &signing_certificate_v2(certificate, digest_algorithm)?,
        )?);
        attributes.push(attribute(
            ID_CMS_ALGORITHM_PROTECTION,
            &CmsAlgorithmProtection {
                digest_algorithm: digest_algorithm.identifier(),
                signature_algorithm: algorithm.identifier(),
            },
        )?);
        attributes.extend(optional_attributes(options)?);
    }
    let signed_attrs = SetOfVec::try_from(attributes)?;
    Ok(PendingSignature {
        data_to_sign: vec![DataToSign::new(signed_attrs.to_der()?, algorithm)],
        signed_attrs,
        embedded_content: embedded,
        certificate: certificate.clone(),
        embedded: embedded_certificates(certificate, certificates),
        modulus_len,
    })
}

fn optional_attributes(options: &Options) -> Result<Vec<Attribute>, Error> {
    let mut attributes = Vec::new();
    if let Some(mime_type) = &options.mime_type {
        attributes.push(attribute(ID_MIME_TYPE, mime_type)?);
    }
    if let Some(hints) = &options.content_hints {
        attributes.push(attribute(
            ID_CONTENT_HINTS,
            &cms::ContentHints {
                description: hints.description.clone(),
                content_type: hints.content_type,
            },
        )?);
    }
    if let Some(identifier) = &options.content_identifier {
        attributes.push(attribute(
            ID_CONTENT_IDENTIFIER,
            &OctetString::new(identifier.as_slice())?,
        )?);
    }
    if let Some(reference) = &options.content_reference {
        attributes.push(attribute(
            ID_CONTENT_REFERENCE,
            &cms::ContentReference {
                content_type: reference.content_type,
                signed_content_identifier: OctetString::new(
                    reference.signed_content_identifier.as_slice(),
                )?,
                originator_signature_value: OctetString::new(
                    reference.originator_signature_value.as_slice(),
                )?,
            },
        )?);
    }
    Ok(attributes)
}

fn embedded_certificates(
    signer: &Certificate,
    certificates: &Certificates,
) -> Vec<x509_cert::Certificate> {
    match certificates {
        Certificates::Signer => vec![signer.inner().clone()],
        Certificates::Chain(chain) => std::iter::once(signer)
            .chain(chain.iter().filter(|c| *c != signer))
            .map(|c| c.inner().clone())
            .collect(),
        Certificates::None => Vec::new(),
    }
}

fn attribute(oid: ObjectIdentifier, value: &impl Encode) -> Result<Attribute, Error> {
    Ok(Attribute {
        oid,
        values: SetOfVec::try_from(vec![Any::from_der(&value.to_der()?)?])?,
    })
}

fn signing_certificate_v2(
    certificate: &Certificate,
    digest_algorithm: DigestAlgorithm,
) -> Result<SigningCertificateV2, Error> {
    let tbs = certificate.inner().tbs_certificate();
    Ok(SigningCertificateV2 {
        certs: vec![EssCertIdV2 {
            hash_algorithm: (digest_algorithm != DigestAlgorithm::Sha256)
                .then(|| digest_algorithm.identifier()),
            cert_hash: OctetString::new(digest_algorithm.digest(&certificate.inner().to_der()?))?,
            issuer_serial: IssuerSerial {
                issuer: vec![GeneralName::DirectoryName(tbs.issuer().clone())],
                serial_number: tbs.serial_number().clone(),
            },
        }],
    })
}

impl PendingSignature {
    /// The data to sign, one signature value each.
    #[must_use]
    pub fn data_to_sign(&self) -> &[DataToSign] {
        &self.data_to_sign
    }

    /// Phase 2: the encoded CAdES with the signature values, matched by position.
    ///
    /// # Errors
    /// [`Error::SignatureValueCount`] or [`Error::SignatureValueLength`] if a value has the
    /// wrong shape.
    pub fn complete(self, values: &[SignatureValue]) -> Result<Vec<u8>, Error> {
        let [value] = values else {
            return Err(Error::SignatureValueCount {
                expected: self.data_to_sign.len(),
                actual: values.len(),
            });
        };
        if value.as_bytes().len() != self.modulus_len {
            return Err(Error::SignatureValueLength {
                expected: self.modulus_len,
                actual: value.as_bytes().len(),
            });
        }
        let algorithm = self.data_to_sign[0].algorithm();
        let digest_algorithm = algorithm.digest_algorithm();
        let tbs = self.certificate.inner().tbs_certificate();
        let signer_info = SignerInfo {
            version: 1,
            sid: IssuerAndSerialNumber {
                issuer: tbs.issuer().clone(),
                serial_number: tbs.serial_number().clone(),
            },
            digest_algorithm: digest_algorithm.identifier(),
            signed_attrs: self.signed_attrs,
            signature_algorithm: algorithm.identifier(),
            signature: OctetString::new(value.as_bytes())?,
        };
        let signed_data = SignedData {
            version: 1,
            digest_algorithms: SetOfVec::try_from(vec![digest_algorithm.identifier()])?,
            encap_content_info: EncapsulatedContentInfo {
                e_content_type: ID_DATA,
                e_content: self.embedded_content.map(OctetString::new).transpose()?,
            },
            certificates: if self.embedded.is_empty() {
                None
            } else {
                Some(SetOfVec::try_from(self.embedded)?)
            },
            signer_infos: SetOfVec::try_from(vec![signer_info])?,
        };
        Ok(ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::from_der(&signed_data.to_der()?)?,
        }
        .to_der()?)
    }
}
