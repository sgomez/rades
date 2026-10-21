//! CAdES baseline signatures (EN 319 122-1) over CMS `SignedData` (RFC 5652).

use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode};
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::name::GeneralName;

use crate::certificate::PublicKey;
use crate::cms::{
    CmsAlgorithmProtection, ContentInfo, EncapsulatedContentInfo, EssCertIdV2,
    ID_CMS_ALGORITHM_PROTECTION, ID_CONTENT_TYPE, ID_DATA, ID_MESSAGE_DIGEST, ID_SIGNED_DATA,
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

/// CAdES options beyond the signature algorithm and time.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Options {}

/// Phase 1 done: the data to sign, waiting for its signature value.
#[derive(Debug)]
pub struct PendingSignature {
    data_to_sign: Vec<DataToSign>,
    signed_attrs: SetOfVec<Attribute>,
    embedded_content: Option<Vec<u8>>,
    certificate: Certificate,
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
    let _ = options;
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
    let signed_attrs = SetOfVec::try_from(vec![
        attribute(ID_CONTENT_TYPE, &ID_DATA)?,
        attribute(ID_MESSAGE_DIGEST, &OctetString::new(content_digest)?)?,
        attribute(ID_SIGNING_TIME, &signing_time.to_time())?,
        attribute(
            ID_SIGNING_CERTIFICATE_V2,
            &signing_certificate_v2(certificate, digest_algorithm)?,
        )?,
        attribute(
            ID_CMS_ALGORITHM_PROTECTION,
            &CmsAlgorithmProtection {
                digest_algorithm: digest_algorithm.identifier(),
                signature_algorithm: algorithm.identifier(),
            },
        )?,
    ])?;
    Ok(PendingSignature {
        data_to_sign: vec![DataToSign::new(signed_attrs.to_der()?, algorithm)],
        signed_attrs,
        embedded_content: embedded,
        certificate: certificate.clone(),
        modulus_len,
    })
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
            certificates: Some(SetOfVec::try_from(vec![self.certificate.inner().clone()])?),
            signer_infos: SetOfVec::try_from(vec![signer_info])?,
        };
        Ok(ContentInfo {
            content_type: ID_SIGNED_DATA,
            content: Any::from_der(&signed_data.to_der()?)?,
        }
        .to_der()?)
    }
}
