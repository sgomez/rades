//! The `signing-certificate` (RFC 2634) and `signing-certificate-v2` (RFC 5035) attributes.

use der::asn1::ObjectIdentifier;
use x509_cert::ext::pkix::name::GeneralName;

use super::{AlgorithmIdentifier, algorithm, single_value};
use crate::DigestAlgorithm;
use crate::cms::read::{self, ID_SIGNING_CERTIFICATE};
use crate::cms::{ID_SIGNING_CERTIFICATE_V2, IssuerSerial};

const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

/// The certificates a signer binds to its signature, first its own.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningCertificate {
    /// `signing-certificate`, with SHA-1 hashes.
    V1(Vec<CertId>),
    /// `signing-certificate-v2`.
    V2(Vec<CertId>),
}

/// One certificate of a [`SigningCertificate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertId {
    hash_algorithm: AlgorithmIdentifier,
    hash: Vec<u8>,
    issuer_serial: Option<IssuerAndSerial>,
}

impl CertId {
    /// The algorithm of [`Self::hash`], its default filled in.
    #[must_use]
    pub fn hash_algorithm(&self) -> &AlgorithmIdentifier {
        &self.hash_algorithm
    }

    /// The hash of the whole DER certificate.
    #[must_use]
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// The certificate's issuer and serial number, when present as a directory name.
    #[must_use]
    pub fn issuer_serial(&self) -> Option<&IssuerAndSerial> {
        self.issuer_serial.as_ref()
    }
}

/// A certificate's issuer, as an RFC 4514 string, and its serial number's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerAndSerial {
    issuer: String,
    serial_number: Vec<u8>,
}

impl IssuerAndSerial {
    /// The issuer distinguished name.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The serial number, big-endian.
    #[must_use]
    pub fn serial_number(&self) -> &[u8] {
        &self.serial_number
    }
}

/// The v2 attribute if present, else the v1.
pub(super) fn decode(
    attributes: &[x509_cert::attr::Attribute],
) -> der::Result<Option<SigningCertificate>> {
    if let Some(v2) =
        single_value::<read::SigningCertificateV2>(attributes, ID_SIGNING_CERTIFICATE_V2)?
    {
        return v2
            .certs
            .into_iter()
            .map(|id| {
                Ok(CertId {
                    hash_algorithm: match id.hash_algorithm {
                        Some(identifier) => algorithm(identifier)?,
                        None => algorithm(DigestAlgorithm::Sha256.identifier())?,
                    },
                    hash: id.cert_hash.into_bytes().into_vec(),
                    issuer_serial: id.issuer_serial.and_then(issuer_serial),
                })
            })
            .collect::<der::Result<_>>()
            .map(|certs| Some(SigningCertificate::V2(certs)));
    }
    let Some(v1) = single_value::<read::SigningCertificate>(attributes, ID_SIGNING_CERTIFICATE)?
    else {
        return Ok(None);
    };
    Ok(Some(SigningCertificate::V1(
        v1.certs
            .into_iter()
            .map(|id| CertId {
                hash_algorithm: AlgorithmIdentifier {
                    oid: SHA1,
                    parameters: None,
                },
                hash: id.cert_hash.into_bytes().into_vec(),
                issuer_serial: id.issuer_serial.and_then(issuer_serial),
            })
            .collect(),
    )))
}

fn issuer_serial(id: IssuerSerial) -> Option<IssuerAndSerial> {
    id.issuer.into_iter().find_map(|name| match name {
        GeneralName::DirectoryName(issuer) => Some(IssuerAndSerial {
            issuer: issuer.to_string(),
            serial_number: id.serial_number.as_bytes().to_vec(),
        }),
        _ => None,
    })
}
