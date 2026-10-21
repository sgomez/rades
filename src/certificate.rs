//! The signer's X.509 certificate.

use der::asn1::{ObjectIdentifier, UintRef};
use der::{Decode, DecodePem, Sequence};

use crate::Error;

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// An X.509 certificate (RFC 5280).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate(x509_cert::Certificate);

/// The certificate's public key, as far as signing needs it.
pub(crate) enum PublicKey {
    Rsa { modulus_len: usize },
    Ec,
    Other(ObjectIdentifier),
}

impl PublicKey {
    pub(crate) fn name(&self) -> String {
        match self {
            Self::Rsa { .. } => "RSA".to_owned(),
            Self::Ec => "EC".to_owned(),
            Self::Other(oid) => oid.to_string(),
        }
    }
}

#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

impl Certificate {
    /// Parses a DER certificate.
    ///
    /// # Errors
    /// [`Error::InvalidCertificate`] if the bytes are not one.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        x509_cert::Certificate::from_der(der)
            .map(Self)
            .map_err(|e| Error::InvalidCertificate(e.to_string()))
    }

    /// Parses a PEM certificate.
    ///
    /// # Errors
    /// [`Error::InvalidCertificate`] if the text is not one.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        x509_cert::Certificate::from_pem(pem)
            .map(Self)
            .map_err(|e| Error::InvalidCertificate(e.to_string()))
    }

    pub(crate) fn new(inner: x509_cert::Certificate) -> Self {
        Self(inner)
    }

    pub(crate) fn inner(&self) -> &x509_cert::Certificate {
        &self.0
    }

    pub(crate) fn public_key(&self) -> Result<PublicKey, Error> {
        let spki = self.0.tbs_certificate().subject_public_key_info();
        let oid = spki.algorithm.oid;
        if oid == EC_PUBLIC_KEY {
            return Ok(PublicKey::Ec);
        }
        if oid != RSA_ENCRYPTION {
            return Ok(PublicKey::Other(oid));
        }
        let bits = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| Error::InvalidCertificate("rsa key is not whole bytes".to_owned()))?;
        let key =
            RsaPublicKey::from_der(bits).map_err(|e| Error::InvalidCertificate(e.to_string()))?;
        Ok(PublicKey::Rsa {
            modulus_len: key.modulus.as_bytes().len(),
        })
    }
}
