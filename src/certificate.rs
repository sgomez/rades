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
    Ec { curve: Curve },
    UnsupportedCurve(String),
    Other(ObjectIdentifier),
}

impl PublicKey {
    pub(crate) fn name(&self) -> String {
        match self {
            Self::Rsa { .. } => "RSA".to_owned(),
            Self::Ec { .. } | Self::UnsupportedCurve(_) => "EC".to_owned(),
            Self::Other(oid) => oid.to_string(),
        }
    }
}

/// The elliptic curves ECDSA signs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        match oid.to_string().as_str() {
            "1.2.840.10045.3.1.7" => Some(Self::P256),
            "1.3.132.0.34" => Some(Self::P384),
            "1.3.132.0.35" => Some(Self::P521),
            _ => None,
        }
    }

    /// Length in bytes of the curve's order.
    pub(crate) fn order_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
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
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<ObjectIdentifier>().ok())
                .ok_or_else(|| {
                    Error::InvalidCertificate("ec key without named curve".to_owned())
                })?;
            return Ok(Curve::from_oid(curve).map_or_else(
                || PublicKey::UnsupportedCurve(curve.to_string()),
                |curve| PublicKey::Ec { curve },
            ));
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
