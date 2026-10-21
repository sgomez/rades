//! Values that cross the two signing phases, shared by every format.

use std::time::Duration;

use der::asn1::OctetString;
use der::{DateTime, Encode};
use x509_cert::time::Time;

use crate::cms::DigestInfo;
use crate::{Error, SignatureAlgorithm};

/// The time the signer claims to sign at, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningTime(DateTime);

impl SigningTime {
    /// Signing time `seconds` after the Unix epoch.
    ///
    /// # Errors
    /// [`Error::SigningTimeOutOfRange`] past the year 9999.
    pub fn from_unix_seconds(seconds: u64) -> Result<Self, Error> {
        DateTime::from_unix_duration(Duration::from_secs(seconds))
            .map(Self)
            .map_err(|_| Error::SigningTimeOutOfRange)
    }

    pub(crate) fn from_time(time: Time) -> Self {
        Self(time.to_date_time())
    }

    /// `UTCTime` up to 2049 and `GeneralizedTime` from 2050, as RFC 5652 asks.
    pub(crate) fn to_time(self) -> Time {
        Time::from(self.0)
    }
}

/// What the key signs: the bytes, and the algorithm to sign them with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataToSign {
    bytes: Vec<u8>,
    algorithm: SignatureAlgorithm,
}

impl DataToSign {
    pub(crate) fn new(bytes: Vec<u8>, algorithm: SignatureAlgorithm) -> Self {
        Self { bytes, algorithm }
    }

    /// The bytes to sign, for a key that hashes them itself.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The signature algorithm the caller named in phase 1.
    #[must_use]
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The digest of the bytes, for a key that signs hashes.
    #[must_use]
    pub fn digest(&self) -> Vec<u8> {
        self.algorithm.digest_algorithm().digest(&self.bytes)
    }

    /// The DER `DigestInfo` of the digest, for a key that signs it raw under PKCS#1 v1.5.
    ///
    /// # Errors
    /// [`Error::Encoding`] if the structure cannot be encoded.
    pub fn digest_info(&self) -> Result<Vec<u8>, Error> {
        let digest_algorithm = self.algorithm.digest_algorithm();
        Ok(DigestInfo {
            digest_algorithm: digest_algorithm.identifier_with_null(),
            digest: OctetString::new(self.digest())?,
        }
        .to_der()?)
    }
}

/// A signature value the caller's key produced over a [`DataToSign`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureValue(Vec<u8>);

impl SignatureValue {
    /// The value as the key returned it.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SignatureValue {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
