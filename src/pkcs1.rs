//! `AutoFirma`'s raw PKCS#1 mode (`NONE`): the signature value over the content, as is.

use crate::certificate::PublicKey;
use crate::{Certificate, Error, SignatureValue};

/// Phase 1 done: the content, waiting for its signature value.
#[derive(Debug)]
pub struct PendingSignature {
    content: Vec<u8>,
    modulus_len: usize,
}

/// Phase 1: the content is the data to sign.
///
/// # Errors
/// [`Error::NotRsaKey`] if the certificate's key is not RSA.
pub fn sign(content: &[u8], certificate: &Certificate) -> Result<PendingSignature, Error> {
    match certificate.public_key()? {
        PublicKey::Rsa { modulus_len } => Ok(PendingSignature {
            content: content.to_vec(),
            modulus_len,
        }),
        key => Err(Error::NotRsaKey { key: key.name() }),
    }
}

impl PendingSignature {
    /// The bytes to sign, with PKCS#1 v1.5 padding and no `DigestInfo`.
    #[must_use]
    pub fn data_to_sign(&self) -> &[u8] {
        &self.content
    }

    /// Phase 2: the signature value, unchanged.
    ///
    /// # Errors
    /// [`Error::SignatureValueLength`] if the value is not as long as the modulus.
    pub fn complete(self, value: &SignatureValue) -> Result<Vec<u8>, Error> {
        let bytes = value.as_bytes();
        if bytes.len() != self.modulus_len {
            return Err(Error::SignatureValueLength {
                expected: self.modulus_len,
                actual: bytes.len(),
            });
        }
        Ok(bytes.to_vec())
    }
}
