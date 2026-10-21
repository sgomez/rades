//! AdES signature formats from the ETSI standards, with the signing key kept outside the crate.

mod algorithm;
pub mod cades;
mod certificate;
mod cms;
mod ecdsa;
mod error;
pub mod pkcs1;
mod signature_policy;
mod signing;

pub use der::asn1::ObjectIdentifier;

pub use algorithm::{DigestAlgorithm, SignatureAlgorithm};
pub use certificate::Certificate;
pub use error::Error;
pub use signature_policy::{ExplicitPolicy, PolicyHashAlgorithm, PolicyQualifier, SignaturePolicy};
pub use signing::{DataToSign, SignatureValue, SigningTime};
