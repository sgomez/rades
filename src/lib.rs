//! AdES signature formats from the ETSI standards, with the signing key kept outside the crate.

mod algorithm;
pub mod cades;
mod certificate;
mod cms;
mod ecdsa;
mod error;
pub mod pkcs1;
mod signing;

pub use algorithm::{DigestAlgorithm, SignatureAlgorithm};
pub use certificate::Certificate;
pub use error::Error;
pub use signing::{DataToSign, SignatureValue, SigningTime};
