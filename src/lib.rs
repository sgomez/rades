//! AdES signature formats from the ETSI standards, with the signing key kept outside the crate.

mod algorithm;
pub mod cades;
mod certificate;
mod cms;
mod error;
mod signing;

pub use algorithm::{DigestAlgorithm, SignatureAlgorithm};
pub use certificate::Certificate;
pub use error::Error;
pub use signing::{DataToSign, SignatureValue, SigningTime};
