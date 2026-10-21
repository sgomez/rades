//! CMS structures of RFC 5652 and the ESS attributes of RFC 5035, as DER.

use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use der::{Sequence, ValueOrd};
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::name::GeneralNames;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;

pub(crate) const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
pub(crate) const ID_SIGNED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
pub(crate) const ID_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
pub(crate) const ID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
pub(crate) const ID_SIGNING_TIME: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
pub(crate) const ID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
pub(crate) const ID_CMS_ALGORITHM_PROTECTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.52");

pub(crate) const ID_MIME_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.4.0.1733.2.1");
pub(crate) const ID_CONTENT_HINTS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.4");
pub(crate) const ID_CONTENT_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.7");
pub(crate) const ID_CONTENT_REFERENCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.10");

#[derive(Sequence)]
pub(crate) struct ContentHints {
    #[asn1(optional = "true")]
    pub(crate) description: Option<String>,
    pub(crate) content_type: ObjectIdentifier,
}

#[derive(Sequence)]
pub(crate) struct ContentReference {
    pub(crate) content_type: ObjectIdentifier,
    pub(crate) signed_content_identifier: OctetString,
    pub(crate) originator_signature_value: OctetString,
}

#[derive(Sequence)]
pub(crate) struct ContentInfo {
    pub(crate) content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT")]
    pub(crate) content: Any,
}

#[derive(Sequence)]
pub(crate) struct SignedData {
    pub(crate) version: u8,
    pub(crate) digest_algorithms: SetOfVec<AlgorithmIdentifierOwned>,
    pub(crate) encap_content_info: EncapsulatedContentInfo,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub(crate) certificates: Option<SetOfVec<x509_cert::Certificate>>,
    pub(crate) signer_infos: SetOfVec<SignerInfo>,
}

#[derive(Sequence)]
pub(crate) struct EncapsulatedContentInfo {
    pub(crate) e_content_type: ObjectIdentifier,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub(crate) e_content: Option<OctetString>,
}

#[derive(Clone, Sequence, ValueOrd)]
pub(crate) struct SignerInfo {
    pub(crate) version: u8,
    pub(crate) sid: IssuerAndSerialNumber,
    pub(crate) digest_algorithm: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    pub(crate) signed_attrs: SetOfVec<Attribute>,
    pub(crate) signature_algorithm: AlgorithmIdentifierOwned,
    pub(crate) signature: OctetString,
}

#[derive(Clone, Sequence, ValueOrd)]
pub(crate) struct IssuerAndSerialNumber {
    pub(crate) issuer: Name,
    pub(crate) serial_number: SerialNumber,
}

#[derive(Sequence)]
pub(crate) struct SigningCertificateV2 {
    pub(crate) certs: Vec<EssCertIdV2>,
}

/// `hash_algorithm` is `None` for SHA-256, its DER default.
#[derive(Sequence)]
pub(crate) struct EssCertIdV2 {
    #[asn1(optional = "true")]
    pub(crate) hash_algorithm: Option<AlgorithmIdentifierOwned>,
    pub(crate) cert_hash: OctetString,
    pub(crate) issuer_serial: IssuerSerial,
}

#[derive(Sequence)]
pub(crate) struct IssuerSerial {
    pub(crate) issuer: GeneralNames,
    pub(crate) serial_number: SerialNumber,
}

#[derive(Sequence)]
pub(crate) struct DigestInfo {
    pub(crate) digest_algorithm: AlgorithmIdentifierOwned,
    pub(crate) digest: OctetString,
}

/// RFC 6211, without the MAC algorithm.
#[derive(Sequence)]
pub(crate) struct CmsAlgorithmProtection {
    pub(crate) digest_algorithm: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT")]
    pub(crate) signature_algorithm: AlgorithmIdentifierOwned,
}
