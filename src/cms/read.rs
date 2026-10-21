//! CMS structures as found in a signature to decode, where RFC 5652 allows more than rades writes.

use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{
    Choice, Decode, DecodeValue, Encode, EncodeValue, FixedTag, Header, Length, Reader, Sequence,
    Tag, Writer,
};
use x509_cert::attr::Attribute;
use x509_cert::spki::AlgorithmIdentifierOwned;

use super::{EncapsulatedContentInfo, IssuerAndSerialNumber, IssuerSerial};

/// A `SET OF` kept in encoding order and without DER's ordering check.
pub(crate) struct Set<T>(pub(crate) Vec<T>);

impl<'a, T: Decode<'a, Error = der::Error>> DecodeValue<'a> for Set<T> {
    type Error = der::Error;

    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> der::Result<Self> {
        let mut elements = Vec::new();
        while !reader.is_finished() {
            elements.push(T::decode(reader)?);
        }
        Ok(Self(elements))
    }
}

impl<T: Encode> EncodeValue for Set<T> {
    fn value_len(&self) -> der::Result<Length> {
        self.0
            .iter()
            .try_fold(Length::ZERO, |len, e| len + e.encoded_len()?)
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.0.iter().try_for_each(|e| e.encode(writer))
    }
}

impl<T> FixedTag for Set<T> {
    const TAG: Tag = Tag::Set;
}

#[derive(Sequence)]
pub(crate) struct SignedData {
    pub(crate) version: u8,
    pub(crate) digest_algorithms: Set<AlgorithmIdentifierOwned>,
    pub(crate) encap_content_info: EncapsulatedContentInfo,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub(crate) certificates: Option<Set<Any>>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub(crate) crls: Option<Set<Any>>,
    pub(crate) signer_infos: Set<SignerInfo>,
}

#[derive(Sequence)]
pub(crate) struct SignerInfo {
    pub(crate) version: u8,
    pub(crate) sid: SignerIdentifier,
    pub(crate) digest_algorithm: AlgorithmIdentifierOwned,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub(crate) signed_attrs: Option<Set<Attribute>>,
    pub(crate) signature_algorithm: AlgorithmIdentifierOwned,
    pub(crate) signature: OctetString,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub(crate) unsigned_attrs: Option<Set<Attribute>>,
}

#[derive(Choice)]
pub(crate) enum SignerIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    SubjectKeyIdentifier(OctetString),
}

/// `SigningCertificate` (RFC 2634).
#[derive(Sequence)]
pub(crate) struct SigningCertificate {
    pub(crate) certs: Vec<EssCertId>,
    #[asn1(optional = "true")]
    pub(crate) policies: Option<Any>,
}

/// `SigningCertificateV2` (RFC 5035).
#[derive(Sequence)]
pub(crate) struct SigningCertificateV2 {
    pub(crate) certs: Vec<EssCertIdV2>,
    #[asn1(optional = "true")]
    pub(crate) policies: Option<Any>,
}

#[derive(Sequence)]
pub(crate) struct EssCertId {
    pub(crate) cert_hash: OctetString,
    #[asn1(optional = "true")]
    pub(crate) issuer_serial: Option<IssuerSerial>,
}

/// `hash_algorithm` is `None` for SHA-256, its DER default.
#[derive(Sequence)]
pub(crate) struct EssCertIdV2 {
    #[asn1(optional = "true")]
    pub(crate) hash_algorithm: Option<AlgorithmIdentifierOwned>,
    pub(crate) cert_hash: OctetString,
    #[asn1(optional = "true")]
    pub(crate) issuer_serial: Option<IssuerSerial>,
}

pub(crate) const ID_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
pub(crate) const ID_COUNTERSIGNATURE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.6");
