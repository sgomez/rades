//! Decoding CMS signatures: rades' golden vectors and AutoFirma's fixtures.

mod common;

use der::{Decode, Encode};
use rades::cades::{self, SignerIdentifier, SigningCertificate};
use rades::{ObjectIdentifier, SigningTime};
use sha2::{Digest, Sha256, Sha384};

const SHA256: &str = "2.16.840.1.101.3.4.2.1";
const SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

fn oid(text: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(text)
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_detached_golden_vector_decodes_to_its_signer() {
    let decoded = cades::decode(&common::read("cades/bb-detached-rsa-sha256.p7m")).unwrap();
    assert_eq!(decoded.content(), None);
    assert_eq!(decoded.content_type(), oid("1.2.840.113549.1.7.1"));
    let [signer] = decoded.signers() else {
        panic!("one signer expected")
    };
    assert_eq!(
        signer.certificate(),
        Some(&common::certificate("signer-rsa"))
    );
    let SignerIdentifier::IssuerAndSerialNumber {
        issuer,
        serial_number,
    } = signer.identifier()
    else {
        panic!("issuer and serial number expected")
    };
    assert_eq!(issuer, "CN=rades test intermediate CA,O=rades test");
    assert_eq!(
        serial_number,
        &hex("779922863F04F8E99E441CD1EA6F2A549D7C7C43")
    );
    assert_eq!(signer.digest_algorithm().oid(), oid(SHA256));
    assert_eq!(signer.digest_algorithm().parameters(), None);
    assert_eq!(signer.signature_algorithm().oid(), oid(SHA256_WITH_RSA));
    assert_eq!(signer.signature_algorithm().parameters(), Some(&[5, 0][..]));
    assert_eq!(signer.signature_value().len(), 384);
}

#[test]
fn a_golden_vector_decodes_its_signed_attributes() {
    let decoded = cades::decode(&common::read("cades/bb-detached-rsa-sha256.p7m")).unwrap();
    let signer = &decoded.signers()[0];
    let mut oids: Vec<String> = signer
        .signed_attributes()
        .iter()
        .map(|a| a.oid().to_string())
        .collect();
    oids.sort();
    assert_eq!(
        oids,
        [
            "1.2.840.113549.1.9.16.2.47",
            "1.2.840.113549.1.9.3",
            "1.2.840.113549.1.9.4",
            "1.2.840.113549.1.9.5",
            "1.2.840.113549.1.9.52",
        ]
    );
    assert_eq!(signer.unsigned_attributes(), []);
    let content_type = signer
        .signed_attribute(oid("1.2.840.113549.1.9.3"))
        .unwrap();
    assert_eq!(
        content_type.values(),
        [b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01".to_vec()]
    );
    assert_eq!(
        signer.message_digest(),
        Some(&hex("fcb11de2458619597c8877ab498856f1d9172f43cacb84084ec52e3ee0c446e8")[..])
    );
    assert_eq!(
        signer.signing_time(),
        Some(SigningTime::from_unix_seconds(1_792_584_000).unwrap())
    );
}

fn certificate_der(signer: &str) -> Vec<u8> {
    let pem = std::fs::read_to_string(common::path(&format!("pki/{signer}.crt"))).unwrap();
    der::pem::decode_vec(pem.as_bytes()).unwrap().1
}

#[test]
fn signing_certificate_v2_is_read() {
    let decoded = cades::decode(&common::read("cades/bb-detached-rsa-sha384.p7m")).unwrap();
    let Some(SigningCertificate::V2(certs)) = decoded.signers()[0].signing_certificate() else {
        panic!("signing-certificate-v2 expected")
    };
    let [cert] = certs.as_slice() else {
        panic!("one certificate expected")
    };
    assert_eq!(cert.hash_algorithm().oid(), oid("2.16.840.1.101.3.4.2.2"));
    assert_eq!(
        cert.hash(),
        Sha384::digest(certificate_der("signer-rsa")).as_slice()
    );
    let issuer_serial = cert.issuer_serial().unwrap();
    assert_eq!(
        issuer_serial.issuer(),
        "CN=rades test intermediate CA,O=rades test"
    );
    assert_eq!(
        issuer_serial.serial_number(),
        hex("779922863F04F8E99E441CD1EA6F2A549D7C7C43")
    );
}

#[test]
fn signing_certificate_v2_defaults_to_sha256() {
    let decoded = cades::decode(&common::read("cades/bb-detached-rsa-sha256.p7m")).unwrap();
    let Some(SigningCertificate::V2(certs)) = decoded.signers()[0].signing_certificate() else {
        panic!("signing-certificate-v2 expected")
    };
    assert_eq!(certs[0].hash_algorithm().oid(), oid(SHA256));
    assert_eq!(
        certs[0].hash(),
        Sha256::digest(certificate_der("signer-rsa")).as_slice()
    );
}

/// The golden vector with `id-aa-signingCertificateV2` renamed `id-aa-signingCertificate`: both
/// OIDs encode in as many bytes and `ESSCertIDv2` without its default algorithm is an `ESSCertID`.
fn with_signing_certificate_v1(signature: &[u8]) -> Vec<u8> {
    let v2 = b"\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x02\x2f";
    let at = signature.windows(v2.len()).position(|w| w == v2).unwrap();
    let mut patched = signature.to_vec();
    patched[at + v2.len() - 1] = 0x0c;
    patched
}

#[test]
fn signing_certificate_v1_is_read() {
    let signature = with_signing_certificate_v1(&common::read("cades/bb-detached-rsa-sha256.p7m"));
    let decoded = cades::decode(&signature).unwrap();
    let Some(SigningCertificate::V1(certs)) = decoded.signers()[0].signing_certificate() else {
        panic!("signing-certificate expected")
    };
    assert_eq!(certs[0].hash_algorithm().oid(), oid("1.3.14.3.2.26"));
    assert_eq!(
        certs[0].hash(),
        Sha256::digest(certificate_der("signer-rsa")).as_slice()
    );
    assert!(certs[0].issuer_serial().is_some());
}

/// Re-encodes `der` with every TLV equal to `from` replaced by `to`.
fn replace_tlv(der: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    replace_tlv_after(der, &mut true, &[], from, to)
}

/// As [`replace_tlv`], only after a primitive TLV equal to `marker`, in encoding order.
fn replace_tlv_after(
    der: &[u8],
    armed: &mut bool,
    marker: &[u8],
    from: &[u8],
    to: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = der;
    while !rest.is_empty() {
        let tag = rest[0];
        let (len, header) = match rest[1] {
            short if short < 0x80 => (usize::from(short), 2),
            long => {
                let n = usize::from(long & 0x7f);
                let len = rest[2..2 + n]
                    .iter()
                    .fold(0, |acc, b| acc << 8 | usize::from(*b));
                (len, 2 + n)
            }
        };
        let (tlv, tail) = rest.split_at(header + len);
        if *armed && tlv == from {
            out.extend_from_slice(to);
        } else if tag & 0x20 == 0 {
            out.extend_from_slice(tlv);
            *armed |= tlv == marker;
        } else {
            let value = replace_tlv_after(&tlv[header..], armed, marker, from, to);
            out.push(tag);
            out.extend(encode_len(value.len()));
            out.extend(value);
        }
        rest = tail;
    }
    out
}

fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![u8::try_from(len).unwrap()];
    }
    let bytes: Vec<u8> = len
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    let mut out = vec![0x80 | u8::try_from(bytes.len()).unwrap()];
    out.extend(bytes);
    out
}

const SHA256_TLV: &[u8] = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01";
const MD5_TLV: &[u8] = b"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05";

#[test]
fn md5_as_the_digest_algorithm_is_rejected() {
    let signature = common::read("cades/bb-detached-rsa-sha256.p7m");
    let md5 = replace_tlv(&signature, SHA256_TLV, MD5_TLV);
    assert_ne!(md5, signature);
    assert_eq!(
        cades::decode(&md5).unwrap_err().to_string(),
        "rejected digest algorithm MD5"
    );
}

#[test]
fn md5_with_rsa_as_the_signature_algorithm_is_rejected() {
    let signature = common::read("cades/bb-detached-rsa-sha256.p7m");
    let sha256_with_rsa = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b";
    let md5_with_rsa = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04";
    let md5 = replace_tlv(&signature, sha256_with_rsa, md5_with_rsa);
    assert_ne!(md5, signature);
    assert_eq!(
        cades::decode(&md5).unwrap_err().to_string(),
        "rejected digest algorithm MD5"
    );
}

#[test]
fn md5_in_a_countersignature_is_rejected() {
    let signature = common::read("autofirma/countersign-ecdsa-by-rsa.p7s");
    let countersignature = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x06";
    let md5 = replace_tlv_after(
        &signature,
        &mut false,
        countersignature,
        SHA256_TLV,
        MD5_TLV,
    );
    assert_ne!(md5, signature);
    cades::decode(&replace_tlv(&md5, MD5_TLV, SHA256_TLV)).unwrap();
    assert_eq!(
        cades::decode(&md5).unwrap_err().to_string(),
        "rejected digest algorithm MD5"
    );
}

#[test]
fn a_subject_key_identifier_finds_the_signer_certificate() {
    let certificate = x509_cert::Certificate::from_der(&certificate_der("signer-rsa")).unwrap();
    let tbs = certificate.tbs_certificate();
    let mut issuer_and_serial = tbs.issuer().to_der().unwrap();
    issuer_and_serial.extend(tbs.serial_number().to_der().unwrap());
    let mut from = vec![0x30];
    from.extend(encode_len(issuer_and_serial.len()));
    from.extend(issuer_and_serial);
    let ski = hex("74BDF4051A3D5E9CC2C189B4691F992251F785BD");
    let mut to = vec![0x80, 20];
    to.extend(&ski);
    let signature = replace_tlv(
        &common::read("cades/bb-detached-rsa-sha256.p7m"),
        &from,
        &to,
    );
    let decoded = cades::decode(&signature).unwrap();
    let signer = &decoded.signers()[0];
    assert_eq!(
        signer.identifier(),
        &SignerIdentifier::SubjectKeyIdentifier(ski)
    );
    assert_eq!(
        signer.certificate(),
        Some(&common::certificate("signer-rsa"))
    );
}

#[test]
fn malformed_der_is_an_error_not_a_panic() {
    let signature = common::read("cades/bb-attached-rsa-sha256.p7m");
    for len in 0..signature.len() {
        assert!(
            cades::decode(&signature[..len]).is_err(),
            "truncated to {len} bytes"
        );
    }
    for at in 0..signature.len() {
        for flip in [0x01, 0x80, 0xff] {
            let mut corrupted = signature.clone();
            corrupted[at] ^= flip;
            let _ = cades::decode(&corrupted);
        }
    }
    assert!(
        cades::decode(b"\x30\x03\x02\x01")
            .unwrap_err()
            .to_string()
            .starts_with("malformed signature: ")
    );
}

#[test]
fn a_content_info_other_than_signed_data_is_rejected() {
    let data = b"\x30\x0f\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01\xa0\x02\x04\x00";
    assert_eq!(
        cades::decode(data).unwrap_err().to_string(),
        "malformed signature: content type 1.2.840.113549.1.7.1 is not signed data"
    );
}
