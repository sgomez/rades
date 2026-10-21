//! Requirements of the CAdES B-B matrix (`docs/cades-bb-matrix.md`) that no other test names.

mod common;

use rades::cades::{self, Certificates, Content, Options};
use rades::{DigestAlgorithm, SignatureAlgorithm, SigningTime};

const RSA_SHA256: SignatureAlgorithm = SignatureAlgorithm::RsaPkcs1v15(DigestAlgorithm::Sha256);
const SIGNING_TIME: u64 = 1_792_584_000;
const MD5: &[u8] = b"\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05";
const SHA256: &[u8] = b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01";
const ID_DATA: &[u8] = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01";

/// Splits a DER value into its tag and content, and the bytes after it.
fn tlv(der: &[u8]) -> (u8, &[u8], &[u8]) {
    let (tag, first) = (der[0], der[1]);
    let (len, start) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        (
            der[2..2 + n]
                .iter()
                .fold(0, |len, b| (len << 8) | usize::from(*b)),
            2 + n,
        )
    };
    (tag, &der[start..start + len], &der[start + len..])
}

fn children(mut der: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while !der.is_empty() {
        let (tag, content, rest) = tlv(der);
        out.push((tag, content));
        der = rest;
    }
    out
}

/// The children of the `SignedData` inside a `ContentInfo`.
fn signed_data(signature: &[u8]) -> Vec<(u8, &[u8])> {
    let (_, content_info, _) = tlv(signature);
    let (_, explicit, _) = tlv(children(content_info)[1].1);
    children(explicit)
}

fn sign(content: Content<'_>, options: &Options) -> Vec<u8> {
    let pending = cades::sign(
        content,
        &common::certificate("signer-rsa"),
        RSA_SHA256,
        SigningTime::from_unix_seconds(SIGNING_TIME).unwrap(),
        options,
    )
    .unwrap();
    let value = common::sign_rsa_pkcs1("signer-rsa", &pending.data_to_sign()[0]);
    pending.complete(&[value]).unwrap()
}

#[test]
fn the_signed_data_version_is_1_for_id_data_with_issuer_and_serial_identifiers() {
    let content = common::read("cades/content.txt");
    let signature = sign(Content::Detached(&content), &Options::default());
    let parts = signed_data(&signature);
    assert_eq!(parts[0], (0x02, &[1][..]));
    let signer_info = children(parts.last().unwrap().1)[0].1;
    assert_eq!(children(signer_info)[0], (0x02, &[1][..]));
}

#[test]
fn the_digest_algorithms_list_the_signers_digest() {
    let content = common::read("cades/content.txt");
    let signature = sign(Content::Detached(&content), &Options::default());
    let digests = children(signed_data(&signature)[1].1);
    assert_eq!(digests.len(), 1);
    assert_eq!(children(digests[0].1)[0].1, &SHA256[2..]);
}

#[test]
fn the_encapsulated_content_is_id_data_and_carries_the_content_only_when_attached() {
    let content = common::read("cades/content.txt");
    let detached = sign(Content::Detached(&content), &Options::default());
    let encapsulated = signed_data(&detached)[2].1;
    assert_eq!(encapsulated, ID_DATA);
    let attached = sign(Content::Attached(&content), &Options::default());
    let encapsulated = children(signed_data(&attached)[2].1);
    assert_eq!(encapsulated[0].1, &ID_DATA[2..]);
    let (tag, explicit) = encapsulated[1];
    assert_eq!(tag, 0xa0);
    assert_eq!(tlv(explicit).1, content);
}

#[test]
fn a_signature_has_exactly_one_signer_info() {
    let content = common::read("cades/content.txt");
    let signature = sign(Content::Detached(&content), &Options::default());
    assert_eq!(children(signed_data(&signature).last().unwrap().1).len(), 1);
}

#[test]
fn no_golden_vector_uses_md5() {
    let manifest = String::from_utf8(common::read("cades/manifest.tsv")).unwrap();
    for file in manifest
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split('\t').next().unwrap())
    {
        let signature = common::read(&format!("cades/{file}"));
        assert!(!signature.windows(MD5.len()).any(|w| w == MD5), "{file}");
    }
}

#[test]
fn the_signing_time_is_a_utc_time_up_to_2049_and_a_generalized_time_from_2050() {
    let content = common::read("cades/content.txt");
    for (seconds, tag) in [(2_524_607_999, 0x17), (2_524_608_000, 0x18)] {
        let pending = cades::sign(
            Content::Detached(&content),
            &common::certificate("signer-rsa"),
            RSA_SHA256,
            SigningTime::from_unix_seconds(seconds).unwrap(),
            &Options::default(),
        )
        .unwrap();
        let attributes = pending.data_to_sign()[0].bytes();
        let signing_time = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x05\x31";
        let at = attributes
            .windows(signing_time.len())
            .position(|w| w == signing_time)
            .unwrap();
        assert_eq!(attributes[at + signing_time.len() + 1], tag, "{seconds}");
    }
}

#[test]
fn a_certificate_given_twice_is_embedded_once() {
    let content = common::read("cades/content.txt");
    let options = Options::default().certificates(Certificates::Chain(vec![
        common::certificate("signer-rsa"),
        common::certificate("intermediate"),
        common::certificate("intermediate"),
        common::certificate("root"),
    ]));
    let signature = sign(Content::Detached(&content), &options);
    let embedded = children(
        signed_data(&signature)
            .iter()
            .find(|(tag, _)| *tag == 0xa0)
            .unwrap()
            .1,
    );
    assert_eq!(embedded.len(), 3);
}
