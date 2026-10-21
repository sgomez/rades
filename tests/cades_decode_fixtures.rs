//! Every committed signature decodes: rades' golden vectors and AutoFirma's fixtures.

mod common;

use der::Decode;
use rades::cades::{self, Signer, SignerIdentifier, SigningCertificate};
use rades::{ObjectIdentifier, SigningTime};
use sha2::Digest;

/// 2026-10-21T12:00:00Z, the signing time of every golden vector.
const GOLDEN_SIGNING_TIME: u64 = 1_792_584_000;
/// 2026-10-21T11:50:37Z, when AutoFirma made its fixtures.
const AUTOFIRMA_SIGNING_TIME: u64 = 1_792_583_437;

fn oid(text: &str) -> ObjectIdentifier {
    ObjectIdentifier::new_unwrap(text)
}

fn digest(algorithm: ObjectIdentifier, data: &[u8]) -> Vec<u8> {
    match algorithm.to_string().as_str() {
        "2.16.840.1.101.3.4.2.1" => sha2::Sha256::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.2" => sha2::Sha384::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.3" => sha2::Sha512::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.8" => sha3::Sha3_256::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.9" => sha3::Sha3_384::digest(data).to_vec(),
        "2.16.840.1.101.3.4.2.10" => sha3::Sha3_512::digest(data).to_vec(),
        other => panic!("digest algorithm {other} missing from this test"),
    }
}

fn certificate_der(signer: &str) -> Vec<u8> {
    let pem = std::fs::read_to_string(common::path(&format!("pki/{signer}.crt"))).unwrap();
    der::pem::decode_vec(pem.as_bytes()).unwrap().1
}

/// The test PKI signer the signer identifies.
fn signer_named(signer: &Signer) -> String {
    let SignerIdentifier::IssuerAndSerialNumber { serial_number, .. } = signer.identifier() else {
        panic!("issuer and serial number expected")
    };
    std::fs::read_dir(common::path("pki"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter_map(|file| Some(file.strip_suffix(".crt")?.to_owned()))
        .filter(|name| name.starts_with("signer-"))
        .find(|name| {
            let certificate = x509_cert::Certificate::from_der(&certificate_der(name)).unwrap();
            certificate.tbs_certificate().serial_number().as_bytes() == serial_number.as_slice()
        })
        .unwrap()
}

/// The signer decodes to the inputs every signature carries.
fn assert_signer(signer: &Signer, name: &str, content: &[u8], signing_time: u64) {
    assert_eq!(signer_named(signer), name);
    if let Some(certificate) = signer.certificate() {
        assert_eq!(certificate, &common::certificate(name));
    }
    let digest_algorithm = signer.digest_algorithm().oid();
    assert_eq!(
        signer.message_digest(),
        Some(digest(digest_algorithm, content).as_slice())
    );
    assert_eq!(
        signer.signing_time(),
        Some(SigningTime::from_unix_seconds(signing_time).unwrap())
    );
}

fn assert_signing_certificate_v2(signer: &Signer, name: &str) {
    let Some(SigningCertificate::V2(certs)) = signer.signing_certificate() else {
        panic!("signing-certificate-v2 expected")
    };
    assert_eq!(
        certs[0].hash(),
        digest(certs[0].hash_algorithm().oid(), &certificate_der(name))
    );
}

#[test]
fn every_golden_vector_decodes_to_its_inputs() {
    let manifest = String::from_utf8(common::read("cades/manifest.tsv")).unwrap();
    let content = common::read("cades/content.txt");
    for row in manifest.lines().filter(|l| !l.starts_with('#')) {
        let columns: Vec<&str> = row.split('\t').collect();
        let decoded = cades::decode(&common::read(&format!("cades/{}", columns[0])))
            .unwrap_or_else(|e| panic!("{}: {e}", columns[0]));
        let [signer] = decoded.signers() else {
            panic!("{}: one signer expected", columns[0])
        };
        if columns[0].contains("-tampered") {
            continue;
        }
        let attached = columns.get(3).is_none();
        assert_eq!(decoded.content(), attached.then_some(content.as_slice()));
        let name = signer_named(signer);
        assert_signer(signer, &name, &content, GOLDEN_SIGNING_TIME);
        if columns[2].starts_with("CAdES") {
            assert_signing_certificate_v2(signer, &name);
        } else {
            assert_eq!(signer.signing_certificate(), None, "{}", columns[0]);
        }
        assert_eq!(signer.unsigned_attributes(), []);
    }
}

const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

/// AutoFirma's signer: SHA-256, its own attribute order, its content hint, everything embedded.
fn assert_autofirma_signer(signer: &Signer, name: &str, signature_algorithm: &str) {
    assert_signer(
        signer,
        name,
        &common::read("pki/content.txt"),
        AUTOFIRMA_SIGNING_TIME,
    );
    assert_signing_certificate_v2(signer, name);
    assert_eq!(
        signer.certificate(),
        Some(&common::certificate(name)),
        "embedded"
    );
    assert_eq!(
        signer.digest_algorithm().oid(),
        oid("2.16.840.1.101.3.4.2.1")
    );
    assert_eq!(signer.signature_algorithm().oid(), oid(signature_algorithm));
    let oids: Vec<String> = signer
        .signed_attributes()
        .iter()
        .map(|a| a.oid().to_string())
        .collect();
    assert_eq!(
        oids,
        [
            "1.2.840.113549.1.9.3",
            "1.2.840.113549.1.9.5",
            "1.2.840.113549.1.9.16.2.4",
            "1.2.840.113549.1.9.4",
            "1.2.840.113549.1.9.16.2.47",
        ]
    );
}

fn decode_autofirma(file: &str) -> cades::DecodedSignature {
    cades::decode(&common::read(&format!("autofirma/{file}"))).unwrap()
}

#[test]
fn autofirma_attached_and_detached_signatures_decode() {
    for (file, name, algorithm, attached) in [
        ("attached-rsa.p7s", "signer-rsa", RSA_ENCRYPTION, true),
        (
            "attached-ecdsa.p7s",
            "signer-ecdsa",
            ECDSA_WITH_SHA256,
            true,
        ),
        ("detached-rsa.p7s", "signer-rsa", RSA_ENCRYPTION, false),
        (
            "detached-ecdsa.p7s",
            "signer-ecdsa",
            ECDSA_WITH_SHA256,
            false,
        ),
    ] {
        let decoded = decode_autofirma(file);
        let content = common::read("pki/content.txt");
        assert_eq!(decoded.content(), attached.then_some(content.as_slice()));
        let [signer] = decoded.signers() else {
            panic!("{file}: one signer expected")
        };
        assert_autofirma_signer(signer, name, algorithm);
        assert_eq!(signer.unsigned_attributes(), []);
    }
}

#[test]
fn an_autofirma_co_signature_decodes_to_both_signers_in_order() {
    let decoded = decode_autofirma("cosign-ecdsa-rsa.p7s");
    let [first, second] = decoded.signers() else {
        panic!("two signers expected")
    };
    assert_autofirma_signer(first, "signer-ecdsa", ECDSA_WITH_SHA256);
    assert_autofirma_signer(second, "signer-rsa", RSA_ENCRYPTION);
}

#[test]
fn an_autofirma_countersignature_stays_an_unsigned_attribute() {
    let decoded = decode_autofirma("countersign-ecdsa-by-rsa.p7s");
    let [signer] = decoded.signers() else {
        panic!("one signer expected")
    };
    assert_autofirma_signer(signer, "signer-ecdsa", ECDSA_WITH_SHA256);
    let [countersignature] = signer.unsigned_attributes() else {
        panic!("one unsigned attribute expected")
    };
    assert_eq!(countersignature.oid(), oid("1.2.840.113549.1.9.6"));
    assert_eq!(countersignature.values().len(), 1);
}
