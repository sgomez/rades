# rades

[![crates.io](https://img.shields.io/crates/v/rades.svg)](https://crates.io/crates/rades)
[![docs.rs](https://img.shields.io/docsrs/rades)](https://docs.rs/rades)
[![CI](https://github.com/sgomez/rades/actions/workflows/ci.yml/badge.svg)](https://github.com/sgomez/rades/actions/workflows/ci.yml)
[![License: EUPL-1.2](https://img.shields.io/crates/l/rades.svg)](https://github.com/sgomez/rades/blob/main/LICENSE)

AdES signature formats in pure Rust, written from the ETSI standards: CAdES, PAdES, XAdES, JAdES and ASiC, from B-B to B-LTA. The signing key never enters the crate: it hands out the data to sign and takes back the signature value, so any token, smart card or remote service can sign. It behaves the same on every platform Rust targets.

Its first consumer is [rFirma](https://github.com/sgomez/rfirma).

## Conformance

| Format | B-B | B-T | B-LT | B-LTA |
| --- | --- | --- | --- | --- |
| CAdES | ✅ [conformant](https://github.com/sgomez/rades/blob/main/docs/cades-bb-matrix.md) | — | — | — |
| PAdES | — | — | — | — |
| XAdES | — | — | — | — |
| JAdES | — | — | — | — |
| ASiC | — | — | — | — |

Each cell links to its requirements matrix, which names what is covered and the milestone of the rest.

| Mark | Meaning |
| --- | --- |
| — | Not started |
| 🟡 | In progress: a *shall* row is missing |
| ✅ | Conformant, as [the roadmap](https://github.com/sgomez/rades/blob/main/docs/roadmap.md#done-means) defines it: every *shall* row covered, DSS and the ETSI conformance checker validate it |
| ⭐ | Complete: every *should* and *may* row is covered too, or left out on purpose |

The signature and digest algorithms are those of [`SignatureAlgorithm`](https://docs.rs/rades/latest/rades/enum.SignatureAlgorithm.html) and [`DigestAlgorithm`](https://docs.rs/rades/latest/rades/enum.DigestAlgorithm.html). [`cades::decode`](https://docs.rs/rades/latest/rades/cades/fn.decode.html) reads the signers and attributes of a CAdES signature, without validating it.

## Usage

```toml
[dependencies]
rades = "0.1"
```

```rust
use rades::cades::{self, Content, Options};
use rades::{
    Certificate, DigestAlgorithm, SignatureAlgorithm, SignaturePolicy, SignatureValue,
    SigningTime,
};

fn sign_document(document: &[u8], certificate_pem: &str, now: u64) -> Result<Vec<u8>, rades::Error> {
    let certificate = Certificate::from_pem(certificate_pem)?;
    let options = Options::default().signature_policy(SignaturePolicy::age_v1_9());
    let pending = cades::sign(
        Content::Detached(document),
        &certificate,
        SignatureAlgorithm::RsaPkcs1v15(DigestAlgorithm::Sha256),
        SigningTime::from_unix_seconds(now)?,
        &options,
    )?;
    let values: Vec<SignatureValue> = pending
        .data_to_sign()
        .iter()
        .map(|data| SignatureValue::new(sign_with_the_key(data.bytes())))
        .collect();
    pending.complete(&values)
}
```

`DataToSign` also gives its `digest` and `digest_info`, for keys that sign a precomputed hash. The signing time is a value, so the same inputs give the same signature.

## Platforms

Pure Rust, with no system libraries: the CI runs the tests on Linux, macOS and Windows.

The minimum supported Rust version is 1.85.

## Security

Report vulnerabilities privately, as [`SECURITY.md`](https://github.com/sgomez/rades/blob/main/SECURITY.md) explains.

## Contributing

See [`CONTRIBUTING.md`](https://github.com/sgomez/rades/blob/main/CONTRIBUTING.md).

## License

Copyleft: free software under the [EUPL-1.2](https://github.com/sgomez/rades/blob/main/LICENSE).
