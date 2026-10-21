# rades

AdES signature formats in pure Rust, written from the ETSI standards: CAdES, PAdES, XAdES, JAdES and ASiC, from B-B to B-LTA. The signing key never enters the crate: it hands out the data to sign and takes back the signature value, so any token, smart card or remote service can sign.

Its first consumer is [rFirma](https://github.com/sgomez/rfirma).

**Status:** early development, no format yet. Not on crates.io.

## License

[EUPL-1.2](LICENSE)
