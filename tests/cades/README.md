# CAdES golden vectors

Signatures the integration tests produce with rades from fixed inputs and compare byte for byte; `RADES_BLESS=1 cargo test` rewrites them. Each `-tampered` copy has one signed-attribute byte changed.

`manifest.tsv` lists the verdict each signature expects from the oracles (`oracles/README.md`).
