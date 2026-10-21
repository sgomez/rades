# CAdES golden vectors

Signatures the integration tests produce with rades from fixed inputs and compare byte for byte; `RADES_BLESS=1 cargo test` rewrites them. Each `-tampered` copy has one signed-attribute byte changed.

`manifest.tsv` lists the verdict each signature expects from the oracles (`oracles/README.md`).

`-nocert` embeds no certificate: DSS finds no signing certificate in the test PKI's trusted source and reports `INDETERMINATE` `CAdES-BES`.

`cms-*` is AutoFirma's bare CMS (no ETSI attributes): DSS reports `CMS-NOT-ETSI`.
