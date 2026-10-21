# AutoFirma fixtures

CAdES signatures made by AutoFirma 1.8.2 with the test PKI (`../pki`) over `../pki/content.txt`, committed because AutoFirma's output is not reproducible: attached and detached content, RSA and ECDSA, a co-signature and a countersignature. `attached-*-age.p7s` are made with `expPolicy=FirmaAGE`, expanded through AutoFirma's `ExtraParamsProcessor` as the application does.

`cosign-ecdsa-rsa.p7s` is the ECDSA signature co-signed by the RSA signer; `countersign-ecdsa-by-rsa.p7s` is the ECDSA signature countersigned by the RSA signer. AutoFirma's own `verify` rejects the same pair the other way round (RSA first, ECDSA second: its RSA verifier is applied to the ECDSA key), so that order is not here.

`oracles/autofirma/Generate.java` regenerates them (each run changes every file; commit only the ones that need it): `jbang oracles/autofirma/Generate.java tests/pki tests/autofirma`. It fails if AutoFirma does not verify its own output.

`manifest.tsv` lists the attached signatures, the only ones the oracles check today. DSS can validate detached CAdES (`SignedDocumentValidator.setDetachedContents`), but neither `Dss.java` nor the manifest has a way to pass the detached content yet; DSS also sees two signatures in the co-signed and countersigned files, which the manifest does not model yet.
