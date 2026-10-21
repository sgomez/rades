# Oracles

Java programs, run with JBang outside the crate, that judge rades' signatures with other implementations. `just oracles` runs them all; the `oracles` CI job runs it on Linux on every PR.

The seam is a directory of signatures with a `manifest.tsv`: one line per signature, `file indication level [content]`, the verdict as DSS's simple report names it (`TOTAL_PASSED CAdES-BASELINE-B`) and, for a detached signature, the file it signs, relative to the manifest (`digest:SHA-256:<file>` makes DSS validate through a `DigestDocument` of that file's digest; AutoFirma reads the file). Each oracle checks every entry of every directory in one JVM run and fails naming each signature whose verdict differs. A new directory is one more argument in the `oracles` recipe.

## DSS

`dss/Dss.java` validates with DSS 6.5.1, offline: it trusts only `tests/pki/root.crt`, with no LOTL, AIA, OCSP or CRL, and is handed `tests/pki/intermediate.crt` to build the chain of signatures that embed only the signer certificate. `dss/policy.xml` is DSS's default policy with missing revocation data lowered from FAIL to WARN, so B-B and B-T pass until M14 brings OCSP and CRL.

## AutoFirma

`autofirma/AutoFirma.java` verifies with AutoFirma 1.8.2 (`es.gob.afirma:afirma-crypto-*`, on Maven Central). Its `verify` checks the signature's cryptography and the certificate's validity dates, not the chain, so DSS stays the validity oracle. It reads the same manifests: `TOTAL_PASSED` expects `OK`, `TOTAL_FAILED` expects `KO`, and the level column is DSS's. Any other indication is skipped.

`autofirma/Generate.java` makes the fixtures in `tests/autofirma`.

## ETSI Signatures Conformance Checker

A manual step, since the checker is web upload only, with no API: closing a format includes running its signatures through it. It checks structure and the signature value against the standard, not the chain or validity dates, so DSS stays the validity oracle.

1. Log in at <https://signatures-conformance-checker.etsi.org/pub/index.php> (free registration).
2. Pick the format's checker and its baseline profile: for CAdES, ETSI EN 319 122-1 v1.1.1.
3. Upload the signature. The CAdES checker takes only `.p7m` files. Upload only signatures made with `tests/pki`.
4. Download the report zip. `CAdES-signature-1/docs/errorsandwarnings.html` lists errors and warnings; `fullreport.html` states whether the validation succeeded.

A signature passes with no errors. The CAdES checker warns on the `smimeCapabilities` attribute (OID 1.2.840.113549.1.9.15) that `openssl cms` adds: it does not know it and skips it.
