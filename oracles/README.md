# Oracles

Java programs, run with JBang outside the crate, that judge rades' signatures with other implementations. `just oracles` runs them all; the `oracles` CI job runs it on Linux on every PR.

The seam is a directory of signatures with a `manifest.tsv`: one line per signature, `file indication level`, as DSS's simple report names them (`TOTAL_PASSED CAdES-BASELINE-B`). Each oracle checks every entry of every directory in one JVM run and fails naming each signature whose verdict differs. A new directory is one more argument in the `oracles` recipe.

## DSS

`dss/Dss.java` validates with DSS 6.5.1, offline: it trusts only `tests/pki/root.crt`, with no LOTL, AIA, OCSP or CRL. `dss/policy.xml` is DSS's default policy with missing revocation data lowered from FAIL to WARN, so B-B and B-T pass until M14 brings OCSP and CRL.

## AutoFirma

`autofirma/AutoFirma.java` verifies with AutoFirma 1.8.2 (`es.gob.afirma:afirma-crypto-*`, on Maven Central). Its `verify` checks the signature's cryptography and the certificate's validity dates, not the chain, so DSS stays the validity oracle. It reads the same manifests: `TOTAL_PASSED` expects `OK`, `TOTAL_FAILED` expects `KO`, and the level column is DSS's. Any other indication is skipped.

`autofirma/Generate.java` makes the fixtures in `tests/autofirma`.
