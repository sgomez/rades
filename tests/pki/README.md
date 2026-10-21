# Test PKI

Fictitious PKI every rades test and oracle signs with: root CA, intermediate CA, and signers RSA 3072 and ECDSA P-256, P-384 and P-521, plus a brainpoolP256r1 signer for the unsupported-curve test (certificates, keys and PKCS#12 with password `rades`), valid until 2126. No TSA, OCSP or CRL.

`cades-bb.p7m` is a CAdES B-B made with `openssl cms` (attached content in `content.txt`); `cades-bb-tampered.p7m` has one content byte changed.

`./generate.sh` creates only what is missing and keeps every existing key and certificate, so a new signer or TSA lands under the committed root and intermediate; it fails if a signer chain or the fixture does not verify. `./generate.sh --fresh` regenerates everything from scratch, which invalidates `../autofirma`: regenerate it then with `oracles/autofirma/Generate.java` (`../autofirma/README.md`).

`manifest.tsv` lists the verdict each signature here expects from the oracles (`oracles/README.md`).
