# Test PKI

Fictitious PKI every rades test and oracle signs with: root CA, intermediate CA, and signers RSA 3072 and ECDSA P-256 (certificates, keys and PKCS#12 with password `rades`), valid until 2126. No TSA, OCSP or CRL.

`cades-bb.p7m` is a CAdES B-B made with `openssl cms` (attached content in `content.txt`); `cades-bb-tampered.p7m` has one content byte changed.

`./generate.sh` regenerates everything and fails if a signer chain does not verify up to the root.

`manifest.tsv` lists the verdict each signature here expects from the oracles (`oracles/README.md`).
