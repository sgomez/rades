# Own formats from the ETSI standards, easiest first, with DSS as the oracle

rFirma signs through a GraalVM build of AutoFirma's Java code, which ties it to the platforms GraalVM ships for. rades replaces it with pure Rust, written from the ETSI standards rather than ported: AutoFirma is mostly glue over BouncyCastle, a patched iText and Apache Santuario, so a port would mean porting those too. We write every format layer ourselves and take only the primitives (hashes, RSA/ECDSA, DER, X.509) from RustCrypto.

## Considered Options

Building on the existing Rust AdES crates (`underskrift`, `bergshamra`, `tsp-ltv`) would have been faster. They are rejected because they are 0.x with a single maintainer, and they lack what rFirma needs: signature policies (EPES), custom signed attributes and generic CAdES outside PDF.

## Consequences

- Formats land from easiest to hardest, so the hard pieces (PDF parsing, C14N, revocation) come after the easy ones have shaped the API: CAdES B-B, JAdES, ASiC-S, the RFC 3161 client for B-T, PAdES, XAdES, then B-LT, B-LTA and validation.
- DSS validates every format in the CI. It is Java, but only in the tests, never in the crate.
- DSS proves that what we generate is valid, not that a format is complete. Completeness is a matrix of the ETSI baseline requirements (EN 319 122, 132, 142, 162; TS 119 182-1) and their test specifications, each row pointing at its test.
- A third-party crate in the format layers needs a new ADR that supersedes this one.
