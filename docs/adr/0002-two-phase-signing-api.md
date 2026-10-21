# Two-phase signing: data to sign out, signature values in

The signing key never enters the crate, so every format signs in two phases. Phase 1 takes the content, the signer certificate, an explicit signature algorithm, the signing time and typed options, and returns a `PendingSignature` holding a list of data to sign. Phase 2 consumes it with one signature value per item and returns a B-B signature. Higher levels are augmentation of a finished signature, not more phases.

- **Data to sign is the DTBS, not its digest.** EdDSA and pure ML-DSA sign the message, not a hash. It carries the signature algorithm and offers digest and `DigestInfo` views for keys that sign hashes.
- **The caller names the signature algorithm in phase 1**, because it ends up in signed content (XAdES `SignatureMethod`, JAdES `alg`, CAdES `cms-algorithm-protection`). rades rejects one that does not fit the certificate's key or is forbidden, and has no default.
- **Time is a value, randomness a `&mut impl CryptoRng`** on each call that needs it. The library has no clock and no OS randomness, so a signature is reproducible (B-36).
- **`PendingSignature` lives in memory and is not serializable.** `complete` consumes it, so a signature value cannot be applied twice.
- **One operation can need several signature values**, e.g. countersigning several signatures. They match the data to sign by position, and the count is checked.
- **Options are typed per format**, built from shared value types named after the ETSI attributes (policy, commitment type, signer location, signer role). Co-signing and countersigning are operations on an existing signature. A countersignature takes explicit targets from the signer tree the existing signature exposes.
- **Augmentation is sans-IO.** rades builds the time-stamp request and checks the response; the caller moves the bytes.
- **No trait shared by every format yet.** Formats share the types above; a trait is extracted once CAdES and JAdES show what they really have in common.

## Considered Options

- **A digest as the data to sign.** Rejected: it locks out EdDSA and pure ML-DSA.
- **AutoFirma's string `extraParams`.** Rejected: untyped, and it would carry AutoFirma's key names into a format library.
- **A serializable state token, like AutoFirma's `TriphaseData`**, to finish in another process. Rejected until someone needs it. A stateless phase 2 that recomputes phase 1 from the same inputs stays possible without changing this API, since the output is reproducible.
- **AutoFirma's countersignature targets** (`tree`, `leafs`, `nodes`, `signers`). Rejected: they are selection policies, not ETSI concepts, and are a few lines over the signer tree.
- **A time-stamp call between the phases, or a TSP client that does network I/O.** Rejected: the time stamp covers the signature value, so it comes after phase 2. A network client would also pick an HTTP stack and an async runtime for every user.
