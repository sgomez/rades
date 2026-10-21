# Agent instructions: rades

## Goal

Pure Rust library for the AdES signature formats of the ETSI standards (CAdES, PAdES, XAdES, JAdES and ASiC, B-B to B-LTA), the same on every platform Rust targets. Its first consumer is [rFirma](https://github.com/sgomez/rfirma), which replaces its Java bridge with it one format at a time.

## Design constraints

The decisions live in `docs/adr/`. The ones to know before touching anything:

1. **Formats are ours, primitives are not (ADR-0001).** Hashes, RSA/ECDSA, DER and X.509 come from RustCrypto; every format, container, PDF and XML layer, C14N and TSP/OCSP/CRL client is written here. No third-party AdES, PDF or XML-security crate.
2. **Written from the ETSI standards, not ported (ADR-0001).** AutoFirma and DSS are oracles in the tests, never sources to translate.
3. **The signing key never enters the crate.** Each format signs in two phases: data to sign out, signature value in. Time and randomness are injected, so a signature is reproducible.
4. **Easiest first (ADR-0001).** A format is done when its row in the ETSI requirements matrix is covered and DSS validates it.
5. **No `unsafe`** (`unsafe_code = "forbid"` in `Cargo.toml`).
6. **English everywhere:** code, docs, comments, error messages, commits, issues and PRs. Error messages follow the Rust API Guidelines: lowercase, no trailing period.
7. **Comments: the default is none.** The name is the comment. `//!` for a module and `///` for a public item, one line each; `//` in a body only when it says what the code cannot.
8. **Don't write what rots:** no counters or lists that already live in the code. Point at the source.
9. **Tests live outside the module they test:** `src/foo/tests.rs`, declared in `src/foo.rs` as `#[cfg(test)] mod tests;`. Tests through the public API go in `tests/`.

## Personal data

**No test uses a real certificate.** Test keys and certificates are generated, never a person's. Neither the repo, nor an issue, nor a PR carries real certificates, names or signed documents.

## What to run and when

Everything goes through the `justfile`: bare `just <recipe>`, one command per call.

| When | What |
| --- | --- |
| On every red → green | `just test-one <filter>` |
| Before committing | `just fmt`. Lefthook runs `just fmt-check` and `just file-tokens` on commit |
| Before pushing | The pre-push hook runs `just check` |
| On opening the PR | The CI's verdict: `just check` on Linux, `just test` on macOS and Windows |

## Agent skills

* **Issue tracker:** GitHub Issues of `sgomez/rades`, through `gh` (`docs/agents/issue-tracker.md`).
* **Triage labels:** `docs/agents/triage-labels.md`.
* **Code host:** GitHub PRs (`docs/agents/code-host.md`); `/developer` defaults in `docs/agents/developer-defaults.md`.
* **Domain docs:** `docs/agents/domain.md`.
