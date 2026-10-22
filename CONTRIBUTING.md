# Contributing

## Ground rules

- No test, CI job, issue or PR uses or carries a real certificate, name or signed document. Test keys and certificates are generated.
- Hashes, RSA, ECDSA, DER and X.509 come from RustCrypto; every format, container, C14N and protocol client is written here.
- Formats are written from the ETSI standards. AutoFirma and DSS are oracles in the tests, never sources to translate.
- No `unsafe`.

## Commands

Everything goes through the [`justfile`](justfile); `just --list` shows the recipes. `just check` is what the CI runs. Lefthook checks the formatting on commit and runs `just check` on push.

`just oracles` has DSS and AutoFirma judge the signatures in `tests/`; it needs JBang and Java 17+.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): the changelog is generated from them.

## Mutation testing

`just mutants` reports the mutants the tests miss. It is slow; pass `--in-diff` with a diff to mutate only what changed.

The CI mutates the diff of every push to `main` and the whole crate weekly. Missed mutants land as comments on one open issue.
