export PATH := env_var_or_default('HOME', '') / ".cargo/bin:" + env_var('PATH')

_default:
    @just --list

# What the CI runs.
check: fmt-check (file-tokens "--all") lint doc test

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

# Files over 5,000 tokens: the staged ones, or every tracked one with `--all`.
file-tokens *flags:
    scripts/check-file-tokens.sh {{ flags }}

lint:
    cargo clippy --all-targets -- -D warnings

# Fails on rustdoc warnings, which docs.rs would show.
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --quiet

test:
    cargo test --quiet

# Builds the crate from its package, as crates.io will.
package:
    cargo publish --dry-run --quiet

# The library on its `rust-version`; the tests may need a newer Rust.
msrv:
    #!/usr/bin/env sh
    set -eu
    version=$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)
    rustup toolchain install "$version" --profile minimal
    cargo +"$version" check --lib

# Advisories, licenses and sources of the dependencies (`deny.toml`).
deny:
    cargo deny check

# Mutates the code and reports the mutants the tests miss (`.cargo/mutants.toml`); slow.
[positional-arguments]
mutants *args:
    cargo mutants "$@"

test-one filter:
    cargo test --quiet {{ filter }}

# Every oracle over the manifest of each signature directory; needs JBang and Java 17+.
oracles:
    jbang oracles/dss/Dss.java oracles/dss/policy.xml tests/pki/root.crt tests/pki/intermediate.crt tests/pki tests/autofirma tests/cades
    jbang oracles/autofirma/AutoFirma.java tests/pki tests/autofirma tests/cades
