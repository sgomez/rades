export PATH := env_var_or_default('HOME', '') / ".cargo/bin:" + env_var('PATH')

_default:
    @just --list

# What the CI runs.
check: fmt-check (file-tokens "--all") lint test

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

# Files over 5,000 tokens: the staged ones, or every tracked one with `--all`.
file-tokens *flags:
    scripts/check-file-tokens.sh {{ flags }}

lint:
    cargo clippy --all-targets -- -D warnings

test:
    cargo test --quiet

# Advisories, licenses and sources of the dependencies (`deny.toml`).
deny:
    cargo deny check

# Mutates the code and reports the mutants the tests miss; slow, run by hand.
[positional-arguments]
mutants *args:
    cargo mutants "$@"

test-one filter:
    cargo test --quiet {{ filter }}

# Run all oracles (DSS, AutoFirma) against the manifest.
[positional-arguments]
oracles *args:
    bash scripts/oracles.sh {{ args }}
