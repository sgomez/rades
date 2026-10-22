# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-22

### Added

- Initial release: CAdES B-B in two phases, the data to sign out and the signature value in, with the signing time injected.
- Signs detached or attached content, or a digest the caller computed.
- RSA PKCS#1 v1.5, RSA-PSS and ECDSA on P-256, P-384 and P-521, with SHA-2 or SHA-3 and `cms-algorithm-protection`.
- Optional `mime-type`, `content-hints`, `content-identifier` and `content-reference`, and the signer certificate, its chain or no certificate embedded.
- Signature policies: explicit, with every qualifier shape, or implied; the AGE policy v1.9 built in.
- AutoFirma's bare CMS and raw PKCS#1.
- `cades::decode` reads the signers and attributes of a CAdES signature, without validating it.

[0.1.0]: https://github.com/sgomez/rades/releases/tag/v0.1.0
