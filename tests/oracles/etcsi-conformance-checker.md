# ETSI Signatures Conformance Checker

This document describes how to use the [ETSI Signatures
Conformance Checker](https://ec.europa.eu/digital-building-blocks/wikis/display/DIGITAL/ETSI+Signatures+Conformance+Checker)
to validate rades signatures.

> **This is a manual step.** The conformance checker has no API and requires
> web registration. It is never automated.

## Prerequisites

1. An account on the [EU Digital Building Blocks](https://ec.europa.eu/digital-building-blocks/) platform.
2. Access to the ETSI Signatures Conformance Checker (request access through your organization's contact).

## Procedure

1. Log in to the conformance checker web interface.
2. Upload a signature file (`.p7s` format).
3. Select the expected signature profile (e.g., CAdES-Baseline-B).
4. Review the validation result.

## Using rades fixtures

Upload `tests/oracles/test-pki/fixtures/third-party-cades-b-b.p7s` to verify
the conformance checker accepts signatures from the test PKI.

Expected result: **PASS** with profile CAdES-Baseline-B.

## Uploading only test-PKI signatures

All rades test fixtures use obviously fictitious certificates:
- `CN=rades test root ca`
- `CN=rades test intermediate ca`
- `CN=rades test signer RSA` / `CN=rades test signer ECDSA`

No real personal data is ever included in these certificates or signed documents.

## When to run

From M1 onwards, closing each format milestone includes running the
conformance checker on that format's signature.
