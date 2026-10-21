# Security policy

## Supported versions

rades is pre-1.0: only the latest release gets fixes.

## Reporting a vulnerability

Report it privately through [GitHub's private vulnerability reporting](https://github.com/sgomez/rades/security/advisories/new). Do not open a public issue.

Include the affected version and the input that reproduces it. Leave out anything that identifies a signer: real certificates, names and signed documents.

You will get an answer within 7 days. Once a fix ships, the advisory is published with credit to the reporter, unless they prefer otherwise.

## Scope

In scope: signatures that verify when they should not, or fail when they should; parsers that crash or loop on hostile input; and any path that leaks what is being signed.
