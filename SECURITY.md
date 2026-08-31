# Security policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Please report any vulnerability or any bug that could potentially affect the security of users' funds by mail to:

- [`steve@cryptoguide.tips`](mailto:steve@cryptoguide.tips)

In the subject type `[ShieldSigner] Security Report: <short description>`
and in the body a long description describing the issue. We aim to respond
within one week and patch within 90 days.

### GPG key

To protect sensitive details, please encrypt your report with the public key below:

- User ID: `CryptoGuide <steve@cryptoguide.tips>`
- Fingerprint: `7C817290 6B9A7EAF 9F0BD8F1 62A1D33E 233C8EA0`

The key is bundled with this repository at [`gpg_keys/ShieldSigner_CryptoGuide.asc`](./gpg_keys/ShieldSigner_CryptoGuide.asc) and is also available from [keys.openpgp.org](https://keys.openpgp.org/vks/v1/by-fingerprint/7C8172906B9A7EAF9F0BD8F162A1D33E233C8EA0).

### What to include

To help triage the report quickly, please include as much of the following as you can:

- The ShieldSigner version (e.g. `SeSi-0.8.7+ShSi-B12`)
- A description of the vulnerability and its impact
- Steps to reproduce, ideally with a proof of concept

## Scope

This policy covers ShieldSigner (this fork) and related build repos (ie the seedsigner-os submodule and other 3rdIteration build repositories).

## Upstream disclosure

ShieldSigner is a fork of [SeedSigner](https://github.com/SeedSigner/seedsigner). If a reported issue is determined to also affect upstream SeedSigner, it will be disclosed to the upstream maintainers as well, in accordance with their [security policy](https://github.com/SeedSigner/seedsigner/blob/dev/SECURITY.md).
