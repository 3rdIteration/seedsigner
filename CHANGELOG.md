# Changelog

All notable changes to this project are documented in this file.

Entries marked "(SeedSigner official)" originate from the upstream project, while "(smartcard fork)" indicates releases and changes unique to this repository.

## 2026-10-06 - SeSi-0.8.7+ShSi-B13 (smartcard fork)

Paired OS release: `seedsigner-os` tag `SeSi-0.8.7+ShSi-B13`. Highlights since SeSi-0.8.7+ShSi-B12:

- Merged the upstream PSBT output-ownership rewrite (#1032) with fork hardening preserved, plus upstream multisig output-claim hardening (#1044): every derivation entry claiming this seed on a multisig output is now held to the committed script, closing a crafted-PSBT verification bypass; change outputs are verified to actually pay this seed
- Refuse version-confused and ambiguously framed PSBTs (psbt_faker ENC-01..10); resynced the psbt_faker corpus and closed the gaps it exposed
- New high-transaction-fee warning, highlighted on the PSBT Overview and PSBT Math screens (upstream #722)
- Security review hardening (H1, H2, M1, M5, M2, M3); added SECURITY.md, bundled the CryptoGuide GPG key, and tracked ShieldSigner as a trusted signer
- Security audit fixes: Verify Signature now refuses clearsigned files with unsigned text outside the signed block and hashes only the signed text; Provision MicroSD rejects path-traversal image names in unsigned `sd_update.txt`; redacts encryption keys and Text QR content from logged Destination reprs; clears Luckfox release-signing keys on Home and inactivity wipe; requires an explicit confirmation before blind digest signing; parses VALIDSIG's primary fingerprint so subkey-signed releases match the trusted-signer whitelist
- Fixed multisig PSBT signing with Keycard/Satochip cards; smartcard menu split per applet with master fingerprint display and Satodime; Satochip Enable 2FA gated behind confirmations
- SeedKeeper: fixed V2 descriptor read-back decode, mapped the 0x9C01 (card full) status, added v0.1 applet test coverage
- Luckfox: re-sign a release from MicroSD with BIP85-derived keys; refuse to write an armed idblock a fused board would reject; UART2 console + FIQ debugger stripped by default on every variant; hardened Pico Mini (SPI_NAND) image built in automatic CI
- Added Pico-Mini smartcard display hat hardware and enclosure files
- GPG fixes; fixed a newly created seed never reaching the Seeds menu, the invert-colors setting ignored at boot, and completed workflows being buried in the back stack
- Docs: smartcard/feature documentation, quick starts and regenerated screenshots; SeedSigner OS docs mirrored into the GitHub Pages site
- BIP85 GPG scheme v4: RSA keys now derive via the BIP85-spec path (see entries below, shipping for the first time in this release)

Previously-unreleased smartcard-fork changes shipping in this release:

- Randomized dummy Satochip signing requests (0-6 by default, configurable up to 12) that themselves may execute extra signatures per the configured probability and dummy count, plus optional extra per-input signatures with random selection among them to reduce potential nonce leakage
- Issue a random number of post-signing dummy requests (0-6 by default, configurable up to 12) applying the same extra-signing rules for additional nonce obfuscation
- Enforce configurable per-signature timeout (0.5–5 s, default 1 s, adjustable in 0.5 s steps) and allow tuning of pre-signing dummies, in-transaction dummy count, and per-input dummy probability
- Log dummy signing counts and per-operation signing durations for Satochip actions
- Gracefully handle Satochip signature normalization failures to avoid crashes
- Enhance Satochip benchmark signing tool to run 20 signatures and report min/avg/max times
- Randomize order of PSBT inputs during Satochip signing to further obfuscate input processing
- Deterministic BIP85 GPG key derivation with configurable name, email, expiration (defaulting to the end of 2029 for RSA 2048 keys and the end of 2035 for other key types), and key type (NIST P-256, Brainpool P-256, RSA 2048, RSA 3072, RSA 4096, or secp256k1); metadata such as expiration, deprecation, and end-of-use dates can be modified after import
- BIP85 GPG RSA keys now derive via the BIP85-spec path `m/83696968'/828365'/{bits}'/{index}'` (no `0'` key_type discriminator), bringing RSA back in line with the B8-era scheme; ECC derivation is unchanged
- RSA key selections warn that generation on a Pi Zero may take approximately 3 minutes (2048), 15 minutes (3072), or an hour (4096) and recommend NIST or Brainpool keys as faster, smaller alternatives
- MicroSD and GPG tools now display seed-loaded warnings only when opening file pickers
- GPG public keys can now be exported directly to a connected Seedkeeper card as ASCII-armored text
- Loading BIP85 GPG metadata now auto-selects the correct derivation scheme from each key's `ss_version` (map of firmware B-number → v1/v2/v3/v4), and it is stored per-key so the manual `BIP85 GPG version` setting only governs brand-new key generation

## 2025-08-04 - SS0.8.6+Satochip+Earthdiver-B3 (smartcard fork)
- Satochip card transaction signing and PSBT verification
- Satochip Message signing and xpub export (single and multisig) with address explorer integration
- BIP32 account prompt when exporting xpubs (disabled by default)
- Smartcard info screen with card UID and genuineness check
- SLIP39 seed creation, import, and extendable shares with configurable seed word lengths
- WIF and BIP38 key signing support (disabled by default)
- Settings to toggle smartcard and SLIP39 features and to configure smartcard PIN attempts
- SeedKeeper Electrum seed support and splitted passphrase/encryption key QR codes
- Enhanced entropy monitoring with hardware RNG, quality indicators and optional 30-minute wipe timer
- Desktop simulation mode with system camera support

## 2025-08-04 - SS0.8.6+Satochip+Earthdiver-B2-A1 (smartcard fork)
- Pre-release build for SS0.8.6 smartcard fork; see GitHub release notes

## 2025-07-08 - SS0.8.6+Satochip+Earthdiver-B2 (smartcard fork)
- Baseline smartcard fork release based on SeedSigner 0.8.6 with Satochip and Earthdiver enhancements

## 2025-07-01 - SS0.8.6+Satochip+Earthdiver-B1 (smartcard fork)
- Pre-release build for SS0.8.6 smartcard fork

## 2025-06-30 - 0.8.6 (SeedSigner official)
- Support for optional larger displays for improved readability
- Added French, Chinese, Catalan, Dutch, German, Italian, and Japanese translations

## 2025-06-27 - SS0.85+Satochip+earthdriver-b8 (smartcard fork)
- Reworked smartcard PIN workflows with optional caching and more reliable reconnections
- Smartcard reader management to list, test, enable or disable readers and restart PCSC
- Tools menu enhancements including human-friendly applet names, NFC policy configuration, factory reset and clearer locked-card errors
- Updated MicroSD tools for the new driver and fixes for smartcard failures when removing the card and navigation issues
- Documentation updates for SEC1210-based smartcard hats

## 2025-06-17 - SS0.85+Satochip+earthdriver-b7 (smartcard fork)
- Pre-release build with smartcard reader management and tooling enhancements

## 2025-06-09 - SS0.85+Satochip+earthdriver-b7-pre (smartcard fork)
- Pre-release build for upcoming b7 smartcard release

## 2025-05-02 - SS0.85+Satochip+earthdriver-b6 (smartcard fork)
- Pre-release build

## 2025-03-31 - SS0.85+Satochip+earthdriver-b3 (smartcard fork)
- Pre-release build

## 2025-03-12 - SS0.85+Satochip+earthdriver-b2 (smartcard fork)
- Pre-release build

## 2025-03-01 - SS0.85+Satochip+earthdriver-b1 (smartcard fork)
- Pre-release build

## 2025-02-26 - ss0.85-b5+earthdriver-a2 (smartcard fork)
- Pre-release build

## 2025-02-25 - ss0.85-b3+earthdriver-a1 (smartcard fork)
- Pre-release build

## 2025-02-04 - 0.8.5 (SeedSigner official)
- Introduced Spanish translation and groundwork for additional languages

## 2025-01-17 - ss0.85rc1-b3-a2 (smartcard fork)
- Pre-release build

## 2025-01-14 - ss0.85rc1-b3-a1 (smartcard fork)
- Pre-release build

## 2024-08-20 - 0.8.0 (SeedSigner official)
- Added legacy P2PKH and P2SH signing support
- Improved QR scanning UI and performance with smarter progress estimation
- Explicit support for PSBTs containing `OP_RETURN`
- Import Electrum native segwit seeds

## 2024-03-11 - 0.7.0+Satochip-Beta2 (smartcard fork)
- Pre-release build

## 2024-02-24 - 0.7.0+Satochip-Beta1 (smartcard fork)
- Pre-release build

## 2023-12-23 - 0.7.0+Satochip-Alpha1 (smartcard fork)
- Pre-release build

## 2023-12-05 - 0.7.0+SeedKeeper-Alpha (smartcard fork)
- Pre-release build

## 2023-09-11 - 0.7.0 (SeedSigner official)
- Reproducible builds and faster startup time
- QR-based message signing and SettingsQR generator
- Improved live camera framerate and more responsive controls

## 2023-02-21 - 0.6.0 (SeedSigner official)
- SeedSigner OS with removable microSD and minimal kernel
- Address explorer, BIP-85 deterministic seeds, and taproot signing
- Compact SeedQR enabled by default and additional UI tweaks

## 2022-06-17 - 0.5.1 (SeedSigner official)
- Options to add final word entropy via coin flips, BIP39 word or zeros
- Final word calculation screen with entropy and checksum bits
- Integrated secp256k1 library for faster signing and address verification

## 2022-04-25 - 0.5.0 (SeedSigner official)
- Major UI/UX upgrade with refreshed interface and workflows

## 2022-02-21 - 0.4.6 (SeedSigner official)
- Compressed SeedQRs (opt-in) and improved Sparrow XPUB workflow

## 2021-11-21 - 0.4.5 (SeedSigner official)
- Optimized XPUB export and customizable derivation paths
- On-demand address verification and QR brightness adjustment

## 2021-08-28 - 0.4.4 (SeedSigner official)
- Smart QR scanning and live preview during seed-from-photo and QR scanning
- Additional entropy sources and faster animated QR generation

## 2021-08-01 - 0.4.3 (SeedSigner official)
- Generate 24-word seed entropy from photos
- Redesigned seed/passphrase entry keyboard
- Reduced camera startup time and initial test suite

## 2021-07-16 - 0.4.2 (SeedSigner official)
- BIP39 passphrase support and SeedQR transcription/import
- Single-signature wallet mode and QR density setting
- Extended public key information detail

## 2021-06-25 - 0.4.1 (SeedSigner official)
- Support for Sparrow Wallet and BlueWallet multisig vault

## 2021-05-26 - 0.4.0 (SeedSigner official)
- New code structure for faster startup and improved navigation

## 2021-05-08 - 0.4.0b3 (SeedSigner official)
- Pre-release with new code structure and ability to display stored seeds

## 2021-02-06 - 0.3.0 (SeedSigner official)
- Testnet support and 12-word seed capability
- Temporary storage for up to three seeds and PSBT trimming

## 2021-01-15 - 0.2.0 (SeedSigner official)
- Added xpub generation and QR-based transaction signing

## 2020-12-20 - 0.0.2 (SeedSigner official)
- UX improvements and dice-roll 24-word seed generation
