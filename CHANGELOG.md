# Changelog

All notable changes to this project are documented in this file.

Entries marked "(SeedSigner official)" originate from the upstream project, while "(smartcard fork)" indicates releases and changes unique to this repository.

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
