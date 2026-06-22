# Changelog

All notable changes to this project are documented in this file.

Entries marked "(SeedSigner official)" originate from the upstream project, "(smartcard fork)" indicates releases inherited from 3rdIteration/seedsigner, and "(Keycard edition)" indicates releases of this fork.

## 2026-06-22 - 0.1.3 (Keycard edition)

- **Fix — "Create instance" failed with 0x6982**: the free-NV memory check is now read **in the clear, before** the SCP02 secure channel opens. The previous build issued an un-MAC'd `GET DATA` over the *open* channel, desyncing it so the next `INSTALL` was rejected with "Security status not satisfied". The post-INSTALL self-calibration (which also needed a read over the open channel) was dropped in favour of the conservative per-instance estimate
- **Seed word entry (Import seed ▸ Type words)**: navigation now **skips over greyed-out letters** and jumps the cursor straight to the next still-available key (no more scrolling across keys you can't pick); the **back arrow steps to the previous word** — re-opened pre-filled for editing — instead of discarding every word entered so far (it only backs out of the flow on word #1)
- **Security / RAM hygiene**: the seed import / generate / SeedKeeper-backup flows now also wipe the *joined* plaintext mnemonic string and the *decoded* passphrase string (each held the whole secret in one immutable allocation) on every exit path, not just the per-word lists. `decode_seedkeeper_seed_secret` now bounds-checks every length-prefixed field and rejects non-canonical BIP-39 entropy lengths (returns `None` instead of raising on a malformed/hostile card). Secure-channel response MACs and the encrypted-QR auth tag use constant-time comparison
- **Destructive key ops moved out of the daily path**: `This instance` now holds only safe management (Change PIN, Unblock PIN, Rename, Lock); Generate key / Import seed / Initialise instance / Factory reset live under a new **Set up / reset ›** submenu. Generate key / Import seed now warn **"Replace key?"** before overwriting an existing key (advisory SELECT-only probe; falls back to the generic warning on any failure)
- **Memory-aware instance limit**: the hardcoded 4-instance cap becomes a free-space estimate (firmware ceiling raised to 16). The create flow shows **"≈N more fit"**, self-calibrates from the free-NV delta around INSTALL, and only soft-warns ("Create anyway") when the card looks too full; the Storage view shows **"≈N more instances fit"**
- **ETH account layout chooser**: pick **Standard (BIP-44)** `m/44'/60'/0'/0/i` vs **Ledger Live** `m/44'/60'/i'/0/0` for *View wallets* and *Connect software wallet*, with per-scheme address caching. The Ledger Live export picker is now paginated and shows each account's address so you can verify before exporting
- **Import hex (NGRAVE)**: the Type-hex path gains a **24-word (64 hex) / 12-word (32 hex)** length chooser that caps input and shows all slots grouped in blocks of 8 for cross-checking. SeedKeeper backup at creation simplified to the single iOS-compatible "BIP39 mnemonic" format
- **Stealth games console**: held buttons no longer "run on" (the input loop drains and throttles per-key actions, fixing Tetris soft-drop overshoot) — the unlock combo still sees every raw key. The game-select menu is redesigned with real typography, per-game accent colours, and a HUD refresh
- **Keycard install UX**: the iOS-coexistence warning is now a subtle non-blocking toast instead of a blocking screen, and the pre-install low-space check no longer false-positives on a card that already holds the Keycard package (footprint is estimated from the real on-card size, not the raw `.cap`). The SeedKeeper storage chooser shows the card's free space ("Free: X KB")
- **Card-swap detection extended** to the warm address-cache views (ETH *View wallets* / BTC *View addresses*) and to **every Keycard menu entry**, reusing the SELECT the probe already did: swapping cards no longer shows the previous card's cached addresses; the view re-derives for the new card

## 2026-06-19 - 0.1.2 (Keycard edition)

- Keycard instance AIDs unified on the **9-byte canonical form** real Status cards / keycard-cli use: the first instance created on a blank card is no longer the 10-byte legacy form, so every instance is consistent. Cards already in the field keep working — `select_with_autodetect` still probes the legacy form
- Creating a Keycard instance now **auto-activates** it, so the next step (Init / Generate / Import) targets the instance you just created without a manual switch
- Single-instance cards: the "Switch instance" entry and the "Inst N" title suffix are **hidden** when there is nothing to switch between, cutting menu noise (a user-assigned name still shows)
- Reader-independent **card-swap detection**: swapping cards mid-flow is caught synchronously at SELECT (not only via the unreliable PC/SC removal event), dropping the previous card's cached PIN; sign/export flows retry after a swap **without re-scanning** the QR
- Stealth boot is now a **games console**: choose Snake, 2048, Tetris, or a one-button Dino-style runner; the unlock combo (entered in any game or the menu) reveals the wallet. Snake wraps around the walls
- ETH **calldata decoding** improvements: decodes with the transaction value in context, accepts hex `personal_sign` payloads, and adds a function-selector registry + 4byte lookup so more contract calls render human-readably before signing

## 2026-06-15 - 0.1.1 (Keycard edition)

- SeedKeeper → Keycard import: new "From SeedKeeper" source restores a seed stored on a SeedKeeper applet into a Keycard instance (the stored passphrase is preserved; guided card swap since the two applets usually sit on separate cards)
- Faster Keycard menu: dropped the heavy GlobalPlatform/ISD enumeration from the `Tools > Keycard` entry path — fixes a multi-second stall on already-used cards. "Switch instance" visibility now uses a light, unauthenticated AID probe; card detection and removal are unchanged
- Clearer error when a card's GlobalPlatform ISD keys are not the defaults ("GP keys not default"), so applet/instance management fails legibly instead of hanging
- Bitcoin "Connect software wallet" first screen reworded to explain the watch-only BIP-84 account export
- Docs: clarified that the device installs the Keycard applet onto a blank card (loads the official `keycard_v3.2.cap` and creates the signing instance); new README card-compatibility section (signing works on any pairable card, management needs the default GP ISD keys); corrected the applet-count note (the official cap ships four applets: signing, NDEF, Cash, Ident)
- All new UI strings translated across the 10 locales

## 2026-06-10 - 0.1.0 (Keycard edition)

First release of the Keycard-only fork ("SeedSigner — Keycard Edition"). Keys never live on the device — they live on a PIN-protected smartcard.

- On-device seed manager and host-side PSBT signer removed entirely; every signature is produced inside a Status Keycard (applet 3.x) secure element
- Bitcoin over Keycard: BIP-84 P2WPKH PSBT signing via animated QR, xpub + descriptor export ("Connect software wallet"), on-card receive-address browser, BIP-137 message signing
- Ethereum over Keycard: legacy (EIP-155) and EIP-1559 transactions, EIP-712 typed data and personal_sign via UR `eth-sign-request` / `eth-signature`; offline calldata decoding; ERC-8213 / EIP-712 digest verification screens; on-card address browser
- Keycard management: init wizard (PIN/PUK/pairing), duress (alt) PIN with on-card decoy wallet, change PIN, unblock PIN with PUK, Lock card, multi-instance create/delete/switch/rename over GlobalPlatform SCP02
- Putting a key on the card: on-card generate (TRNG), show-words + import with confirmation quiz, import via SeedQR / typed words / NGRAVE "Perfect Key" hex; optional SeedKeeper backup at creation time
- SeedKeeper applet kept as an encrypted secret vault (view / save / delete / clone secrets, applet install onto blank JavaCards)
- Optional stealth boot (Snake game with configurable unlock sequence)
- Pairing persistence on microSD (AES-256-GCM); per-instance PIN cache with strict wipe triggers
- 10 UI languages
- Removed from upstream: on-device seed creation/storage, SLIP-39, BIP-85, Electrum seeds, WIF/BIP38, GPG tools, multisig descriptors, on-card Satochip signing

## 2025-09-24 - SS0.8.6+Satochip+Earthdiver-B4 (smartcard fork)
- Randomized dummy Satochip signing requests (0-6 by default, configurable up to 12) that themselves may execute extra signatures per the configured probability and dummy count, plus optional extra per-input signatures with random selection among them to reduce potential nonce leakage
- Issue a random number of post-signing dummy requests (0-6 by default, configurable up to 12) applying the same extra-signing rules for additional nonce obfuscation
- Enforce configurable per-signature timeout (0.5–5 s, default 1 s, adjustable in 0.5 s steps) and allow tuning of pre-signing dummies, in-transaction dummy count, and per-input dummy probability
- Log dummy signing counts and per-operation signing durations for Satochip actions
- Gracefully handle Satochip signature normalization failures to avoid crashes
- Enhance Satochip benchmark signing tool to run 20 signatures and report min/avg/max times
- Randomize order of PSBT inputs during Satochip signing to further obfuscate input processing
- Deterministic BIP85 GPG key derivation with configurable name, email, expiration (defaulting to the end of 2029 for RSA 2048 keys and the end of 2035 for other key types), and key type (NIST P-256, Brainpool P-256, RSA 2048, RSA 3072, RSA 4096, or secp256k1); metadata such as expiration, deprecation, and end-of-use dates can be modified after import
- RSA key selections warn that generation on a Pi Zero may take approximately 3 minutes (2048), 15 minutes (3072), or an hour (4096) and recommend NIST or Brainpool keys as faster, smaller alternatives
- MicroSD and GPG tools now display seed-loaded warnings only when opening file pickers
- GPG public keys can now be exported directly to a connected Seedkeeper card as ASCII-armored text

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
