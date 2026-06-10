# SeedSigner — Keycard Edition

**An air-gapped, DIY signing device for Bitcoin and Ethereum where your keys never live on the device — they live on a PIN-protected smartcard.**

This firmware turns cheap, publicly available hardware (a Raspberry Pi Zero, a small LCD, a camera and a smartcard reader — typically under $50 plus the card) into a QR-in / QR-out hardware wallet built around the [Status Keycard](https://keycard.tech/) JavaCard applet. The device itself is a stateless orchestrator: it scans transactions, shows you what you are signing, and asks the card to sign. Private keys are generated on (or imported into) the card's secure element and **can never be read back out**.

> This is a community fork of [SeedSigner/seedsigner](https://github.com/SeedSigner/seedsigner), built on top of [3rdIteration/seedsigner](https://github.com/3rdIteration/seedsigner) (the Satochip/smartcard fork). Both upstreams deserve the credit for the platform; this fork takes their work in a different direction — see below.

---

## How this fork differs from upstream

The two upstream projects are Bitcoin-only and (optionally) hold seeds *in device memory* while powered. This fork makes one structural change and builds everything around it:

* **The on-device seed manager and on-device PSBT signer were removed entirely.** There is no `Seed` object, no in-memory seed storage, no host-side signing. Every signature is produced inside a smartcard. If the device is seized while idle, there is nothing key-related on it to extract.
* **Ethereum support was added** as a first-class citizen alongside Bitcoin — both signing flows drive the same Keycard.
* The Satochip **SeedKeeper** applet is kept, but only as an encrypted **secret vault** (passwords, seed backups) — not as a signer.

What was deliberately dropped from upstream: on-device seed creation/storage, SLIP-39, BIP-85, Electrum seeds, WIF/BIP38, GPG tools, multisig descriptors and on-card Satochip signing. If you want those, use the upstreams — they do them well.

---

## Features

### Bitcoin (BIP-84 native segwit, mainnet)

* **PSBT signing** via animated QR — accepts UR `crypto-psbt`, Specter, base64 and base43 encodings; full review screen (inputs, outputs, fee) before the card signs; signed PSBT returned as a QR.
* **Connect software wallet** — exports the account xpub at `m/84'/0'/0'` plus the canonical `wpkh([fp/84h/0h/0h]xpub…/<0;1>/*)` descriptor (with BIP-380 checksum) for Sparrow, Specter, BlueWallet and friends.
* **View addresses** — paginated list of receive addresses (`m/84'/0'/0'/0/i`) derived *on the card*, each with a QR. Verify a receive address on the trusted display before funds touch it. Address derivation is test-locked to the official BIP-84 vectors.
* **Message signing** (BIP-137) via `signmessage` QR.
* Scope: single-sig P2WPKH, mainnet, PSBTs capped at 40 inputs / 40 outputs. Multisig / taproot / testnet are on the roadmap — the module boundaries already anticipate them.

### Ethereum

* **Transaction signing** for legacy (EIP-155) and EIP-1559 transactions, **EIP-712 typed data** and **personal_sign messages**, exchanged as UR `eth-sign-request` / `eth-signature` QRs (Keystone-style air-gapped flows).
* **Offline calldata decoding** — a built-in function registry recognises common calls (ERC-20 `transfer`/`approve`, swaps, Seaport, …) and shows you *what the transaction actually does* before signing, not just hex.
* **Digest verification screens** — ERC-8213 calldata digest for contract calls; EIP-712 digest + domain hash + message hash for typed data — so you can cross-check against what your software wallet displays.
* **View wallets** — paginated EIP-55 addresses (`m/44'/60'/0'/0/i`) derived on-card, with QR per address.

### Keycard management

* **Init wizard** — provisions PIN (6 digits), PUK (12 digits) and pairing in one guided flow. PIN attempt limit is configurable (2–10).
* **Duress PIN (decoy wallet)** — optional second PIN, set at init time, that transparently unlocks an on-card *decoy* wallet (the applet's native "alt PIN": same paths, different chain code, all routing done on-card — the host can't tell the difference, and neither can someone watching you unlock). Declining the option installs a random duress PIN so the predictable applet default is never live.
* **PIN lifecycle** — change PIN, **unblock a blocked PIN with the PUK** (with remaining-retry feedback), and **Lock card** to drop cached credentials on demand so the next operation re-prompts — which is also how you switch between the real and decoy wallets.
* **Multi-instance** — a single card can host several independent Keycard instances (own key, PIN, pairing each). Create, delete, switch and **rename** instances; management runs over GlobalPlatform SCP02. Instance names live in a plaintext file on the microSD (never put secrets in a name).
* **Pairing** — v3.2+ cards pair ephemerally (nothing touches disk); persistent pairings are stored on the microSD encrypted with AES-256-GCM under a key derived from your pairing password, and are bound to the card's unique ID.
* Wire-compatible with cards initialised by `keycard-cli` / `keycard-shell` — same pairing KDF, secure channel and AID conventions.

### Putting a key on the card

Creation is the **only** moment a seed can exist outside the secure element, so every path is short and ends in `LOAD_KEY`:

| Path | Entropy source | Words shown? |
|---|---|---|
| **Generate (on-card)** | The card's TRNG — indices travel once over the secure channel, the host derives the seed, loads it back, wipes everything | No |
| **Show + import** | Host CSPRNG — you copy the words to paper, pass a confirmation quiz, then the card is loaded | Yes (paper backup) |
| **Import existing** | Yours — SeedQR / Compact SeedQR / plain mnemonic QR / 4-letter QR, typed words (12/15/18/21/24), or NGRAVE "Perfect Key" hex | n/a |

Optional BIP-39 passphrase on import. At creation time you can mirror the seed to a **SeedKeeper backup** (on the same card, a second card, or both) — after that window closes, the seed is sealed: there is deliberately no way to ever read it back.

### SeedKeeper vault

The Satochip SeedKeeper applet is used as an encrypted store: view secrets on the card, save passwords, delete secrets, **clone card-to-card**, check free space — and install the applet onto a blank JavaCard from the device when needed. (Heads-up: the SeedKeeper iOS app currently crashes if a Keycard applet shares the same physical card; the firmware warns before creating that combination.)

### Stealth boot

Optional mode (off by default) that boots the device into a playable Snake game instead of the wallet UI; a configurable button sequence reveals the firmware. The game module is import-isolated from all key-handling code and writes nothing to disk. Details in [AGENTS.md](./AGENTS.md).

### Other tools

* Text QR encode/decode.
* MicroSD tools: flash a new image, verify a flashed card, secure wipe (zeros / random).
* SettingsQR import, GoPro Labs time-sync QR, battery calibration.
* **10 languages**: English, Català, Deutsch, Español, Français, Italiano, 日本語, Nederlands, Português (PT), 简体中文.

---

## Security model in one minute

* **No keys on the device, ever.** Generation, derivation and signing happen inside the card's secure element. The host sees public keys and signatures.
* **Short-lived sessions.** Verified PINs are cached only per session and are wiped on returning Home, locking the card, switching instances, removing the card, or any wrong PIN. Derived address lists die with the PIN cache (that's what keeps the decoy wallet indistinguishable).
* **Untrusted input discipline.** Every QR and file is parsed with strict validation; card responses (TLV/DER) are bounds-checked; mnemonic words are handled as independent copies and buffers are zeroed on every exit path (best-effort, as Python allows).
* **Tested.** 1,000+ unit tests, including BIP-84/EIP-712 vectors, protocol fixtures, and guard tests that statically enforce the stealth-module isolation rule and translation coverage of UI strings.
* **Honest limits.** Memory wiping in CPython is best-effort; treat physical seizure *mid seed-creation* as a potential compromise. The duress PIN deters coercion, it doesn't make it impossible. Read [AGENTS.md](./AGENTS.md) for the full threat-model notes.

---

## Hardware

* Raspberry Pi Zero 1.3 / Zero W / Zero 2 W (Pi 2/3/4 also work) — same boards as upstream SeedSigner.
* Waveshare 1.3" 240×240 LCD hat (320×240 displays are also supported).
* Pi-compatible camera (OV5647-class).
* **A smartcard interface** — any PC/SC-capable reader (USB CCID readers, the SEC1210 UART hat, PN532 over I2C…). See [docs/smartcard_support_installation.md](./docs/smartcard_support_installation.md) and [docs/io_config.md](./docs/io_config.md).
* **Cards:** a retail Status Keycard, or any compatible JavaCard running the Keycard applet 3.x (cards initialised with `keycard-cli` / `keycard-shell` work as-is). For the vault/backup features: a Satochip SeedKeeper (or a blank JavaCard — the firmware can install the applet).

Runs on [SeedSigner OS](https://github.com/SeedSigner/seedsigner-os) (Buildroot): small, reproducible images; the microSD can be removed after boot.

---

## Developing

```bash
# run the test suite (src/ layout — needs PYTHONPATH)
PYTHONPATH=src python3 -m pytest tests/

# hardware end-to-end check, on a Pi with a reader + card
python3 scripts/keycard_smoke_test.py --path "m/44'/60'/0'/0/0" --sign
python3 scripts/keycard_smoke_test.py --btc
```

* Desktop simulation (no Pi needed): [docs/desktop_simulation.md](./docs/desktop_simulation.md)
* Code map and contributor notes: [docs/code_structure.md](./docs/code_structure.md), [AGENTS.md](./AGENTS.md) (the living architecture/threat-model document)
* Changelog: [CHANGELOG.md](./CHANGELOG.md)
* Translations live in `src/seedsigner/resources/seedsigner-translations/` (vendored; compiled `.mo` checked in). New UI strings must land in **all** catalogs — a lint test enforces that they are at least gettext-wrapped.

---

## Status & disclaimer

Beta software, under active development. It handles real money on real networks — review what you sign, keep backups, and test with small amounts first. No warranty of any kind (MIT). This project is not affiliated with Status/Keycard, Satochip, or the upstream SeedSigner project.

## Acknowledgements

* [SeedSigner](https://github.com/SeedSigner/seedsigner) — the platform, UI framework and the air-gapped QR signing model.
* [3rdIteration/seedsigner](https://github.com/3rdIteration/seedsigner) — smartcard integration groundwork (readers, Satochip/SeedKeeper, SeedSigner-OS builds for card hardware).
* [Status Keycard](https://github.com/status-im/status-keycard) and [keycard-shell](https://github.com/status-im/keycard-shell) — the applet and the protocol conventions this firmware follows.
* [Satochip / Toporin](https://github.com/Toporin) — the SeedKeeper applet and pysatochip.
* [embit](https://github.com/diybitcoinhardware/embit) — the Bitcoin primitives.

## License

[MIT](./LICENSE.md) — same as upstream.
