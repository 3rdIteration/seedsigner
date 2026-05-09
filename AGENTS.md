# AGENTS instructions for /workspace/seedsigner

## UI copy length guidance

For TextArea-based informational screens (especially ButtonListScreen flows), keep body copy to a **maximum of ~120 characters total**, split across **no more than 2 lines** (roughly **~60 characters per line**). This aligns with existing info screens such as the restart/power-off messages, which fit cleanly on the display.

If additional detail is needed, prefer a second screen instead of longer text.

## Screen layout and vertical space guidance

The display is 240×240 pixels. Key layout constants (from `GUIConstants`):

| Constant             | Value | Notes                                   |
|----------------------|-------|-----------------------------------------|
| `TOP_NAV_HEIGHT`     | 48 px | Title bar at the top of every screen    |
| `BUTTON_HEIGHT`      | 32 px | Height of a standard bottom button      |
| `EDGE_PADDING`       | 8 px  | Padding around screen edges / below buttons |
| `COMPONENT_PADDING`  | 8 px  | Default gap between stacked components  |
| `LIST_ITEM_PADDING`  | 4 px  | Tighter gap (use between closely-related lines) |

For a `ButtonListScreen` with `is_bottom_list=True` and a single button, the bottom button area occupies **`BUTTON_HEIGHT + EDGE_PADDING` = 40 px** from the bottom of the screen, so content must stay within the top **200 px** (y < 200).

When stacking multiple `TextArea` components (e.g. on `LargeIconStatusScreen` subclasses), calculate the cumulative `screen_y + height` to make sure the last component ends **above** the button zone. If content is tight, use `LIST_ITEM_PADDING` (4 px) instead of `COMPONENT_PADDING` (8 px) between closely-related lines (e.g. a derivation path and its warning label).

## IO config consistency guidance

- Keep `src/seedsigner/hardware/io_config.json` and `docs/io_config.md` consistent whenever pin mappings or profile details are changed.
- If the JSON and documentation conflict and the correct source of truth is unclear, explicitly ask the user how they want the conflict resolved before finalizing changes.

## Persistent settings and platform-detected defaults

`Settings.get_instance()` in `src/seedsigner/models/settings.py` initialises settings in three layers, applied in order so that each layer overrides the previous:

1. **Code defaults** — `SettingsDefinition.get_defaults()`
2. **Platform-detected defaults** — hardware-specific values (display config, camera rotation) computed once via `get_platform_default_*()` methods
3. **User-persisted settings** — loaded from the settings JSON file on disk

Because user settings are applied **last**, they naturally take priority over platform defaults without any additional guard logic.

### How it works

Platform defaults are computed into a `platform_defaults` dict at the top of `get_instance()`. When a settings file (or template) is loaded, `platform_defaults` are merged in as fallbacks for any keys the file doesn't contain (`loaded.setdefault(key, value)`), then `settings.update(loaded)` applies everything at once. When no file is loaded (test environment or first boot without template), platform defaults are written directly to `settings._data`.

### Rules

- **User-persisted settings must always take priority over platform-detected defaults.** The current layered approach guarantees this: platform defaults are merged as fallbacks before user settings are applied.
- When adding a **new** platform-detected default, add it to the `platform_defaults` dict in `get_instance()`:
  ```python
  platform_defaults = {
      SettingsConstants.SETTING__DISPLAY_CONFIGURATION: Settings.get_platform_default_display_config(),
      SettingsConstants.SETTING__CAMERA_ROTATION: Settings.get_platform_default_camera_rotation(),
      SettingsConstants.SETTING__MY_NEW_SETTING: Settings.get_platform_default_my_new_setting(),
  }
  ```
  No additional guard logic is needed — `loaded.setdefault()` ensures the user's saved value wins when present.

### Currently platform-detected settings

| Setting constant | Platform default method |
|-----------------|------------------------|
| `SETTING__DISPLAY_CONFIGURATION` | `get_platform_default_display_config()` |
| `SETTING__CAMERA_ROTATION` | `get_platform_default_camera_rotation()` |

Any **new** hardware-detected setting that can also be changed by the user must be added to this table and to the `platform_defaults` dict. Failing to do so will cause the platform default to not be applied.

## Security-first development guidance

Because this project handles private key material for an air-gapped signer, **security takes precedence over convenience**. Treat all entropy and key-handling paths as high-risk code.

### Entropy generation and handling
- Use only cryptographically secure RNG sources/APIs; never use non-CSPRNG functions for seed/key generation.
- Mix entropy sources conservatively (never reduce effective entropy via lossy transforms or truncation).
- Do not log, print, serialize, or persist raw entropy, seed bytes, or private keys—even in debug mode.
- Prefer deterministic, reviewed key-derivation standards (e.g., BIP39/BIP32 flows already used in repo) over custom schemes.
- Add explicit comments when code assumes a minimum entropy size/security level.

### Private key safety
- Keep secret material in memory for the shortest time possible.
- Avoid copies of secret data (including implicit copies via string conversions, repr/debug formatting, or temporary buffers).
- Zeroize/wipe secret buffers as soon as they are no longer needed.
- Store secrets in mutable byte buffers when possible (so they can be wiped), not immutable strings.
- Ensure error paths and early returns also wipe sensitive intermediates.

### Secure wipe and shared wordlist safety

`wipe_string()` (in `secure_delete.py`) uses `ctypes.memset` to zero a Python string's internal buffer **in place**. Because Python interns and shares string objects, this will **corrupt any other reference to the same object**. The BIP-39 and SLIP-39 wordlists (`bip39.WORDLIST`, `shamir_mnemonic.wordlist.WORDLIST`) are global, module-level lists of interned strings—if a word looked up from one of these lists is stored directly and later wiped, the corresponding entry in the global wordlist is permanently destroyed, breaking all subsequent mnemonic entry/matching for that word.

**Rules:**

- **Never store a direct reference** to an element of `bip39.WORDLIST` (or any shared/global wordlist) in a list or object that may later be passed to `wipe_list()` or `wipe_string()`.
- **Create an independent copy** with `"".join(word)`. This builds a new `str` object whose memory is separate from the wordlist.
- **`str(word)` and `word[:]` do NOT create copies** for `str` objects—Python returns the same object. Only `"".join(word)` (or equivalent `str` concatenation that forces a new allocation) is safe.
- When reviewing or writing code that **reads from a wordlist and stores the result** in a list, always apply the `"".join(...)` pattern at the point of storage.

**Currently protected call sites** (as of this writing):

| File | Function / line | What it stores |
|------|----------------|----------------|
| `seed_storage.py` | `update_pending_mnemonic()` | BIP-39 word into `_pending_mnemonic` |
| `seed_storage.py` | `update_pending_slip39_share()` | SLIP-39 word into `_pending_slip39_share` |
| `decode_qr.py` | `SeedQrDecoder.add()` (SeedQR path) | BIP-39 word into `seed_phrase` |
| `decode_qr.py` | `SeedQrDecoder.add()` (four-letter path) | BIP-39 word into `words` |
| `mnemonic_generation.py` | `calculate_checksum()` | Temp final word (`wordlist[0]`) appended to caller's list |
| `tools_views.py` | `_bip39_words_from_entropy()` | BIP-39 word into password word list |

Any **new** code path that looks up a word from a shared wordlist and stores it in a list that could be wiped must follow the same `"".join(word)` pattern and should include a regression test that wipes the list and asserts the global wordlist is still intact (see `test_seedqr.py::test_seedqr_decode_does_not_corrupt_wordlist` for an example).

### Cleanup and lifecycle controls
- On screen transitions, cancellations, exceptions, and shutdown/restart flows, clear in-memory seed/key state.
- Ensure temporary files are never used for entropy/key material; if unavoidable, they must be securely deleted immediately.
- Verify object caches/singletons do not retain secret state longer than required.

### Input, command, and script hardening
- Treat all external input (QR payloads, SD card files, settings imports) as untrusted.
- Validate and constrain input using strict allowlists, length checks, and format checks before processing.
- Never build shell commands by string concatenation with untrusted input.
- Prefer `subprocess.run([...], shell=False, check=True)` patterns over shell invocation.
- If shell scripts are required, quote variables defensively and avoid eval-like constructs.
- Do not execute dynamic code from user-provided payloads, descriptors, labels, or metadata.

### Dependency and crypto hygiene
- Prefer standard-library or well-reviewed cryptographic primitives already used by the project.
- Do not introduce new crypto dependencies or algorithms without explicit justification in the PR description.
- Keep reproducibility and deterministic builds in mind for security-sensitive changes.

### Seed type differences — `seed_bytes` vs `get_root()`

The codebase supports multiple seed types (see `src/seedsigner/models/seed.py`). They share a `Seed` base class but differ in critical ways. **Always use `seed.get_root(network)` to obtain the BIP-32 root key** — never call `bip32.HDKey.from_seed(seed.seed_bytes)` directly, because some seed types have `seed_bytes = None`.

| Type | `seed_bytes` | `get_root(network)` | Notes |
|------|-------------|---------------------|-------|
| **`Seed`** (BIP39) | 64-byte BIP39 seed (from mnemonic + passphrase) | Derives root from `seed_bytes` with network version | Standard path; passphrase changes `seed_bytes` |
| **`XprvSeed`** | **`None`** | Returns pre-parsed `_root` HDKey (network param ignored) | No mnemonic, no seed bytes — root key is the only secret |
| **`ElectrumSeed`** | PBKDF2-derived bytes | Inherited from `Seed` | Overrides `script_override`, `derivation_override`, `detect_version` |
| **`AezeedSeed`** | Aezeed entropy | Inherited from `Seed` | Decrypted from aezeed ciphertext |
| **`Slip39Seed`** | SLIP-39 master secret | Inherited from `Seed` | Recovered from share combination |

**Rules when writing code that handles seeds:**

- **Never access `seed.seed_bytes` directly for key derivation.** Call `seed.get_root(network)` instead. `XprvSeed.seed_bytes` is `None` and will crash `bip32.HDKey.from_seed()`.
- **Check for feature support before using seed-type-specific features.** For example, `seed.mnemonic_list` is empty for `XprvSeed`; `seed.seedqr_supported` is `False` for `XprvSeed`, `ElectrumSeed`, and `Slip39Seed`.
- **Respect method overrides.** `ElectrumSeed` overrides `derivation_override()`, `script_override`, and `detect_version()`. Always call these through the seed object rather than assuming BIP39 defaults.
- **When working with non-Seed-like objects** (e.g. in helper functions that may receive mock objects or raw HDKeys), use the pattern `if hasattr(seed, "get_root"): root = seed.get_root()` with a fallback to `bip32.HDKey.from_seed(seed.seed_bytes)`.
- **Test with multiple seed types.** Any new feature touching key derivation, BIP85, address verification, or PSBT signing should be tested with at least `Seed` (BIP39) and `XprvSeed` to catch `seed_bytes = None` issues.

### Code review expectations for sensitive changes
For changes touching entropy, seed generation/import, key derivation, signing, or secret storage:
- Add/extend tests for both success and failure/cleanup paths.
- For seed creation/loading features, test all supported workflows for consistent behavior and fault tolerance.
- Prefer shared code paths across workflows (scan/manual/import) instead of duplicating seed-handling logic.
- Document threat assumptions and failure modes in code comments or PR notes.
- Call out any remaining risk tradeoffs explicitly.

## Unicode and locale-safe string handling

SeedSigner must produce identical results regardless of the host locale or input method. Follow these rules when processing user-supplied or externally-sourced strings:

### Normalization
- **BIP39 / SLIP39 / Electrum passphrases and mnemonics** must be NFKD-normalized (already done in `seed.py`). Do not change the normalization form.
- **Encrypted QR code passwords** (`kef.py` `Cipher` class) are NFKD-normalized before PBKDF2 key derivation, ensuring the same password produces the same encryption key regardless of platform (macOS typically stores NFD, Linux/Windows use NFC).
- **Display strings** shown to the user should be NFC-normalized (also already done in `seed.py` via `passphrase_display` / `mnemonic_display_str`).

### Normalization audit summary

The following table lists every code path where user-supplied strings feed into key derivation, encryption, or deterministic output, and whether NFKD normalization is applied:

| Code path | Normalized? | Where |
|-----------|-------------|-------|
| BIP-39 passphrase | ✅ NFKD | `Seed.set_passphrase()` in `seed.py` |
| BIP-39 mnemonic | ✅ NFKD | `Seed.__init__()` in `seed.py` |
| SLIP-39 passphrase | ✅ NFKD | `Slip39Seed.set_slip39_passphrase()` in `seed.py` |
| Electrum passphrase | ✅ NFKD + lower() | `ElectrumSeed.normalize_electrum_passphrase()` in `seed.py` |
| Aezeed passphrase | ✅ NFKD (inherited) | Via `Seed.set_passphrase()` before reaching `aezeed.decode_mnemonic()` |
| Encrypted QR password | ✅ NFKD | `Cipher.__init__()` in `kef.py` |
| Dice / coin-flip entropy | N/A (ASCII-only) | Input constrained to `1-6` / `0-1` by keyboard UI |
| GPG name / email | N/A (ASCII keyboard) | Input constrained to ASCII by on-screen keyboard |
| GPG expiration dates | ✅ dash-normalized | `_normalize_date_input()` in `tools_views.py` |

When adding a **new** code path that derives keys or produces deterministic output from user-supplied strings, always NFKD-normalize the input before encoding to bytes.

### Date and numeric input
- When parsing dates from user input, always use `_normalize_date_input()` (in `tools_views.py`) to replace non-ASCII dashes (fullwidth `\uff0d`, en-dash `\u2013`, em-dash `\u2014`, Unicode minus `\u2212`) with ASCII hyphen-minus before calling `strptime` / `fromisoformat`.
- When converting user-provided numeric strings use `try/except ValueError` around `int()` / `float()` instead of pre-checking with `.isdigit()`.  Python's `.isdigit()` returns `True` for non-ASCII Unicode digit characters (e.g. superscript `¹²³`) that `int()` / `float()` cannot convert, so the pre-check gives a false positive and the subsequent conversion raises `ValueError`.
- If an ASCII-only digit check is truly needed, combine `.isascii()` and `.isdigit()`, or test membership in `"0123456789"`.

### General rules
- Never rely on locale-dependent behaviour (`str.lower()` with Turkish İ, `strftime` with locale month names, etc.) for data that affects derivation, signing, or deterministic output.
- QR-scanned data, settings QRs, and file-imported data should all be treated as untrusted byte strings; decode as UTF-8 with error handling before further processing.
- When adding new user-input parsing, add tests that exercise at least one non-ASCII variant (e.g. a fullwidth digit, a non-ASCII dash) to catch locale-dependent regressions.
- Be aware that the same Unicode character can have multiple representations (e.g. `é` can be U+00E9 [NFC] or U+0065 U+0301 [NFD]). macOS file-system APIs and some input methods produce NFD; most other systems produce NFC. NFKD normalization collapses both forms into a single canonical byte sequence.

## Ethereum + Keycard integration

This fork extends SeedSigner to sign Ethereum transactions using a Status Keycard (or compatible JavaCard applet, e.g. cards initialised via `keycard-shell`). **Bitcoin remains the headline experience**; the Keycard flow lives entirely under `Tools > Smartcard Tools > Keycard` and shares no code paths with the BIP39/PSBT flow.

### Module layout

| Path | Responsibility |
|------|----------------|
| `src/seedsigner/helpers/ethereum/` | Chain-agnostic primitives: `rlp`, `keccak`, `address` (EIP-55), `tx_legacy` (EIP-155), `tx_eip1559`, `eip712`, `personal_sign`, `ur_codec` (UR `eth-sign-request` / `eth-signature`) |
| `src/seedsigner/helpers/keycard/` | Card protocol: `commands` (APDU builders), `responses` (TLV/DER), `crypto` (PBKDF2/AES-CBC/ECDH), `secure_channel`, `client`, `reader` (PC/SC), `secrets` (CSPRNG PIN/PUK/password), `pairing_storage` (AES-GCM blob on microSD), `ui_helpers` (path/pubkey/PIN helpers shared by views) |
| `src/seedsigner/helpers/keycard_signer.py` | Glue: `signing_hash_for(request)` + `compute_v(request, rec_id)` |
| `src/seedsigner/views/keycard_views.py` | UI: `Tools > Keycard` menu, init/pair/unpair, generate-key, export address, sign-eth scan→review→sign→QR |
| `scripts/keycard_smoke_test.py` | Hardware-only end-to-end check (SELECT → PAIR → SC → VERIFY_PIN → DERIVE → EXPORT → SIGN+recover) |

### Protocol compatibility — DO NOT change without coordinating with existing cards

Cards initialised by `keycard-cli` / `keycard-shell` ship with very specific protocol parameters. The constants below are deliberately matched to that convention; **changing any of them breaks every previously-paired card.**

| Parameter | Value | Source |
|-----------|-------|--------|
| Applet AID | `A0000008040001010101` | Status Keycard published AID, hard-coded in `commands.py` |
| Pairing-password KDF | PBKDF2-HMAC-**SHA256**, 50000 iter | `crypto.derive_pairing_secret()` — matches keycard-cli/shell defaults |
| Pairing-password salt | `b"Keycard Pairing Password Salt"` | Same constant as keycard-cli |
| Password Unicode normalisation | NFKD before UTF-8 encode | Already done at every entry point (PairView, smoke test) |
| Secure channel ECDH | secp256k1, raw X-coordinate (not libsecp default SHA256-of-X) | `crypto.secp256k1_ecdh()` uses `ec_pubkey_tweak_mul` |
| Session key derivation | SHA512 over `shared_x ‖ pairing_key ‖ salt`, split into ENC/MAC keys | `secure_channel.py` |
| Session encryption | AES-256-CBC + AES-CBC-MAC over framed payload | `secure_channel.py` |
| Default ETH derivation path | `m/44'/60'/0'/0/0` (BIP-44 chain 60) | exported as `helpers.ethereum.DEFAULT_ETH_PATH` |
| PIN length | 6 ASCII digits | `keycard_views.PIN_LENGTH` |
| PUK length | 12 ASCII digits | `keycard_views.PUK_LENGTH` |

If the user has cards from a custom applet variant (e.g. one that derives the pairing secret with SHA-512 instead of SHA-256), the right answer is to add an opt-in setting that toggles `derive_pairing_secret(..., hmac_hash_module=...)`, not to change the default.

### Pairing persistence on microSD

`helpers/keycard/pairing_storage.py` writes a single file:

- **Path:** `<MicroSD>/keycard_pairing.bin` (resolved via `MicroSD.get_microsd_dir()`).
- **Format:** `[version:1] [salt:16] [nonce:12] [tag:16] [ciphertext:N]`. Plaintext payload: `pairing_index ‖ pairing_key(32) ‖ instance_uid_len ‖ instance_uid`.
- **Encryption:** AES-256-GCM. Key derived from the user's pairing password via PBKDF2-HMAC-SHA256, 50000 iter, with a **separate domain salt** (`b"Keycard Pairing Storage v1"` ‖ random 16 bytes) so the on-disk key is not the same as the on-card pairing secret.
- **Card binding:** the persisted `instance_uid` is checked against the SELECT response on load; a blob from another card is rejected before any card APDU is sent.
- **Atomic writes:** `save()` writes to `*.tmp` then `os.replace`s; chmod 0o600 best-effort (vfat ignores).

The user enters the pairing password **once per boot**. The decrypted pairing key is cached in `Controller.keycard_pairing` (a `PairingInfo`) for the session and is dropped on `Tools > Keycard > Forget saved pairing` or unpair.

### Threat model and memory hygiene

- **PIN never cached.** It lives in a `bytearray` for the duration of one APDU exchange. After the operation, `wipe_bytearray()` zeros every byte. Then the operation closes its connection.
- **Pairing password never cached.** Captured into a `bytearray`, NFKD-normalised, used to derive both the on-card secret and the on-disk storage key, then the bytearray and the intermediate normalised string are wiped (best-effort — see below).
- **Pairing key cached.** As above: held in memory until the user exits the session or chooses "Forget saved pairing".
- **Wipe is best-effort.** `helpers/secure_delete.wipe_string()` and our `wipe_bytearray()` cannot defeat Python's GC, copy-on-write inside CPython, or the C runtime's allocator. **Assume any value that exists in memory at the moment of physical seizure is recoverable.** Mitigation: short-lived sessions, PIN re-entry per operation, no debug logging of secrets.
- **Bitcoin paths untouched.** No Keycard or Ethereum module imports from `seedsigner.models.seed*` or any BIP39 path. The `Controller` holds Keycard state in dedicated attributes (`keycard_pairing`, `eth_sign_request`, `eth_signature`) that are reset on flow exit / `MainMenuView`.

### Extension points (when adding new ETH features)

- **New transaction type / signing flavour**: add a `DATA_TYPE_*` to `helpers/ethereum/ur_codec.py`, extend `keycard_signer.signing_hash_for()` and `compute_v()`. Do NOT branch in `keycard_views.py` — the view layer should stay agnostic to digest construction.
- **New chain / derivation path**: prefer making the path part of the `EthSignRequest` (it already carries `derivation_path`). Only override `DEFAULT_ETH_PATH` if the path is wired through the smoke test fixtures and view tests.
- **Alternate card applet (e.g. Satochip with ETH support)**: keep `helpers/ethereum/` as-is, add a parallel `helpers/<card>/` and a `<card>_signer.py` that exposes the same `sign(digest, path) -> (r,s,v,pubkey)` shape. The view layer can then dispatch based on a Tools submenu choice.

### Hardware verification

Before merging any change to `helpers/keycard/` or `helpers/keycard_signer.py`, run on a Pi:

```
python scripts/keycard_smoke_test.py --path "m/44'/60'/0'/0/0" --sign
```

Capture the output to a local file (do **not** commit — the pubkey is fine but pairing diagnostics may include sensitive timing). Without `--sign`, the script exercises SELECT → PAIR → secure-channel → VERIFY_PIN → DERIVE → EXPORT only.

## Stealth boot mode

This fork supports an optional "stealth boot" mode controlled by two settings (default OFF, hidden from the Settings UI under Advanced):

| Setting | Default | Purpose |
|---------|---------|---------|
| `SETTING__STEALTH_BOOT` | `False` | When `True`, the device boots into a Snake game instead of `MainMenuView` |
| `SETTING__STEALTH_UNLOCK_SEQUENCE` | `"KEY_UP,KEY_UP,KEY_UP,KEY_UP,KEY_UP"` | CSV of `HardwareButtonsConstants` names; the sequence the user must press to exit the game and start the firmware |

### Rules

- **The stealth module (`src/seedsigner/stealth/`) MUST NOT import from `seedsigner.models.seed*`, `seedsigner.helpers.keycard*`, or any module that touches secrets.** This is enforced by code review (no static checker yet) and reduces the blast radius if the game has a bug.
- **No persistence from the game.** The Snake game does not write anywhere — no high score, no resume state. The settings file holds only the toggle and the unlock sequence.
- **No visual hint** that the unlock sequence is being matched. Showing partial progress would defeat the "looks like a game" property for a casual observer.
- **Resolution-aware.** The game reads `Renderer.canvas_width` / `canvas_height` and adapts the grid; do not hard-code 240x240 or 320x240 — both are valid hardware configurations.
- **Panic exit** (documented here, not in UI): holding `KEY1 + KEY2 + KEY3` for 10 s during the game disables `STEALTH_BOOT` and triggers a reboot. Use this if a user enables stealth mode and then loses their unlock sequence.

### Where the boot hook lives

`Controller.start()` checks `SETTING__STEALTH_BOOT` *before* the OpeningSplashView. When the game returns (sequence matched), the rest of the boot continues normally — splash, dev/desktop warnings, MainMenu. The session is then indistinguishable from a non-stealth boot.
