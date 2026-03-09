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
- **Display strings** shown to the user should be NFC-normalized (also already done in `seed.py` via `passphrase_display` / `mnemonic_display_str`).

### Date and numeric input
- When parsing dates from user input, always use `_normalize_date_input()` (in `tools_views.py`) to replace non-ASCII dashes (fullwidth `\uff0d`, en-dash `\u2013`, em-dash `\u2014`, Unicode minus `\u2212`) with ASCII hyphen-minus before calling `strptime` / `fromisoformat`.
- When converting user-provided numeric strings use `try/except ValueError` around `int()` / `float()` instead of pre-checking with `.isdigit()`.  Python's `.isdigit()` returns `True` for non-ASCII Unicode digit characters (e.g. Arabic-Indic `٠-٩`) that `int()` cannot convert, so the pre-check gives a false positive and the subsequent conversion crashes.
- If an ASCII-only digit check is truly needed, combine `.isascii()` and `.isdigit()`, or test membership in `"0123456789"`.

### General rules
- Never rely on locale-dependent behaviour (`str.lower()` with Turkish İ, `strftime` with locale month names, etc.) for data that affects derivation, signing, or deterministic output.
- QR-scanned data, settings QRs, and file-imported data should all be treated as untrusted byte strings; decode as UTF-8 with error handling before further processing.
- When adding new user-input parsing, add tests that exercise at least one non-ASCII variant (e.g. a fullwidth digit, a non-ASCII dash) to catch locale-dependent regressions.
