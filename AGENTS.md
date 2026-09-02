# AGENTS instructions for /workspace/seedsigner

## UI copy length guidance

For TextArea-based informational screens (especially ButtonListScreen flows), keep body copy to a **maximum of ~120 characters total**, split across **no more than 2 lines** (roughly **~60 characters per line**). This aligns with existing info screens such as the restart/power-off messages, which fit cleanly on the display.

If additional detail is needed, prefer a second screen instead of longer text.

## Display resize safety guidance

The canvas size (240×240) can differ from the physical display size (e.g. 128×128 on ST7735). `Renderer._resize_for_display()` handles the downscale automatically.

**Rules — always follow these when adding any UI rendering code:**

- **Never call `renderer.disp.show_image()` directly.** Always use the renderer helper methods instead:
  - `renderer.show_image()` — renders the current canvas (or a provided image) to the display.
  - `renderer.show_image(image, show_direct=True)` — renders a raw image frame directly (e.g. camera frames), bypassing the canvas.
  - `renderer.show_image_pan(...)` — animated pan with automatic resize.
  - `renderer.display_blank_screen()` — clears the display.
- All of the above call `_resize_for_display()` internally. Calling `disp.show_image()` directly skips that step and will crash on any display smaller than 240×240 with `"Image must be same dimensions as display"`.
- If you ever need to call `disp.show_image()` directly for a valid reason, wrap the image first: `renderer.disp.show_image(renderer._resize_for_display(image), 0, 0)`.
- When reviewing or writing code that renders images, confirm every `disp.show_image()` call goes through one of the approved renderer helpers. This applies to screen classes, screensavers, toasts, and any background threads that draw to the display.

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

## GPG trusted-signer consistency guidance

- Keep `src/seedsigner/models/gpg_trusted_projects.py` (the filename→project and fingerprint→signer whitelist used by **Verify Signature**) consistent with `docs/gpg_trusted_signers.md` whenever a project, signer fingerprint, bundled key file, or filename pattern changes.
- Fingerprints in the module must be 40-character uppercase hex primary-key fingerprints that match the bundled public keys under `gpg_keys/`. When adding a new signer, add (or confirm) the matching `.asc` in `gpg_keys/` and list it in both the module and the docs page.
- A key that signs for more than one tracked project is listed under each of those projects (e.g. Emzy signs both Electrum and Bitcoin Core).

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

## Testing guidance

### Running the test suite

After making changes, always run the full pytest suite to verify nothing is broken:

```bash
pytest tests/ -v --tb=short
```

Tests run directly against `src/` (configured via `[tool.pytest.ini_options].pythonpath = ["src"]` in `pyproject.toml`). **No `pip install .` required.**

For a quick smoke test of just the affected area, target specific files:

```bash
pytest tests/test_<relevant_file>.py -v --tb=short
```

### Expected platform-dependent failures

Some tests are skipped or fail on certain platforms due to missing hardware or dependencies. These are **expected** and not regressions:

| Test file | Platform(s) affected | Reason |
|-----------|---------------------|--------|
| `test_flows_seed.py` (satochip tests) | All (without hardware) | Requires pysatochip + physical Satochip device |
| `test_flows_tools.py` (satochip test) | All (without hardware) | Requires pysatochip + physical Satochip device |
| `test_smartcard_hardware.py`, `test_flows_smartcard_hardware.py` | All (without hardware) | Requires `pygp` + a PC/SC reader with a blank JavaCard; skips cleanly |

When reviewing test results, focus on **new** failures compared to the baseline. The current baseline on a typical development machine with GPG installed is **716 passing, 134 skipped, 7 failing** (satochip tests only — requires physical hardware). On machines without GPG, `test_gpg_message.py` and `test_gpg_time_update.py` will additionally fail — this is expected.

**Note:** The `_msys2_path()` helper in `test_gpg_message.py` auto-detects whether the installed GPG binary is from Git-for-Windows (needs MSYS2-style `/c/...` paths) or native Windows Gpg4win (needs native `C:\...` paths). If GPG tests fail on Windows with a "no writable keyring found" error, check that `_msys2_path()` correctly identifies the installed GPG variant.

### Hardware-in-the-loop smartcard tests

`tests/test_smartcard_hardware.py` and `tests/test_flows_smartcard_hardware.py` are **local-only** — no CI job runs them. They self-skip when `pygp` is missing or no reader/card is present, so they are safe to leave in the default suite.

They **install and uninstall applets on a single physical card** and factory-reset it, so:

- Never run them under `pytest-xdist` or with randomised ordering. Classes run in file-definition order and each one's teardown uninstalls what it installed.
- Put destructive tests last in their class body. Do **not** use `@pytest.mark.order(-1)` for this — that means last in the *session*, which would run the test after its own class teardown had already uninstalled the applet.

The SeedKeeper suite runs **twice**: `TestSeedKeeper` against the bundled v0.2 CAP, and `TestSeedKeeperV1` — a subclass — against the v0.1 CAP. Adding a test to `TestSeedKeeper` automatically exercises it on v0.1 too; override it in the subclass only when the *expected outcome* differs.

**Superseded applet CAPs go in `tests/javacard-cap-legacy/`, never in `javacard-cap/`.** That directory feeds the on-device "Install Applet" picker and ships in the OS image, while the image build prunes `tests/`. `tests/test_javacard_cap_manifest.py` enforces this and verifies both sha256 manifests; it needs no hardware. The recipe for adding another legacy version is in `tests/javacard-cap-legacy/README.md`.

```bash
pytest tests/test_smartcard_hardware.py -k SeedKeeper -v --tb=short --log-cli-level=INFO
```

### Star import caveat for underscore-prefixed names

The codebase uses `from .module import *` extensively in `tools_views.py` to re-export symbols from split modules (`gpg_views`, `smartcard_views`, `password_generator_views`). **Python's star imports silently skip all names starting with `_`** unless `__all__` is defined.

When moving or renaming an underscore-prefixed function:
- If it's imported by tests or other modules via `tools_views._func_name`, add an explicit re-export in `tools_views.py`:
  ```python
  from .source_module import _func_name as _func_name_alias
  # Re-export for backward compatibility
  _func_name = _func_name_alias  # noqa: F401 W0603
  ```
- If tests monkeypatch a function in `tools_views` but the actual code runs in another module, patch **both** modules:
  ```python
  monkeypatch.setattr(tools_views, "_func", fake_func)
  monkeypatch.setattr(source_module, "_func", fake_func)
  ```

### Adding new tests

- Place new test files in `tests/` with prefix `test_`.
- Use the same patterns as existing tests: `object.__new__(ViewClass)` to create view instances without triggering `__init__`, then monkeypatch dependencies.
- For views that reference symbols from split modules, ensure those symbols are accessible through `tools_views` (see star import caveat above).

### Back stack and workflow completion

`Controller.start()` keeps a `back_stack` of `Destination`s; the top entry is the View
currently running, and the back arrow (`Destination(BackStackView)`) pops the current View plus
the one beneath it. When a View returns a `Destination` that is **already in the stack**, the
Controller truncates the stack at that point rather than pushing a duplicate — so a completed
workflow returning to its entry menu removes its own screens instead of burying them under it.

Follow these rules when a View ends a workflow (see issue #423 for what happens otherwise: back
from the Javacard DIY menu re-ran the uninstall flow, which dead-ended and looped forever):

- **The whole workflow lives in one View** (however many Screens it runs), reached directly from a
  menu → return **`Destination(BackStackView)`**. The Controller pops the finished View and lands
  on whichever menu launched it. No hard-coded coupling, and it stays correct for Views reachable
  from more than one menu.
- **The workflow spans several View classes** → the last one cannot use `BackStackView` (that
  lands on the previous *flow screen*). Return the entry menu explicitly:
  **`Destination(EntryMenuView)`**. The truncation above keeps this from stacking up.
  If the chain has several entry points and no single menu to name, `MainMenuView` is an
  acceptable fallback — add a comment saying why (see `SatochipLoadDescriptorDetailsView`).
- **`Destination(MainMenuView)`** is reserved for workflows whose entry point genuinely *is* Home
  (Scan, PSBT signing, top-level Seeds flows) and for error handlers that deliberately reset
  navigation. **It is not a way to clear the back stack** — it only looks like one because the
  Controller wipes the stack whenever it routes to Home.
- **`clear_history=True`** is for flows that must not be re-enterable at all (error views, the
  post-wipe / settings-changed paths). Prefer the rules above for ordinary completions; it
  discards the parent menus too.

Whenever you add or change a workflow-terminating return, add the matching back-navigation
FlowStep to `tests/test_flows_menu_navigation.py` (see below).

### Navigation test maintenance

`tests/test_flows_menu_navigation.py` (**60 tests**) walks every UI menu path to catch lazy-import errors and platform-crashes. **Whenever a menu tree (a View's button_data list) is changed, a new View is added, or a View's imports are modified, update this test file** to cover the new/changed path.

Key rules:
- **Every settings-gated or conditionally-shown menu item must have a test** that verifies it is reachable (setting enabled) and/or hidden (setting disabled).
- **Every `run()` method that references an external module or class must be exercised** by at least one navigation test that reaches that `run()`. Missing-import bugs (`NameError`) are only caught when the View is actually entered.
- Tests verify **both** forward navigation (correct destination) and backward navigation (BACK returns to the right parent via `BackStackView` or direct `Destination`).
- Deep sub-menus (e.g. Password Generator → Diceware-BIP39 → 64 bits → Dice) should be tested when they contain views with external dependencies or platform-specific code.
- Use `before_run` callbacks (like `_patch_microsd_child`, `_patch_scan_view_decoder`) to patch hardware deps so child Views can be entered without crashing in CI.

When adding a new View that uses lazy imports, always add the corresponding `FlowStep` to an existing or new test method — even a simple "navigate to the View and stop" test is sufficient to catch `NameError` regressions.

### Real-screen (UI driver) flow testing

The normal flow tests mock `View.run_screen()`, so **Screens are never constructed or exercised** — screen-construction bugs (e.g. a keyboard layout that doesn't fit its grid, which raised `"charset will not fit in a 4x6 layout"`) and input-handling regressions can only be caught on-device or by the screenshot generator. Two layers close that gap:

- **`tests/test_screen_construction.py`** — constructs every keyboard-bearing Screen against a real (in-memory) canvas and asserts its keyboards build without error. **Whenever you add a new Screen that builds a `Keyboard`, add it to this file's case list.** This is the cheap, high-value regression net for layout/fit bugs.
- **`tests/ui_driver.py` + `FlowStep(real_screens=True)`** — runs *real* Screens through their real `_run()` input loops with scripted button presses (and simulated camera frames). Use this for end-to-end coverage of high-value user paths that involve typing or multi-step screen interaction (see `tests/test_real_screen_flows.py` for the GPG BIP85 / Generate-New and Text-QR-encode examples).

How to drive a real-screen flow:
1. Build the button script with the planning helpers (`plan_text_entry_script`, `plan_keyboard_screen_script`) — they derive the exact key sequence by driving throwaway `Keyboard` objects through their real `update_from_input()` and **verify the plan by replaying it** before returning, so a wrong plan fails fast in the helper rather than mid-flow.
2. Wrap the flow in a `UISession(script=[...])` (optionally with `camera_frames=[...]`) and pass it to `run_sequence(..., ui_session=session)`. Mark each View whose Screens should run for real with `FlowStep(SomeView, real_screens=True)`; those steps must **not** set `screen_return_value`/`button_data_selection` (the script supplies the input instead).
3. Assert on `session.renderer.frames` (real frames were rendered) and, where relevant, on a real side effect (e.g. a key actually present in an isolated GPG keyring via `GNUPGHOME`).

Gotchas:
- The `UISession` swaps the `Renderer`, `HardwareButtons`, and (optionally) `Camera` singletons for test stand-ins; every Screen picks them up at construction, so construct Screens only *inside* the session.
- GPG subprocess flows must point `GNUPGHOME` at a fresh temp dir (`monkeypatch.setenv`) **and** create that directory first — gpg will not create its own homedir and fails with rc=2 otherwise. Clean up any module-level state the View mutates (e.g. `BIP85_DATA`) in a `finally`.
- A real-screen step is allowed to be the *last* step in the sequence even though it specifies no mocked interaction; `run_sequence` handles that (don't add a redundant trailing `FlowStep`).

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

## seedsigner-os submodule (release pin)

The `seedsigner-os/` directory at the repository root is a **pinned git submodule** pointing to `3rdIteration/seedsigner-os` (a fork of the official `SeedSigner/seedsigner-os`). It is configured with `update = none` in `.gitmodules`.

### Critical Rules

- **`update = none` is load-bearing.** Both OS image build pipelines (`opt/build.sh` and `opt/luckfox/prepare-app-checkout.sh`) clone this repository **with `--recurse-submodules`** to fetch `seedsigner-translations` for `.mo` compilation. If `update = none` is removed, every image build will recursively clone the OS repo **and its nested Buildroot fork** into the rootfs overlay — causing massive slowdown, disk bloat, and potential leakage of OS/buildroot source into signed images.
- **Pin only at release.** The submodule pointer must be updated **only** when cutting a release, to the exact OS release tag (e.g. `SeSi-0.8.7+ShSi-B12`) that built the images for that release. Do not run `git submodule update --remote` or advance the pointer casually.
- **Bump procedure** (at release time):
  ```bash
  git -C seedsigner-os fetch --tags
  git -C seedsigner-os checkout SeSi-X.Y.Z+ShSi-Bnn   # exact tag for this release
  git add seedsigner-os
  git commit -m "chore: pin seedsigner-os to SeSi-X.Y.Z+ShSi-Bnn for release X.Y.Z"
  ```
- **Keep `docs/repositories.md` in sync** when the pin moves or the fork topology changes (e.g. if the upstream org repos become the primary again). The doc contains the authoritative architecture diagram, release pairing table, audit instructions, and the `update = none` rationale.
- **Auditors**: `git submodule update --init seedsigner-os` fetches the pinned OS tree; `git -C seedsigner-os submodule update --init opt/buildroot` fetches the Buildroot toolchain for full-toolchain audit. GitHub web UI renders both submodules directly from the pinned commits without any clone.
