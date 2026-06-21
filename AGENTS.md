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

**Currently protected call sites** (post-keycard-only refactor):

| File | Function / line | What it stores |
|------|----------------|----------------|
| `helpers/mnemonic_generation.py` | `calculate_checksum()` | Temp final word (`wordlist[0]`) appended to caller's list — used by the Keycard generate-mnemonic-visible flow |
| `helpers/mnemonic_generation.py` | `generate_mnemonic_from_bytes()` etc. | Each word in the returned list is independently allocated via `"".join(w)` |
| `views/keycard_views.py` | `_capture_via_keyboard()` | BIP-39 word into a per-session list before `wipe_list()` clears it |
| `views/keycard_views.py` | `_capture_via_hex()` | Words from `bip39.mnemonic_from_bytes` (NGRAVE hex import) copied via `"".join(w)`; entropy `bytearray` wiped in a `finally` |
| `views/keycard_views.py` | `ToolsKeycardImportSeedkeeperSelectView` | Mnemonic decoded off a Seedkeeper secret (`seedkeeper_utils.decode_seedkeeper_seed_secret`) split into per-word `"".join(w)` copies before stashing on the controller; the decode's source hex string / entropy are immutable (best-effort) |

The SeedSigner SeedQR / SLIP-39 / on-device seed-entry call sites that this table used to track are gone (see "On-device seed handling — removed"). Any **new** code path that looks up a word from a shared wordlist and stores it in a list that could be wiped must follow the same `"".join(word)` pattern and ship a regression test that wipes the list and asserts the global wordlist is still intact (see `tests/test_secure_delete.py::test_full_lifecycle_wordlist_integrity` for an example).

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

### On-device seed handling — removed

The firmware no longer manages seed material on-device. The previous
`models/seed.py`, `models/seed_storage.py`, `models/aezeed.py`,
`views/seed_views.py` and `views/psbt_views.py` are all gone. Private
key material lives exclusively on a Status Keycard or in a SeedKeeper
applet; the device only orchestrates.

**Do not re-introduce a `Seed` model** without first re-aligning the
threat model. The Keycard / SeedKeeper flows must keep their property
that no private bytes ever leave the smartcard.

<!-- Historical Seed-type table removed in the keycard-only refactor.
The codebase below this point talks to the Keycard / SeedKeeper
applets only. -->

#### Legacy Seed-type compatibility table (DELETED)

The codebase used to ship multiple seed types (see `src/seedsigner/models/seed.py`). They shared a `Seed` base class but differed in critical ways.

_All five classes (`Seed`, `XprvSeed`, `ElectrumSeed`, `AezeedSeed`, `Slip39Seed`) and the `seed_bytes` / `get_root(network)` contract are gone with the on-device seed manager._

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
| Encrypted QR password | ✅ NFKD | `Cipher.__init__()` in `kef.py` |
| Keycard pairing password | ✅ NFKD | `derive_pairing_secret()` in `helpers/keycard/crypto.py` |
| BIP-137 message body | UTF-8 only (no NFKD by spec) | `helpers/bitcoin/message_sign.message_digest()` |

When adding a **new** code path that derives keys or produces deterministic output from user-supplied strings, always NFKD-normalize the input before encoding to bytes. BIP-137 is the exception (the spec hashes the raw UTF-8 bytes).

### Date and numeric input
- When converting user-provided numeric strings use `try/except ValueError` around `int()` / `float()` instead of pre-checking with `.isdigit()`.  Python's `.isdigit()` returns `True` for non-ASCII Unicode digit characters (e.g. superscript `¹²³`) that `int()` / `float()` cannot convert, so the pre-check gives a false positive and the subsequent conversion raises `ValueError`.
- If an ASCII-only digit check is truly needed, combine `.isascii()` and `.isdigit()`, or test membership in `"0123456789"`.

### General rules
- Never rely on locale-dependent behaviour (`str.lower()` with Turkish İ, `strftime` with locale month names, etc.) for data that affects derivation, signing, or deterministic output.
- QR-scanned data, settings QRs, and file-imported data should all be treated as untrusted byte strings; decode as UTF-8 with error handling before further processing.
- When adding new user-input parsing, add tests that exercise at least one non-ASCII variant (e.g. a fullwidth digit, a non-ASCII dash) to catch locale-dependent regressions.
- Be aware that the same Unicode character can have multiple representations (e.g. `é` can be U+00E9 [NFC] or U+0065 U+0301 [NFD]). macOS file-system APIs and some input methods produce NFD; most other systems produce NFC. NFKD normalization collapses both forms into a single canonical byte sequence.

## Keycard-only firmware (Bitcoin + Ethereum)

This fork is a **Keycard / SeedKeeper-only** firmware: the on-device seed manager and the legacy PSBT signer were removed. All signing happens via a Status Keycard (or compatible JavaCard applet, e.g. cards initialised via `keycard-shell`). Both Bitcoin (BIP-84 P2WPKH, BIP-137 messages) and Ethereum (legacy / EIP-1559 / typed-data / personal-message) flows live under `Tools > Keycard`; SeedKeeper xprv storage stays under `Cards > SeedKeeper`.

The **Satochip-as-Bitcoin-wallet** flows (on-card PSBT signing, xpub-export-to-coordinator, descriptor load/save, the DIY JavaCard-applet builder) were removed along with the broken `seed_views` / `psbt_views` / `bip38` imports they carried — a reachability sweep from the live menu roots confirmed the whole subtree was already orphaned. The Satochip/SeedKeeper applet is now used **only** as a secret vault (`ToolsSeedkeeper*`: view / save-password / delete / clone secrets, free space). Regression guard: `tests/test_no_broken_view_imports.py`.

### Bitcoin module layout (added by the keycard-only refactor)

| Path | Responsibility |
|------|----------------|
| `src/seedsigner/helpers/bitcoin/` | Chain-agnostic primitives: `address` (P2WPKH bech32), `xpub` (build_hdkey / serialize_xpub / wpkh_descriptor), `message_sign` (BIP-137), `psbt_helpers` (wrapper over `embit.psbt.PSBT`: parse + extract + sighash + add_partial_signature), `ur_codec` (UR `crypto-psbt` / `crypto-account` encoders) |
| `src/seedsigner/helpers/keycard_btc_signer.py` | Bridge: `export_xpub(client, path)`, `sign_psbt(client, parsed)`, `sign_message(client, msg, path)`, `path_str_to_components`, `compress_pubkey`, `encode_der_signature` |
| `src/seedsigner/views/keycard_views.py` (Bitcoin section) | `ToolsKeycardBitcoinMenuView` + `ToolsKeycardBtcExportXpubView` + `ToolsKeycardBtcSignPsbtScanView` / `ReviewView` / `FinalizeView` + `ToolsKeycardBtcSignMessageStartView` / `ScanView` / `FinalizeView` + `ToolsKeycardBtcAddressesListView` / `AddressView` (paginated `m/84'/0'/0'/0/i` receive addresses, BIP-84-vector-tested, cached per-AID under the `<aid>:btc` key — same wipe rules as the ETH View-wallets cache) |
| `scripts/keycard_smoke_test.py --btc` | Hardware end-to-end: export xpub at `m/84'/0'/0'` + BIP-137 sign "test" at `m/84'/0'/0'/0/0` |

MVP scope: BIP-84 P2WPKH single-sig, mainnet only. Multisig P2WSH / wrapped P2SH (BIP-49) / taproot P2TR are deliberately out of scope; the module boundaries mirror `keycard-shell`'s input-type discriminator so they can be added without a refactor. PSBTs are capped at 40 inputs / 40 outputs.

Defaults: account path `m/84'/0'/0'` (`DEFAULT_BTC_ACCOUNT_PATH`), per-address default `m/84'/0'/0'/0/0` (`DEFAULT_BTC_PATH`). xpub export emits a neutral `xpub...` plus the canonical descriptor `wpkh([fp/84h/0h/0h]xpub.../<0;1>/*)` with the BIP-380 checksum.

### Ethereum module layout (pre-existing)

| Path | Responsibility |
|------|----------------|
| `src/seedsigner/helpers/ethereum/` | Chain-agnostic primitives: `rlp`, `keccak`, `address` (EIP-55), `tx_legacy` (EIP-155), `tx_eip1559`, `eip712` (exposes `domain_separator`, `message_hash`, `signing_hash`), `personal_sign`, `erc8213` (`compute_calldata_digest`: `keccak256(uint256_be(len) ‖ calldata)`), `ur_codec` (UR `eth-sign-request` / `eth-signature`) |
| `src/seedsigner/helpers/keycard/` | Card protocol: `commands` (APDU builders: SELECT, PAIR, OPEN_SC, VERIFY_PIN, DERIVE, EXPORT, SIGN, **GENERATE_MNEMONIC**, LOAD_KEY, GENERATE_KEY, FACTORY_RESET, …), `responses` (TLV/DER + `parse_generate_mnemonic`), `crypto` (PBKDF2/AES-CBC/ECDH), `secure_channel`, `client`, `reader` (PC/SC), `secrets` (CSPRNG PIN/PUK/password), `pairing_storage` (AES-GCM blob on microSD), `ui_helpers` (path/pubkey/PIN helpers shared by views) |
| `src/seedsigner/helpers/keycard_signer.py` | ETH glue: `signing_hash_for(request)` + `compute_v(request, rec_id)` |
| `src/seedsigner/views/keycard_views.py` | UI: `Tools > Keycard` menu, init/pair/unpair, **on-card Generate (Status applet GENERATE_MNEMONIC → host renders words → user confirms → LOAD_KEY)** + Show-mnemonic-and-import + **Import existing seed (SeedQR / 12-24 words / NGRAVE hex)** + **Seedkeeper backup at creation (this card / another card / both, installing the applet when missing)**, ETH sign chain (Overview → Details → **ERC-8213 Digest screen** → optional raw-data viewer → Finalize; digest screen shows Calldata Digest for txs with non-empty data, or three pages — EIP-712 Digest + Domain Hash + Message Hash — for typed-data; skipped for empty calldata and personal-sign), **Bitcoin sub-menu** (see above) |
| `scripts/keycard_smoke_test.py` | Hardware-only end-to-end check (SELECT → PAIR → SC → VERIFY_PIN → DERIVE → EXPORT → SIGN+recover; `--btc` adds export_xpub + BIP-137 sign_message) |

### Menu organisation (scope buckets)

The `Tools > Keycard` menu keeps the **daily-use** ops at the top and pushes
less-frequent management under a `Settings` submenu, so the common path is
short. Branches are still organised by the **scope** each acts on. The active
instance is shown as a readable **`Inst N`** label (`_format_instance_label`,
derived from the AID's trailing instance byte — *not* a user-assigned name)
in the title of every instance-scoped branch.

**Top-level `Keycard · Inst N`** (`ToolsKeycardMenuView`): `Ethereum`,
`Bitcoin`, `Switch instance`, `Lock card`, `Settings`.

| Branch | Scope | Entries |
|--------|-------|---------|
| `Ethereum` / `Bitcoin` (titled `· Inst N`) | active instance | sign / export with the instance key (Bitcoin also gets `View addresses` — BIP-84 receive list, mirroring ETH `View wallets`); `Connect software wallet` (xpub/account export) is the **last** entry in each |
| `Switch instance` | the *set* of instances | picks the active instance (`ToolsKeycardInstancesSwitchView`), then returns to the top menu. **Hidden when the card holds exactly one instance** — the menu reads `Controller.keycard_instance_count`, filled on menu entry by the **fast cleartext probe** `keycard_views._probe_keycard_instance_count` — a **bounded** probe (canonical 9-byte AID form only, **early-exit at the 2nd distinct slot**) that returns **1, or 2 meaning ≥2** (both consumers only need the `==1` boundary), never opening the GET-STATUS-over-ISD channel (the menu-entry stall). The bound keeps menu entry fast even though `MAX_KEYCARD_INSTANCES` is now **16** — the naive both-form full-range walk would be ~32 SELECTs; the exact, both-form census stays in the Switch / Create / Delete flows (and `_probe_keycard_instance_count_exact`, used by the Storage "≈N fit" estimate). The entry shows whenever the count is *not* exactly 1; `None` (→ entry shown) only on no card / probe error, so we never hide the only way to switch on a blank read. The **same count** also drives the `· Inst N` title suffix (see below). Switch / Create / Delete still refresh the count authoritatively. (The authoritative `_count_keycard_instances` GET-STATUS enumeration is currently **unused** — kept for reference; the menu deliberately uses the fast probe to honour the "no ISD on menu entry" performance contract.) **Safety invariant:** the bounded probe may *under*-count (→ `None`, which *shows* Switch — safe), but never reports exactly 1 when more exist (that would wrongly *hide* the only path to other instances). A legacy 10-byte single-instance card now under-counts to `None` (shows Switch + keeps the `Inst N` suffix) — a minor cosmetic regression, never a functional one |
| `Lock card` | cached card auth (all instances) | Drop cached PINs so the next op re-prompts (`ToolsKeycardLockView`) |
| `Settings` | mixed | container (`ToolsKeycardSettingsMenuView`) for the buckets below |

**`Settings`** (`ToolsKeycardSettingsMenuView`) → `Manage Instances` / `Manage Card`:

| Branch | Scope | Entries |
|--------|-------|---------|
| `Manage Instances` (titled `Manage Inst · Inst N`) | instances | `This instance ›`, Create instance, Delete instance. On first entry per boot a one-screen explainer (`Controller.keycard_instances_intro_shown`) describes what instances are, then the menu. (`ToolsKeycardInstancesMenuView`) |
| `This instance · Inst N` | active instance | **Safe per-instance management only** — Change PIN, **`Unblock PIN (PUK)`** (`ToolsKeycardUnblockPinView` — recovery for a blocked PIN: secure-channel session with `skip_pin_verify`, GET STATUS gate, PUK(12) + new PIN entry, INS 0x22; wrong PUK shows remaining retries, 0 PUK retries → factory-reset-only), **`Rename instance`** (gated — see Instance naming below), `Lock card`, and **`Set up / reset ›`** (the dedicated destructive submenu, last). The destructive key ops (Generate key, Import seed, Initialise instance, Factory reset) are **no longer** at this level — see `Set up / reset` below. (No `Pairing` entry — v3.2+ cards pair silently; the `ToolsKeycardPairingMenuView` / Pair / Remove-pairing views still exist for redirect flows but are not surfaced here.) |
| `Set up / reset · Inst N` | active instance | **All destructive key ops, grouped out of the daily path** (`ToolsKeycardSetupResetMenuView`): `Generate key`, `Import seed`, `Initialise instance` (runs INIT on this instance), `Factory reset`. Kept one level below `This instance` so the routine PIN / rename / lock path can't fat-finger a key-overwrite. |
| `Manage Card` | whole card / package | Status, Storage, Uninstall applet |

`This instance` is reached via `Settings ▸ Manage Instances ▸ This instance`,
and `Set up / reset` via `This instance ▸ Set up / reset`.
`Generate key` / `Import seed` are reachable both there and from the post-Init
chooser (`ToolsKeycardSetupChooseSeedView`). `Initialise instance` is the INIT
wizard (`ToolsKeycardInitView`) — it provisions **one instance**, so it lives
under `Set up / reset`, not `Card`. The view classes are
`ToolsKeycardThisInstanceMenuView`, `ToolsKeycardSetupResetMenuView`,
`ToolsKeycardPairingMenuView`,
`ToolsKeycardCardMenuView` (the old `Setup` / `Manage` / `Advanced` menus
were collapsed into these). Routing cover: `tests/test_keycard_views.py`,
`tests/test_keycard_setup_chain.py::TestSetupEntriesReachableAfterReorg`.

**Overwrite guard.** `Generate key` and `Import seed` warn explicitly before
replacing an existing key: a SELECT-only probe (`_instance_key_present`, reading
the unauthenticated `SelectResult.key_uid`) decides the warning text — `Replace
key?` ("Instance already holds a key …") when a key is loaded, or the generic
generate/transmission warning on a fresh / just-initialised instance. The probe
is **advisory only**: any failure (including no card) falls back to the generic
warning and lets the downstream flow surface the real card error, so the entry
views gain no new no-card branch. Cover:
`tests/test_keycard_views.py::TestKeycardMenuRouting` (`test_generate_key_overwrite_guard`,
`test_import_seed_overwrite_guard`, `test_overwrite_guard_probe_failure_falls_back_to_generic`).

`Lock card` (`ToolsKeycardLockView`) is reachable both from the **top-level**
Keycard menu (quick shortcut) and from `Settings ▸ Manage Instances ▸ This instance`. It calls
`Controller.wipe_card_session_secrets()` (drop all cached PINs + any Satochip
session), then the next operation re-prompts for the PIN. The label is
deliberately **neutral** — it must NOT reference duress/decoy/alt — because
re-entering a *different* PIN at that prompt is how the user reaches the on-card
decoy wallet (see [Duress (alt) PIN](#duress-alt-pin)). Cover:
`tests/test_keycard_views.py::TestPinLockLifecycle`.

`Factory reset` (`INS_FACTORY_RESET`) blanks **only the active instance**
on-card; the device-side cleanup is scoped to match — it drops just that
instance's pairing blob + cached pairing/PIN (by the UID seen at SELECT),
leaving other instances' pairings intact, and falls back to a full clear
only when the UID can't be determined. Cover:
`tests/test_keycard_views.py::TestFactoryResetCleanupScope`.

### Setup chain: Generate vs Show-mnemonic

The Setup wizard (`Tools > Keycard > Settings > Manage Instances > This instance > Generate key`) offers two
provisioning sub-flows. Both go through the same `LOAD_KEY` finaliser
so the *on-card* state is identical; they differ only in where the
entropy comes from and whether the host ever displays the words.

| Sub-flow | Where entropy is generated | Mnemonic shown? | When to use |
|----------|---------------------------|-----------------|-------------|
| **GENERATE MNEMONIC** (on-card) | Status applet's TRNG | No (default) — words exist only as indices in transit; host derives seed, sends LOAD_KEY, then `wipe_list()`s the buffer | Air-gapped, no paper backup desired |
| **Show + Import** | Host (`helpers/mnemonic_generation.generate_mnemonic_from_bytes`) | Yes — user copies the 12/24 words to paper, then confirms via quiz before LOAD_KEY | Air-gapped, user wants a paper backup |
| **Import existing seed** (`ToolsKeycardImportSeedView`) | Off-device | n/a — user supplies it | Restoring a known seed: **Scan SeedQR** (also accepts mnemonic-text and 4-letter QRs, any valid BIP-39 length), **Type words** (12/15/18/21/24 chooser), **Import hex (NGRAVE)**, or **From SeedKeeper** (read a backup off a Seedkeeper applet) |

The **Import hex (NGRAVE)** source takes the NGRAVE "Perfect Key" — the 256-bit BIP-39 *entropy* (64 hex chars = 24 words; 32 hex = 12 words) — via QR scan or the dedicated `0-9 a-f` keyboard (`KeycardHexEntryScreen`), runs it through `bip39.mnemonic_from_bytes`, then joins the **same** validate → derive seed64 → `LOAD_KEY P1=0x03` pipeline as the mnemonic import. The entropy buffer is wiped and words are independent copies (never `WORDLIST` references). The **Type hex** path first asks a key-length chooser (`24 words (64 hex)` default / `12 words (32 hex)`); the chosen length is passed as `KeycardHexEntryScreen(num_chars=…)`, which **caps** input at that length (via the new `KeyboardScreen.max_input_length`, distinct from the auto-return `return_after_n_chars`) and swaps the plain text field for a `GroupedHexEntryDisplay` (`gui/keyboard.py`) that shows all 32/64 slots up front, grouped in **blocks of 8** (`aabbccdd eeff0011 …`) for easy cross-checking against the backup. The post-Save validation enforces the **chosen** length (so a 24-word choice can't silently become a 12-word key); the **Scan QR** path is unchanged (no chooser, accepts 32 or 64). Cover: `tests/test_keycard_hex_import.py`.

The **From SeedKeeper** source is the *reverse* of the create-time Seedkeeper backup: it restores a seed stored on a Seedkeeper applet into the active Keycard instance. Because the two applets usually live on **different physical cards** (the iOS Seedkeeper app crashes when both share a card), it is a dedicated **swap chain** rather than part of the single-view push pipeline: `ToolsKeycardImportSeedkeeperInsertView` (swap in the Seedkeeper) → `…SelectView` (PIN via `init_satochip`, list **plaintext-exportable** BIP39/Masterseed-v2 secrets, export, decode via `seedkeeper_utils.decode_seedkeeper_seed_secret` → mnemonic + **stored passphrase**, validate checksum *while the Seedkeeper is still in the reader*, stash on the controller) → `…ReinsertView` (swap the Keycard back) → `…PushView` (derive with the stored passphrase, confirm master fp, `LOAD_KEY`). The **passphrase saved alongside the mnemonic is used as-is** so the restored Keycard reproduces exactly the backed-up wallet. Threat model: the decoded mnemonic + passphrase live in `controller.pending_keycard_mnemonic` / `pending_keycard_passphrase` (same store + `MainMenuView` wipe backstop as the backup chain) across the physical swap; wiped on success and every user-driven exit, but a **transient** failure (PIN cancel / no card / push error) keeps it (via `_import_seedkeeper_error_retry`) so the user can retry without re-reading the Seedkeeper. Seizure mid-import is a likely seed compromise (best-effort wipe). Words are independent `"".join(w)` copies (never `WORDLIST` refs). Cover: `tests/test_keycard_seedkeeper_import.py`; the full two-card swap needs hardware validation.

The mnemonic / passphrase are scrubbed on **success**, on a **user-driven exit** (Skip / Cancel / back at any chooser), and on `MainMenuView` re-entry. A **transient backup error does NOT wipe** them (see the backup section's retry rule below) — the only backup window must survive a recoverable failure. Regression cover: `tests/test_keycard_setup_chain.py`, `tests/test_keycard_hex_import.py`.

### Duress (alt) PIN

The Init wizard (`ToolsKeycardInitView`, `Tools > Keycard > Card > Initialise
card`) optionally sets a **duress PIN** — the Status applet's native **"alt
PIN"** feature (exactly what keycard-shell exposes). It is offered **after** the
main PIN+PUK and **before** the PUK-display screen as a single
`LargeIconStatusScreen` titled "Duress PIN" that explains the concept ("A 2nd
PIN that unlocks a decoy wallet instead of your real one. Settable only now,
never later.") and carries the **Skip** / **Set duress PIN** buttons.

**Skip still sets a *random* duress PIN (keycard-shell parity).** Picking
**Skip** (or backing out of the duress entry) does **not** fall back to the
applet's predictable PUK[:6] default — instead the view generates a random
6-digit duress PIN (CSPRNG via `kc_secrets.generate_pin()`, looped until it
differs from the main PIN) and sends the 58-byte form anyway. This mirrors
keycard-shell's `keycard_random_duress()` and means a Skipped card simply has
**no usable decoy** (nobody knows the random value) rather than a decoy openable
by anyone who learns the PUK's first 6 digits. Consequence: the 50-byte INIT
form is no longer emitted by the Init wizard in practice (the pure
`build_init_plaintext(..., duress_pin=None)` 50-byte path is retained for the
builder/tests only).

- **What it does:** entering the duress PIN at any later sign/export/unlock
  prompt transparently unlocks a **decoy wallet** — the applet routes
  `verifyPIN` to an **alternate chain code** over the *same* master key, so the
  *same* BIP-32 paths derive different (but valid) addresses. This is handled
  **entirely on-card**: there is **no host-side routing or derivation**, and no
  separate decoy seed. Whichever PIN the user types selects the real or decoy
  wallet automatically. Because each card can host multiple applet instances and
  each instance is INIT'd separately, the duress PIN is naturally **per-instance**.
- **Reaching the decoy without a factory reset / reboot.** The applet decides
  routing on *every* `verifyPIN`, but the host caches the verified PIN
  (`Controller.keycard_pins`) and re-sends it without re-prompting, so once you
  unlock with the **real** PIN every later op silently re-authenticates as the
  real wallet. To switch to the decoy, drop the cached PIN so the next op
  re-prompts, then type the **duress** PIN. Any of these does it: **Lock card**
  (`Tools > Keycard > Lock card`, instant and reader-independent), **switch the
  active instance**, or **remove / swap the card**. **Return to Home clears the
  cache only when `SETTING__CACHE_SCARD_PIN` is set to Disabled** — that is **not**
  the default (the default is now **Enabled**, so the PIN is reused across Home
  for fewer prompts). Previously only a factory reset or reboot cleared the
  cache. See [Threat model and memory hygiene](#threat-model-and-memory-hygiene).
- **Changed only from its own session — never cross-managed.** There is no
  *dedicated* change route for the alt PIN (`changePIN` P1 covers only PIN / PUK /
  pairing secret), so you **cannot manage the duress PIN from a main-PIN
  session** (and vice versa). But `changeUserPIN` does `pin.update(...)` on
  **whichever PIN authenticated the current session** (`pin` is set to `altPIN`
  by `verifyPIN` when you unlocked with the duress PIN), so the duress PIN **can
  be changed** by opening Change PIN and entering the *current duress PIN* as the
  "Current PIN", then a new one. Symmetrically the **main PIN is only changeable
  from a main-PIN session**. You cannot *add* a second alt slot nor *remove* the
  alt PIN — there is always exactly one (defaulting to PUK[:6]); only a Factory
  reset + re-init provisions one from scratch. `changePIN` also requires
  `pin.isValidated()` (a PIN must have been verified this session).
- **Must differ from the main PIN.** If they are equal the applet matches *both*
  and routes to the decoy (`verifyPIN` resp `== 3`), so **only the decoy is
  reachable until the two PINs are made distinct again**. This is *recoverable*,
  not fatal: `verifyPIN` re-decides routing on every unlock and the master key /
  `masterChainCode` are never touched, so changing the alt PIN to a distinct
  value restores main-PIN access (no factory reset needed). Note that in the
  collision state the shared value authenticates as the *alt* PIN, so a Change
  PIN there edits the **alt** PIN — exactly what breaks the collision. The
  applet itself does **not** reject `alt == main` at INIT (`processInit` has no
  such check), so the host rejects it in two places to avoid the footgun:
  `ToolsKeycardInitView` (re-prompts with a "Must differ" warning) and
  `commands.build_init_plaintext` (raises `ValueError`). The host **cannot**
  guard against a collision created *later* via Change PIN (it can never read the
  other PIN), so that remains the user's responsibility.
- **Applet's own default (we bypass it):** if an INIT *omits* the alt PIN
  (50/52-byte form) the applet defaults it to the **first 6 digits of the PUK**,
  derived once at INIT (a later PUK change does **not** re-derive it, though it
  can still be changed via the duress-session route above by authenticating with
  PUK[:6]). Our wizard never relies on this — it always sends an explicit alt PIN
  (user-chosen, or random on Skip) — precisely because the PUK[:6] default is
  predictable to anyone who learns the PUK.
- **Wire format:** setting an alt PIN forces the applet's **58-byte** INIT form
  `PIN(6) ‖ PUK(12) ‖ pairingSecret(32) ‖ maxPINAttempts(1) ‖ maxPUKAttempts(1)
  ‖ altPIN(6)` (the applet only accepts 50 / 52 / 58 byte payloads — there is no
  way to set the alt PIN without also sending the two attempt-limit bytes). The
  no-duress path still sends the byte-identical **50-byte** form. Assembled by
  `commands.build_init_plaintext(...)`; `init_encrypted` is unchanged (it only
  sees opaque ciphertext). The two attempt-limit bytes carry
  **maxPINAttempts** and **maxPUKAttempts**. The **PUK** limit is fixed at
  `DEFAULT_MAX_PUK_ATTEMPTS = 5` (matches `KeycardApplet.java`'s
  `DEFAULT_PUK_MAX_RETRIES`). The **PIN** limit is **user-configurable** via
  `SETTING__SCARD_PIN_ATTEMPTS` ("Smartcard PIN Attempts", default **3**,
  range 2..10): `ToolsKeycardInitView` reads it and forwards it to
  `client.init(..., max_pin_attempts=...)` → `build_init_plaintext` (the byte
  was already on the wire — the wizard always sends the 58-byte duress form —
  so this just makes it come from the setting instead of the hardcoded
  `DEFAULT_MAX_PIN_ATTEMPTS = 3`). The applet enforces **PIN ∈ 2..10** and
  **PUK ∈ 3..12** (`PIN_MAX_RETRIES` (10) / `PUK_MAX_RETRIES` (12) are the
  upper *bounds*, not defaults), so every setting value is valid on-card. The
  same setting also drives **Satochip/SeedKeeper** `card_setup`
  (`seedkeeper_utils.py`). Note the limit is baked in at INIT — **changing the
  setting does not retroactively alter already-initialised cards**; re-init
  (Factory reset) is required. `DEFAULT_MAX_PUK_ATTEMPTS` (and the
  `DEFAULT_MAX_PIN_ATTEMPTS` fallback for the builder/test 50-byte path) must
  **stay in sync with the applet**.
- **No version gate.** INIT runs against a *pre-init* applet whose SELECT returns
  `app_version == 0` / `capabilities == 0` (sentinel), so there is nothing
  reliable to gate on; the 58-byte form is supported across the applet 3.x line
  this fork targets, and an improbable rejection surfaces cleanly via
  `classify_card_error` (SW 0x6A80 / 0x6D00).
- **Memory hygiene:** the duress PIN bytearray is wiped on every exit path like
  the main PIN (outer `finally` in the view); the 58-byte INIT plaintext (which
  holds **both** PINs) is held in a `bytearray` and zeroed in `client.init`'s
  `finally` after encryption.

Regression cover: `tests/test_keycard.py::TestApduBuilders` (50- vs 58-byte
layout, `duress == main` rejection, length validation) and
`tests/test_keycard_views.py` (set / decline / equal-main re-prompt / cancel).

### SeedKeeper backup at key creation

Card creation is the **only** moment the host holds the seed — once `LOAD_KEY` seals it in the Keycard it can only be signed with, never read back. So immediately after `LOAD_KEY` (for both the on-card Generate and the Import paths) `ToolsKeycardSeedkeeperOfferView` offers to mirror the seed onto a Seedkeeper applet as a typed "BIP39 mnemonic" (iOS-compatible) secret — the **only** format, since it's the one the `From SeedKeeper` import can re-hydrate (a former "Password" / UTF-8 free-text option was dropped: it never round-tripped, so there's no format chooser anymore). The offer always hands off to `ToolsKeycardSeedkeeperDestChooserView`, which presents **three** destinations:

- **This card** — `ToolsKeycardSeedkeeperThisCardView` probes the inserted card; if no Seedkeeper applet is present it offers to **install** one via the shared `install_seedkeeper_applet()` helper in `views/view.py` (GP `gp.jar` install + the iOS-coexistence `DireWarningScreen` + storage chooser). A freshly-installed applet has no PIN; `seedkeeper_utils.init_satochip` runs `card_setup` (PIN prompt) inline at save time. Then save.
- **Another card** — `ToolsKeycardSeedkeeperSwapInsertView` prompts the user to swap in a *separate* Seedkeeper card, re-probes, then saves.
- **Both** — save to **this card** (install if needed) **and** a separate card. Tracked purely via the `remaining=["other"]` view-arg threaded into `ToolsKeycardSeedkeeperSaveRunView` (the `This card` / swap views route straight to it — no format chooser); after the first save succeeds the SaveRunView shows "Saved (1 of 2)" and routes to the swap flow **without wiping**, then the second save wipes and exits.

**Error vs. user-exit wipe rule (security tradeoff):** a *transient* backup failure (save error, capacity, probe failure, install failure, card removed) routes through `_backup_error_retry()` — it shows a Retry/Cancel screen and, on **Retry**, returns to the destination chooser **without wiping** the pending seed, so the user can recover the only backup window. The seed is wiped only on **success**, an explicit **Cancel** (back button), and the `MainMenuView` re-entry backstop. The one exception that still wipes immediately is "Seedkeeper unavailable" (pysatochip import failure — unrecoverable). Consequence: the seed (already sealed in the Keycard via LOAD_KEY) now lives in host memory across retries and across a same-card install / second-card swap within the wizard. Bounded to the wizard session; wipe is best-effort (CPython GC). Treat seizure mid-backup as a likely seed compromise.

The pending mnemonic survives card swaps on the controller. There is deliberately **no** path to read the seed back off the **Keycard** later — the backup window is creation-time only. (The reverse import — restoring a seed *from a Seedkeeper* into a Keycard — does exist; see the **From SeedKeeper** import source above. That reads the Seedkeeper, never the Keycard.)

### No-card UX in scan/sign flows

When a Keycard sign/export flow (ETH finalize, BTC export-xpub / PSBT review / PSBT finalize / message finalize) hits `NoCardError`/`NoReaderError`, it does **not** show the heavy `ErrorScreen`. Instead `_no_card_toast_or_error()` (in `keycard_views.py`) flashes the same subtle `InfoToast("Insert a card first")` the Cards menu uses and **stays** — re-entering the holding view (or `BackStackView`) so the user can insert a card and retry **without re-scanning**. Critically, the no-card branch must **not** null the scanned state (`eth_sign_request` / `psbt` / `btc_parsed_psbt` / the message view-arg) — that is what makes retry-without-rescan work. Any *other* exception still falls through to `classify_card_error` + `_error_destination(..., return_to_main=True)` as before. `KeycardCardChangedError` (a *swapped* card) now follows the **same retry-without-rescan principle**: the primary sign/export finalize handlers (ETH verify/finalize, BTC export-xpub / PSBT review+finalize / message finalize) keep the scanned state and route via `_pair_then_resume(...)` → `ToolsKeycardPairView(next_destination=…)`, which on a successful pair **resumes the originating step** (both hops carry `skip_current_view`, so the back stack ends up as if the pairing detour never happened). They no longer null `eth_sign_request` / `psbt` / `btc_parsed_psbt`. Setup/import flows still route to `ToolsKeycardPairView` without an explicit resume.

### Protocol compatibility — DO NOT change without coordinating with existing cards

Cards initialised by `keycard-cli` / `keycard-shell` ship with very specific protocol parameters. The constants below are deliberately matched to that convention; **changing any of them breaks every previously-paired card.**

| Parameter | Value | Source |
|-----------|-------|--------|
| Applet AID (`commands.APPLET_AID`) | `A00000080400010101` (9-byte canonical, slot 1) | The **SELECT first-try / default-active** target, hard-coded in `commands.py`. Now the **9-byte canonical** form `A000000804000101 + 0x01` — the same form *created* instances use (blank-card install **and** `_next_free_instance_aid`; see "AID conventions" below) and what real Status cards / keycard-cli use, so the first SELECT on a fresh card hits the instance with no probe. `select_with_autodetect` still probes the **10-byte legacy** form (`…010101`, minted by older builds) so previously-created cards resolve via one extra `0x6A82` + probe. The smoke test's bare `client.select()` now probes both forms on `0x6A82` too. **Migrated from the 10-byte legacy default — hardware-verify every SELECT path (smoke test + blank-card install + legacy card) before merging further changes here.** |
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

### Coexistence with SeedKeeper on the same card

The Seedkeeper iOS app (`Toporin/Seedkeeper-iOS`) **crashes on the secret-reveal step** when the Keycard package (`A0000008040001`) is loaded on the same physical card as the SeedKeeper applet — even if only the signing instance is created and the NDEF / Cash / Ident applets are skipped. Verified hands-on: the SeedKeeper blob on the card is byte-perfect (`[len|pw_utf8|0x00|0x00]`) and the on-device firmware reads it fine; the iOS app loads the secret *label* and then exits the process on Reveal. Deleting only the Keycard package (`gp.jar --delete A0000008040001 -force`, leaving the SeedKeeper applet and secrets intact) restores iOS reveal immediately.

We can't fix this from inside SeedSigner (it's an iOS-side issue, in code we don't control). The mitigation is a **non-blocking heads-up**: before installing either applet on a card that already has the other (in both `CardsInstallAppletView` and the Keycard backup's `install_seedkeeper_applet`, `src/seedsigner/views/view.py`), we flash a subtle `InfoToast` (`_toast_ios_coexistence`) reading *"iOS Seedkeeper may crash"* and continue — the install is **not** gated (no extra screen, no back-to-cancel). It was a blocking `DireWarningScreen` before; it was too invasive (it fires correctly even for an *uninitialised* Keycard instance, since the iOS crash depends only on the Keycard **package** being present, not on init state). The toast is suppressed when the probe can't read the card. Tests: `tests/test_cards_install_and_wipe.py::TestCrossAppletCompatibilityWarning`.

**Pre-install free-space check (`_warn_if_low_space`).** Both install paths run a *soft* low-space warning. It reads the card's real free NV (`query_card_memory` → GlobalPlatform `GET DATA 0xFF21`) and compares it against `required_nv_for_install(kind, store)`. The required size is the applet's **real on-card footprint** — `real_nv_footprint(kind)` = the `.cap` file size scaled by `CAP_NV_FOOTPRINT_RATIO` (0.70), because the `.cap` over-estimates the loaded EEPROM footprint by ~1.3-1.5× (it bundles Debug/Descriptor/Export components stripped at load). Without the ratio the check false-positived on a card that already holds the Keycard package (the install really fits). A `LOW_SPACE_MARGIN_BYTES` (2048) tolerance avoids borderline warnings. The SeedKeeper **Select Storage** chooser (a `DescriptionButtonListScreen`) shows the card's free space as *"Free: X KB"*, and the read `CardMemory` is threaded into `_warn_if_low_space(..., mem=...)` to avoid a second card round-trip. `CAP_NV_FOOTPRINT_RATIO` is hardware-calibratable (free-before/after a real install); the same ratio feeds `estimated_used_nv` (the `Storage` view's occupation bar) for consistency. Tests: `tests/test_keycard_storage.py::TestWarnIfLowSpace` / `TestSizeHelpers`.

If you investigate this further, the next things to check upstream are (a) whether the iOS app does any AID enumeration / Card Manager GET DATA tag that returns differently with the Keycard package loaded, and (b) whether reducing the Keycard CAP footprint (e.g. installing a stripped variant without the NDEF/Cash applets baked in) is enough. As of this writing, neither has been tested.

### Pairing persistence on microSD

`helpers/keycard/pairing_storage.py` writes a single file:

- **Path:** `<MicroSD>/keycard_pairing.bin` (resolved via `MicroSD.get_microsd_dir()`).
- **Format:** `[version:1] [salt:16] [nonce:12] [tag:16] [ciphertext:N]`. Plaintext payload: `pairing_index ‖ pairing_key(32) ‖ instance_uid_len ‖ instance_uid`.
- **Encryption:** AES-256-GCM. Key derived from the user's pairing password via PBKDF2-HMAC-SHA256, 50000 iter, with a **separate domain salt** (`b"Keycard Pairing Storage v1"` ‖ random 16 bytes) so the on-disk key is not the same as the on-card pairing secret.
- **Card binding:** the persisted `instance_uid` is checked against the SELECT response on load; a blob from another card is rejected before any card APDU is sent.
- **Atomic writes:** `save()` writes to `*.tmp` then `os.replace`s; chmod 0o600 best-effort (vfat ignores).

The user enters the pairing password **once per boot**. The decrypted pairing key is cached in `Controller.keycard_pairing` (a `PairingInfo`) for the session and is dropped on `Tools > Keycard > Forget saved pairing` or unpair.

### Threat model and memory hygiene

- **PIN cached per-instance, but droppable on demand.** The verified PIN is held in `Controller.keycard_pins` — a dict keyed by `instance_uid`, values are `bytearray` (`controller.py`, helpers `get_pin_for` / `set_pin_for` / `forget_pin_for` / `forget_all_pins`). After the first VERIFY_PIN, subsequent operations on the same instance re-use the cached value **without re-prompting** (`open_unlocked_session`, `ui_helpers.py`). The cache is dropped on **all** of:
  - **return to Home** *only* when `SETTING__CACHE_SCARD_PIN` is Disabled (`controller.py` MainMenu wipe) — **no longer the default**: the default is now **Enabled** (PIN reused across Home for fewer prompts), so a swap/removal — not Home — is the routine drop trigger;
  - the **Lock card** action (see below) — `wipe_card_session_secrets()`;
  - **active-instance switch** (`ToolsKeycardInstancesSwitchView` → `forget_all_pins()`);
  - any op **observing `NoCardError`/`NoReaderError`** — reader-independent backstop in `_no_card_toast_or_error`;
  - the PC/SC **`removed`** event (`card_monitor.py` → `wipe_card_session_secrets()`);
  - a **card/instance swap detected synchronously at SELECT** — the shared primitive `detect_card_swap(controller, instance_uid)` (`ui_helpers.py`) compares the freshly-SELECTed `instance_uid` against `Controller.last_authenticated_keycard_uid` and, on a change, calls `wipe_card_session_secrets()` **before** the new card is used. It does **not** itself set `last_authenticated_keycard_uid` (that marker means "we hold an authenticated session"; only `open_unlocked_session` sets it after VERIFY_PIN), so it is safe to call from unauthenticated probes. This is the **reader-independent** backstop for the unreliable PC/SC `removed` event (notably on NFC/PN532 via ifdnfc). It fires at **three** choke-points, so a swapped card never leaves the previous card's secrets (or its cached addresses) lingering: (1) every authenticated op via `open_unlocked_session`; (2) **every Keycard menu entry** via `card_probe.run_card_gate` — reusing the SELECT the card probe already did, so **zero extra card I/O** (directly answers "when re-entering the Keycard menus, verify the inserted card matches"); (3) the **`View wallets` / `View addresses` warm-cache path** via `verify_active_card_unchanged` (a cheap SELECT-only check built on `identify_inserted_card` + `detect_card_swap`) — without this, those views serve straight from `keycard_wallets_data` *without* opening an authenticated session, so a swapped card would otherwise show the **previous card's cached addresses**; a swap there wipes the cache and the view re-runs (`skip_current_view`) to re-derive for the new card. The marker is **distinct** from `last_keycard_uid` (which enumeration/name-resolution mutate) and is cleared by `forget_all_pins()`. It does **not** catch *same-card* remove+reinsert (identical `instance_uid`) — **Lock card** is the manual re-auth path for that;
  - a **bad PIN** (SW=0x63CX), which drops that UID's entry before propagating.
  The Lock / instance-switch / no-card / synchronous-swap wipes are **intentionally NOT gated** on `SETTING__CACHE_SCARD_PIN` — they fire even when caching is Enabled, otherwise a swapped card would keep the previous card's secrets in RAM and the duress wallet would stay unreachable for power users. **Migration:** the default is now **Enabled** (reuse PIN across Home, dropping only on swap/removal/Lock/instance-switch/wipe-timer); flipping the default only affects fresh installs / never-set keys, so a user with a persisted settings file keeps whatever `cachepin` value they already saved. Either way they are protected by the ungated wipes above.
- **Derived addresses die with the PIN cache.** `forget_all_pins()` (and therefore every wipe trigger above that routes through it — Lock card, card removal, return-Home, instance switch, wipe-timeout) **also clears `controller.keycard_wallets_data`**, the per-AID cache of ETH "View wallets" addresses. This is required for the duress property: the decoy wallet derives the *same* BIP-32 paths against an alternate on-card chain code, so the host has no way to tell real from decoy addresses apart by inspection — the only safe rule is that derived addresses are valid **only** for the duration of one authenticated PIN session. Without this, locking and re-entering the duress PIN would re-prompt but still display the *real* wallet's cached addresses. The cache is **also** invalidated per-AID after `GENERATE_KEY` / `LOAD_KEY` (key change) and on instance delete. The scanned ETH `eth_sign_request` / `eth_signature` are **not** cleared by the PIN wipe — they are scanned input / results (not key-derived) and must survive the no-card retry-without-rescan path.
- **Card-specific name state dies on swap.** `wipe_card_session_secrets()` (the PC/SC `removed` event) also clears `controller.keycard_aid_to_uid`, `controller.keycard_instance_names`, and `controller.last_keycard_uid`. These are not secrets, but they are *card-specific*: a swapped card reuses the same AIDs (`…0101`, …) with different `instance_uid`s, so a stale AID→UID mapping would resolve the new card's instance to the **previous** card's name. Clearing them forces a fresh SELECT-time re-resolution against whatever card is now inserted. (Name resolution never trusts `last_keycard_uid` — see the Instance-naming section.)
- **Lock card (reach the decoy without a reset).** `Tools > Keycard > Lock card` (also under `This instance`) calls `wipe_card_session_secrets()` so the **next** operation re-prompts for the PIN. This is the supported, reader-independent way to re-authenticate with a **different** PIN — including the **duress (alt) PIN** to reach the on-card decoy wallet — with **no factory reset / reboot**. The label is deliberately neutral: no UI string may reference duress/decoy/alt (preserving the stealth property). See [Duress (alt) PIN](#duress-alt-pin).
- **Pairing password never cached.** Captured into a `bytearray`, NFKD-normalised, used to derive both the on-card secret and the on-disk storage key, then the bytearray and the intermediate normalised string are wiped (best-effort — see below).
- **Pairing key cached.** As above: held in memory until the user exits the session or chooses "Forget saved pairing".
- **Wipe is best-effort.** `helpers/secure_delete.wipe_string()` and our `wipe_bytearray()` (and the in-place zeroing of the cached PIN bytearray) cannot defeat Python's GC, copy-on-write inside CPython, or the C runtime's allocator. **Assume any value that exists in memory at the moment of physical seizure is recoverable** — including the cached PIN, which now persists across operations until one of the wipe triggers above fires. Mitigation: short-lived sessions, Lock card / Home between operations, no debug logging of secrets.
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

### Multi-instance management (GlobalPlatform / SCP02)

Multiple Keycard applet instances can live on the same physical card, each with its own AID, `instance_uid`, PIN, pairing slots and master key. SeedSigner manages them via `Tools > Keycard > Settings > Manage Instances` (plus the top-level `Switch instance`, shown only when >1 instance exists).

**Pre-conditions:**

- The Status Keycard **package** (`A0000008040001`) is loaded on the card. Retail Status Keycards and any card the user previously initialised satisfy this. The **instance** flows here (create / delete / switch) only `INSTALL [for install]` a new instance from an already-loaded package — they do **not** load the `.cap`. A **blank** card is handled separately by `CardsInstallAppletView` (`views/view.py`, reached via `run_card_gate` when the applet is missing): it does `gp.jar --delete A0000008040001 -force` → `--load Keycard-3.2.cap -force` → `--create A00000080400010101` (9-byte canonical slot-1, == `commands.APPLET_AID`). The `.cap` is **shipped in the seedsigner-os image** under `<microsd>/javacard-cap/` (the build downloads + SHA256-verifies the official `keycard_v3.2.cap`), so the device *can* provision a blank JavaCard — given the default ISD keys below (the `--load`/`--create` go over SCP02 with them).
- The card's **ISD keys** are still the GlobalPlatform defaults (`404142434445464748494A4B4C4D4E4F` for ENC, MAC, DEK). Cards with rotated keys are not supported yet; the user would need to introduce them via a future "custom ISD keys" flow.

**Protocol (`helpers/keycard/global_platform.py`):**

| Step | APDU | Notes |
|------|------|-------|
| SELECT ISD | `00 A4 04 00 …` | Tries `A000000003000000` (Visa) then `A000000151000000` (Mastercard) |
| INITIALIZE UPDATE | `80 50 00 00 08 [host_chal] 00` | Response 28 bytes: 10 KDV + 1 KVN + 1 SCP id + 2 seq counter + 6 card chal + 8 card cryptogram |
| Session keys | 3DES-CBC(IV=0) over `derivation_const(2) ‖ seq(2) ‖ zeros(12)` | S-ENC `0182`, S-MAC `0101`, S-DEK `0181` (we don't currently use S-DEK) |
| Card cryptogram check | `last8(3DES-CBC(S-ENC, host_chal ‖ seq ‖ card_chal ‖ pad80))` | Computed and compared before sending anything authenticated |
| EXTERNAL AUTHENTICATE | `84 82 01 00 10 [host_cryptogram(8)] [CMAC(8)]` | Security level 0x01 = C-MAC only (no C-ENC) |
| Subsequent commands | `84 INS P1 P2 (Lc+8) [data] [CMAC]` | Retail MAC (ISO 9797-1 alg 3, padding method 2). ICV chains: next ICV = single-DES-encrypt(prev MAC, K1_MAC) |

**Why C-MAC only:**

The commands we send (`INSTALL [for install]`, `DELETE`, `GET STATUS`) carry no secret payload — INSTALL contains AIDs and install parameters, DELETE contains a target AID, GET STATUS is a query. Adding C-ENC over 3DES-CBC would only add code volume without raising security against an attacker who already has physical card access.

**AID conventions:**

- Status applet binary (prefix): `A000000804000101` (`KEYCARD_APPLET_AID`, 8 bytes).
- **Two instance-AID forms exist in the wild, and the slot index is always the
  last byte of both:**
  - **9-byte canonical** `prefix + slot` (e.g. `A00000080400010101`) — what
    keycard-cli / keycard-shell and real Status cards use. **This is the form
    SeedSigner now mints for EVERY instance**: the blank-card install
    (`view.py` `_KEYCARD_CREATE_COMMANDS` → `--create A00000080400010101`,
    slot 1, == `commands.APPLET_AID`) **and** subsequent instances
    (`_next_free_instance_aid`, next free slot).
  - **10-byte legacy** `prefix + 0x01 + slot` (e.g. `A0000008040001010101`) —
    minted by older SeedSigner builds; **no longer created**, only *accepted*
    (probe/label) for back-compat with cards already in the field.
- `_next_free_instance_aid` computes occupied slots from the **last byte** of
  **every** prefix-matching AID regardless of length, mints the **9-byte**
  next-free slot, and never returns an AID that already exists. (The old code
  only recognised the 10-byte form, so on a real 9-byte card it judged slot 1
  free and re-minted slot 1, colliding with the existing instance **and
  stealing the boot-default slot** — that was the bug, fixed before this
  9-byte unification.)
- Both forms are SELECT-probed everywhere via one shared builder,
  `global_platform.keycard_instance_aid_candidates` (consumed by
  `select_with_autodetect`, `probe_keycard_instance_aids`, and `card_probe`),
  so an instance of either convention is always found and the three probe
  sites can't drift apart again.
- `_format_instance_label` renders `Inst N` (N = last byte) for **both** forms.
  A 9-byte and a 10-byte AID at the same slot therefore share an `Inst N`
  label, so destructive screens (Delete) additionally show the **full AID**
  (`_format_aid_short` no longer truncates ≤12-byte AIDs) — the label alone is
  not a safe delete key.
- Each instance generates its own random `instance_uid` at INIT time, so the per-UID pairing storage in `helpers/keycard/pairing_storage.py` Just Works for multi-instance setups — no schema change needed.

**Manage Instances menu** (`Tools > Keycard > Settings > Manage Instances`, titled `Manage Inst · Inst N`): `This instance ›` / `Create instance` / `Delete instance`, preceded once per boot by a one-screen explainer (`ToolsKeycardInstancesMenuView`). There is **no** standalone "List instances" view anymore — `Switch instance` (its own top-level entry, `ToolsKeycardInstancesSwitchView`, **hidden when only one instance**) is the read-out of the instance set. Every list renders instances by the readable **`Inst N`** label (`_format_instance_label`, derived from the AID's trailing instance byte — falls back to short-AID hex for non-instance AIDs). `Switch instance` shows only **Keycard-prefixed** instances (filtered by `KEYCARD_APPLET_AID`), never other applets (e.g. SeedKeeper).

**Instance naming (microSD plaintext file).** An instance can be given a user name via `This instance ▸ Rename instance` (`ToolsKeycardThisInstanceRenameView`). The name is stored in a **standalone plaintext JSON file** `helpers/keycard/instance_names.py` → `<microSD>/keycard_instance_names.json`, an object mapping `fingerprint(instance_uid)` → name (the fingerprint, not the raw UID, is the key). Names are **not** secret, and crucially the file is **independent of the pairing blob** — v3.2+ cards pair *ephemerally* (nothing about the pairing touches disk), so a blob-stored name would never persist; a standalone file works for **every** card because it only needs the `instance_uid` from SELECT. Naming is **gated** on `SETTING__PERSISTENT_SETTINGS == Enabled` **and** a microSD present (`instance_names.is_enabled()` / `_instance_rename_available()`) — *no* ephemeral exclusion; otherwise the entry is hidden and the instance stays `Inst N`. No pairing password is involved. The name (NFC-normalised, ≤16 chars) is read **lazily** the first time a title needs it, via `Controller.get_instance_name_for_aid` → `instance_names.get_name`, and cached (incl. `None`) in `Controller.keycard_instance_names` (UID-keyed). The AID→UID map (`Controller.keycard_aid_to_uid`) is the link between an instance's AID and the UID its name is keyed by; it is populated by **every** SELECT (centralised in `select_with_autodetect` → `remember_aid_for_uid`) **and** by enumeration (`_resolve_instance_uids` SELECTs each listed AID — cheap, unauthenticated, ≤4 — in `_count_keycard_instances` and `ToolsKeycardInstancesSwitchView`). The map, the name cache, **and** `last_keycard_uid` are all card-specific and cleared on card-change (`forget_pairing_for` / `forget_all_pairings` / `wipe_card_session_secrets`) so a re-inserted/swapped card never renders the previous card's name. Menu titles render via `_instance_title_suffix(controller)` → the cached custom name, or `Inst N` **only when the card holds >1 instance** (dropped when exactly one — see "Single-instance title suppression" below), or *nothing* (bare title). The `Switch` / `Delete` **row** labels and destructive `Wipe {}?` confirmations still use `_instance_display_name(controller, aid)` → cached name or `Inst N` (always a concrete identifier, never suppressed). **Privacy tradeoff (flagged):** the name is plaintext on the microSD — same exposure class as `settings.json`; do not put duress/decoy hints in a name. **Name resolution resolves the UID *only* via `keycard_aid_to_uid`** — `get_instance_name_for_aid` must **never** fall back to `last_keycard_uid` (the globally-last-SELECTed UID), which belongs to whatever instance was touched last and would bleed one instance's name onto another (the historical "merge" bug — fixed). An AID with no resolved UID shows `Inst N`. Because enumeration now resolves every listed instance's UID, the `Switch instance` list and menu titles show real names for **all** instances, not just the active one; the only residual `Inst N` fallback is a failed SELECT or naming gated off. Factory-reset of an instance regenerates its UID and calls `instance_names.remove_name`, so the name clears.

**Ordering / id / default (so the UI is not surprising).** The active instance is **not** persisted: it resets to the Status published AID `…0101` (`commands.APPLET_AID`) on **every** boot. `Inst N` is the AID's **trailing byte** — a physical applet *slot*, reused after a delete (`_next_free_instance_aid` fills the smallest free slot), **not** a user identity. `Switch instance` list order is whatever `GET STATUS` reports. `Create instance` **auto-activates** the new instance (sets `active_keycard_aid` to the freshly-installed AID), so the menu title immediately reflects it and the announced "Run Init next" targets the new (uninitialised) instance directly — without the switch, the Init wizard's `select_with_autodetect` would first-try the previous, already-initialised instance and bail with "Already initialised". `Rename instance` renames the **active** instance — switch to the instance you mean before renaming it (its current name now shows in the `This instance · {name}` title to make the target explicit).

The `pairing_storage` label trailer is back to its prior state (always empty; read-compat only — `StoredPairing.label` is `None`). Cover: `tests/test_keycard_instance_names.py`, `tests/test_keycard_views.py` (naming-present / display-name / menu-gating / rename happy-path / no-Pairing-entry).

**Active instance for the session:**

- `Controller.active_keycard_aid` (defaults to the published Status AID) is the AID we SELECT for every Keycard operation. The Instances flow lets the user switch it.
- The active instance is surfaced as the readable **`Inst N`** label in the **main Keycard menu title** (`Keycard · Inst N`), in every instance-scoped submenu title (`Ethereum · Inst N`, `Bitcoin · Inst N`, `This instance · Inst N`, `Set up / reset · Inst N`, `Pairing · Inst N`, `Manage Inst · Inst N`), in the address-list tags (`Wallets ({})` / `Addresses ({})`), and marked with a leading `» ` in the `Switch instance` view, so the user always knows which instance signing/export will use.
- **Single-instance title suppression.** When the card holds **exactly one** instance (`Controller.keycard_instance_count == 1`), the `· Inst N` / `(Inst N)` suffix is **omitted** from every instance-scoped title — there is nothing to disambiguate, so the auto label is noise. This is centralised in `_instance_title_suffix(controller)`, which returns: a **user-assigned custom name** (always shown, even with one instance → e.g. `Keycard · Cold`); else `None` when the count is exactly 1 (caller renders the bare title — `Keycard`, `Ethereum`, …); else the `Inst N` label (count >1 **or** unknown `None` — never drop identity on a guess). The destructive `Wipe {}?` confirmation is deliberately **excluded** (it keeps a concrete identifier, mirroring the Delete row's full-AID rule). Cover: `tests/test_keycard_views.py` (`test_instance_title_suffix`, `test_main_menu_title_drops_label_for_single_instance`, `…keeps_custom_name…`, `…probe_one_hides_switch…`).
- After DELETE, if the deleted AID was the active one we fall back to the default. After INSTALL, the new AID **becomes active automatically** (`ToolsKeycardInstancesCreateView` sets `active_keycard_aid = new_aid`), so the next step (Init / Generate / Import) targets the instance the user just created without a manual switch.

**Memory-aware instance limit (how many instances fit).** `MAX_KEYCARD_INSTANCES` (now **16**, raised from 4) is a *firmware* ceiling — bounds the slot byte and the management-flow probe range — **not** a hardware one. Whether another instance actually fits is a free-space estimate, since the card reports only **free** NV (GET DATA 0xFF21 via `query_card_memory`), never total or per-instance usage:
  - **Per-instance estimate** (`views.view.keycard_instance_nv_estimate`): `KEYCARD_INSTANCE_NV_ESTIMATE_BYTES` (conservative **3 KB** default, **hardware-calibratable** like `CAP_NV_FOOTPRINT_RATIO` — measure free-NV before/after a real create+init and set it to the delta) **unless** a card-specific measurement exists. An *instance* costs ~1–2 KB (INSTALL shell + INIT/key allocation), **not** the ~30 KB applet *package* — the package is loaded once and shared (`INSTALL [for install]` instantiates from it).
  - **Self-calibration:** `ToolsKeycardInstancesCreateView` reads free NV over the open GP channel before/after INSTALL (`_safe_channel_free_nv`, best-effort — GET DATA 0xFF21 is publicly readable, but some cards reject un-MAC'd reads post EXTERNAL-AUTHENTICATE, in which case the estimate is skipped) and stashes the sanity-bounded delta in `Controller.keycard_measured_instance_nv` (`_record_instance_nv_measurement`, accepts 256..16384 B). It's card-specific → cleared on swap (`wipe_card_session_secrets`), so the constant is the durable default.
  - **`estimate_remaining_instances(free_nv, current_count, per_instance, ceiling)`** = `min(ceiling − current_count, (free_nv − LOW_SPACE_MARGIN_BYTES) // per_instance)` (the 2 KB margin absorbs the small key-growth the INSTALL-delta misses). `free_nv None` (tag unreadable) → slot headroom alone.
  - **UX:** the create-confirm shows `≈{N} more fit`; the Storage view (`ToolsKeycardStorageView` → `KeycardStorageScreen.remaining_instances`) shows `≈{N} more instances fit` (using `_probe_keycard_instance_count_exact` for the real count). When the estimate says **no room** (`remaining <= 0`, and free NV was readable) the create flow shows a soft `DireWarningScreen` ("Card may be too full / for another instance") with a **"Create anyway"** override — never a hard block (fragmentation/per-object overhead make the estimate advisory; install failure is handled by `classify_card_error`). The hard ceiling (16) is the only hard block. Cover: `tests/test_keycard_storage.py::TestInstanceNvEstimate` / `TestEstimateRemainingInstances`, `tests/test_keycard_views.py::TestCreateInstanceMemoryGate` / `TestProbeInstanceAidsKnobs`.

**Threat-model additions:**

- Anyone in physical possession of the card AND the ISD keys can install/delete applets at will. There is no authenticated channel for "the user" beyond the ISD secret. If the user hands a card to someone with default keys still set, that person can wipe it.
- The C-MAC alone provides integrity and replay protection within a session, but not confidentiality. INSTALL/DELETE payloads are observable on a malicious reader (they're already public AIDs, so no leakage of user secrets either way).
- This module **never** signs or imports seed material. It does not import from `seedsigner.models.seed*` or `seedsigner.helpers.keycard.crypto`. Bug or break in `global_platform.py` cannot affect signing flows.

## Stealth boot mode

This fork supports an optional "stealth boot" mode controlled by two settings (default OFF, hidden from the Settings UI under Advanced):

| Setting | Default | Purpose |
|---------|---------|---------|
| `SETTING__STEALTH_BOOT` | `False` | When `True`, the device boots into a **games console** (instead of `MainMenuView`) |
| `SETTING__STEALTH_UNLOCK_SEQUENCE` | `""` (empty) | CSV of `HardwareButtonsConstants` names; the sequence the user must press to exit the console and start the firmware. Empty by default — the user must record a custom combo (via `Tools > Stealth boot > Edit`) before the firmware lets them enable stealth mode |

### Games console architecture

Stealth boot no longer launches a single hard-coded game. `Controller.start()` runs **`StealthConsole().run()`** (`src/seedsigner/stealth/console.py`), which shows a **game-select menu** and dispatches to one of several mini-games; on game-over it returns to the menu. The pieces:

| Module | Responsibility |
|--------|----------------|
| `stealth/console.py` (`StealthConsole`) | Owns everything shared: the **input thread**, the **`UnlockBuffer`** (fed every key pressed *anywhere* — menu or any game — so the secret combo always exits straight into the firmware), the **panic exit**, the game registry (`GAMES`), the game-select menu, and the `_play` loop. Raises/catches `StealthGameExit` to leave. |
| `stealth/base.py` (`BaseStealthGame`) | The per-game contract: `name`, `reset(w,h)`, `tick_ms` (`None` = turn-based), `step()`, `handle_key(key, btn) -> bool`, `alive`, `score`, `draw_frame()`. The console drives these; `render` / `render_game_over` are shared. |
| `stealth/snake.py` (`SnakeGame`) | Snake. **Walls wrap** (modulo) — leaving one edge re-enters the opposite edge; the only death is self-collision. |
| `stealth/game_2048.py` (`Game2048`) | 2048, **turn-based** (`tick_ms is None`); D-pad slides/merges, new tile after any changing move, game-over when no move remains. |
| `stealth/tetris.py` (`TetrisGame`) | Tetris on a 10x18 well; gravity via `tick_ms`, line clears, game-over on spawn collision. |
| `stealth/dino.py` (`DinoGame`) | One-button endless runner; UP/KEY_PRESS jumps, distance = score, speeds up. |

**Controls inside a game:** each game uses the D-pad / KEY_PRESS for play; a single **KEY1** press returns to the console menu (the handheld "menu" button — it is still fed to the unlock buffer first). Real-time games (`tick_ms` set) advance on a timer; turn-based games (`tick_ms is None`) only redraw after an input that changed something.

### Rules

- **The stealth module (`src/seedsigner/stealth/`) MUST NOT import from `seedsigner.models.seed*`, `seedsigner.helpers.keycard*`, or any module that touches secrets.** Enforced by `tests/test_stealth_import_guard.py` (scans every `*.py` in the package) and the package docstring. `console.py` may read/write only the two stealth settings via `Settings` (lazy import).
- **No persistence from the games.** No high score, no resume state. The settings file holds only the toggle and the unlock sequence. (The panic exit is the one write — it flips `STEALTH_BOOT` back to `Disabled`.)
- **No visual hint** that the unlock sequence is being matched. Showing partial progress would defeat the "looks like a game" property for a casual observer.
- **Resolution-aware.** Games read `Renderer.canvas_width` / `canvas_height` and centre their grid via `BaseStealthGame._layout`; do not hard-code 240x240 or 320x240 — both are valid hardware configurations.
- **Panic exit** (documented here, not in UI): holding `KEY1 + KEY2 + KEY3` for 10 s — in the menu *or* any game — disables `STEALTH_BOOT` and exits into the firmware. Use this if a user enables stealth mode and then loses their unlock sequence. (Best-effort: it reads the live GPIO state, so it never fires on a platform that doesn't expose individual pin reads.)
- **Adding a game:** subclass `BaseStealthGame`, add it to `StealthConsole.GAMES`, and ship a unit test plus coverage that the new module passes the import guard. The view layer (`Tools > Stealth boot`) needs no change — the menu is built from `GAMES`.

### Where the boot hook lives

`Controller.start()` checks `SETTING__STEALTH_BOOT` *before* the OpeningSplashView and runs `StealthConsole().run()`. When it returns (unlock sequence matched, or panic), the rest of the boot continues normally — splash, dev/desktop warnings, MainMenu. The session is then indistinguishable from a non-stealth boot.

The `Tools > Stealth boot` management screen (`ToolsStealthBootView`) carries a short inline description — *"Boots into a games console. Your combo reveals the wallet."* — rendered via `DescriptionButtonListScreen` (a `ButtonListScreen` subclass with a description `TextArea`, mirroring `SettingsEntryUpdateSelectionScreen`).
