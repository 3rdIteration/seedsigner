# Legacy JavaCard applets (test fixtures)

Prebuilt CAP files for **superseded** applet versions, flashed by the
hardware-in-the-loop suite so that cross-version compatibility is actually
exercised rather than assumed.

| File | Upstream release | Size | sha256 |
|---|---|---|---|
| `SeedKeeper-0.1-0.1.cap` | [Toporin/Seedkeeper-Applet `v0.1`](https://github.com/Toporin/Seedkeeper-Applet/releases/tag/v0.1) | 71495 | `341d043f…b727ac` |

Files are byte-identical to the upstream release asset and keep its filename
verbatim, so "v0.1" names one specific, checkable build. `javacard-cap-legacy.sha256`
pins them, and `tests/test_javacard_cap_manifest.py` verifies that manifest on every
ordinary test run (no card reader needed).

## Why these are not in `javacard-cap/`

Two reasons, both load-bearing:

1. `ToolsDIYInstallAppletView` globs every `*.cap` in the repo's `javacard-cap/`
   (`_get_internal_cap_dir()` in `src/seedsigner/views/smartcard_views.py`) into the
   on-device **Install Applet** picker. A superseded applet there would sit one tap
   away from users.
2. The OS image build copies the repo to `/opt`, **keeps** `javacard-cap/` and
   **prunes** `tests/` (`seedsigner-os/opt/luckfox/build-local.sh`). Test fixtures
   belong on the pruned side.

`test_javacard_cap_manifest.py` asserts a legacy CAP never also appears in
`javacard-cap/`, so this rule is enforced rather than merely documented.

## Why a v0.1 SeedKeeper is worth testing

Issue #413: a DIY card could read but not write. `seedkeeper_get_status` (INS 0xA7)
answered 0x6D00, which blocked the capacity pre-check; once that was tolerated the
card answered 0x9C01 (`SW_NO_MEMORY_LEFT`) on import. The card was running a v0.1
applet, and the hardware suite only ever flashed v0.2.

Differences that matter, read from the upstream source at tags `v0.1` and `v0.2-0.1`:

| INS | v0.1 | v0.2 |
|---|---|---|
| 0xA3 | commented out → 0x6D00 | `GENERATE_RANDOM_SECRET` |
| 0xA5 | `RESET_SECRET` exists, but `resetSecret()` throws `SW_UNSUPPORTED_FEATURE` (0x9C05) right after the PIN check | `RESET_SECRET` (works) |
| 0xA7 | Shamir import, commented out → 0x6D00 | `GET_SEEDKEEPER_STATUS` |
| 0xA8 | commented out → 0x6D00 | `EXPORT_SECRET_TO_SATOCHIP` |
| 0x3F | absent → 0x6D00 (no NDEF) | NDEF get/set |

- v0.1's `OM_SIZE` is a `final` 0xFFF (4095 bytes) and its `install()` discards the
  install parameters, so **v0.1 ignores `application_specific_parameters`**. v0.2 made
  `OM_SIZE` overridable, which is why the v0.2 fixture installs with `"1FFF"` (8191).
- Because 0xA5 does not work, a full v0.1 card **cannot** be freed by deleting a
  secret — only a factory reset or a re-flash recovers it. That is what
  `seedkeeper_utils.describe_seedkeeper_error()` tells v1 users.
- Both versions report **applet** version 0.1; only the **protocol** minor version
  differs (v0.1 → 0.1, v0.2 → 0.2). That is the sole discriminator, and it is what
  `seedkeeper_utils.is_seedkeeper_v1()` keys on.

## Adding another legacy version

1. Download the prebuilt CAP from the upstream release; keep the asset filename verbatim.
2. Drop it here and append `<sha256>  <filename>` to `javacard-cap-legacy.sha256`.
   `test_javacard_cap_manifest.py` fails if you forget the line, or if the file also
   landed in `javacard-cap/`.
3. Subclass the current suite in `tests/test_smartcard_hardware.py`, overriding **only**
   class attributes: `CAP`, `CAP_DIR_FIXTURE = "legacy_cap_dir"`, `INSTALL_PARAMS`
   (`None` if the applet ignores install params), `APPLET_LABEL`,
   `EXPECTED_PROTOCOL_MINOR`, one `SUPPORTS_<capability>` flag per instruction the
   suite's *teardown* depends on, and re-declare `_connector = None`.
4. Override an inherited test only when its **expected outcome** differs, and write the
   override as a positive assertion on the older behaviour (`assert sw == 0x6D00`) rather
   than an `xfail` — an `xfail` that starts passing on a future applet is silent noise.
5. Add one regression test per instruction the older applet lacks, asserting both the raw
   status word and what `describe_seedkeeper_error()` renders for it.
6. Define the subclass immediately after its parent, and put destructive tests last in
   the class body. Do **not** add `@pytest.mark.order(-1)`: that means last in the
   *session*, which would run it after the class teardown has already uninstalled the
   applet.
