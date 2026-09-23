# Documentation Screenshot Capture

Captures the fork's smartcard screens for the user documentation, driving the **real
Views and Screens** against **real JavaCard applets running in jcardsim**. So a card
info screen shows the applet's actual UID and versions, the free-space screen shows
the applet's real answer, a sealed Satodime address is genuinely derived by the
applet, and so on.

The non-card screens (menus, password generator, microSD) are rendered by the normal
screenshot generator instead: `tests/screenshot_generator/generator.py`.

## Requirements

Same as the jcardsim test suites:

- A JDK 11+ (`java` and `javac` on `PATH`).
- Applet source checkouts discoverable via `SEEDSIGNER_APPLET_ROOT` (defaults to
  `~/Documents/GitHub`): `Satochip-DIY`, `Seedkeeper-Applet` (with its `sdks`
  submodule), and `status-keycard` (which provides `jcardsim-3.0.5-SNAPSHOT.jar`).

See `.github/workflows/tests.yml` for the exact clone commands.

## Running

The capture is opt-in and skipped by the normal suite. Point `SEEDSIGNER_DOCS_OUT` at
the directory the images should land in:

```bash
# Windows / PowerShell
$env:SEEDSIGNER_DOCS_OUT = "docs/img/guide"
python -m pytest tests/docs_screenshots -v --tb=short
```

```bash
# Linux / WSL
SEEDSIGNER_DOCS_OUT=docs/img/guide python -m pytest tests/docs_screenshots -v --tb=short
```

Images are written to `docs/img/guide/<topic>/NN_<ScreenClassName>.png`. Each topic
directory is cleared once per run, so re-running regenerates a stable set. Without
`SEEDSIGNER_DOCS_OUT` the directory is ignored entirely; without Java/applet sources
each test skips with a reason.
