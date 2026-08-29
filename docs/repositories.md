# Repository Layout & Release Pairing

SeedSigner (this repository) and SeedSigner-OS are separate Git repositories that work together to produce the official release images. This document explains the relationship, how releases are paired, and how to obtain the complete source tree for auditing or reproducible builds.

## Two-Repository Architecture

| Aspect | SeedSigner (this repo) | SeedSigner-OS (submodule) |
|--------|------------------------|---------------------------|
| **Primary contents** | Application code (`src/seedsigner/`), UI, cryptography, QR handling, wallet logic, tests, desktop sim | Buildroot external tree, board defconfigs, post-build/post-image scripts, Docker build harness, OS-level hardening, Luckfox Pico SDK integration |
| **Language** | Python 3 | Shell, Make, Buildroot Kconfig/Config.in, Dockerfile |
| **Release artifacts** | PyPI package (optional), source tarball | Signed disk images (`.img`, `.img.zip`), rootfs tarballs, SBOM |
| **CI workflow** | `tests.yml` (unit/integration), `build-buildroot.yml` (dispatches to OS), `build-luckfox.yml` (dispatches to OS) | `build.yml` (Buildroot), `build-luckfox.yml` (Luckfox), reusable workflows |
| **Canonical upstream** | `SeedSigner/seedsigner` (official project) | `SeedSigner/seedsigner-os` (official project) |
| **This fork's remote** | `3rdIteration/seedsigner` (smartcard fork) | `3rdIteration/seedsigner-os` (smartcard fork of OS) |

### Fork Topology

```
SeedSigner/seedsigner (official)          SeedSigner/seedsigner-os (official)
        │                                        │
        ▼                                        ▼
3rdIteration/seedsigner  ◄── submodule pin ──  3rdIteration/seedsigner-os
    (this repo, smartcard fork)                 (this repo's OS fork)
```

- This repository is a fork of the official SeedSigner application, adding Satochip/Smartcard support and other features.
- The submodule points to `3rdIteration/seedsigner-os`, which is **a fork of the official `SeedSigner/seedsigner-os`**.
- **Release tags only exist on the forks**: the tags used for official images (`SeSi-0.8.x+ShSi-Bnn`, older `SS*+Satochip+Earthdiver-Bn`) are created on `3rdIteration/seedsigner-os`. The official upstream repos do not carry these tags.
- Documentation (README, PR template) links to the official org repos for discoverability; the submodule pins the exact fork commits that produced the shipped images.

## Build Composition

Official images are built by the CI workflows in this repository:

1. **`build-buildroot.yml`** (Pi, La Frite):
   - Checks out `3rdIteration/seedsigner-os` into a fresh workspace (`path: seedsigner-os`).
   - Passes `--app-repo=<this repo URL>` and `--app-commit-id=<sha>` (or `--app-branch`) to `opt/build.sh`.
   - Inside the Docker container, `opt/build.sh` clones the app repo at the given ref **with `--recurse-submodules`** (to pull `seedsigner-translations` for `.mo` compilation).
   - Buildroot compiles the OS + app into a single image.

2. **`build-luckfox.yml`** (Luckfox Pico):
   - Calls the reusable workflow `3rdIteration/seedsigner-os/.github/workflows/build-luckfox.yml@main`.
   - That workflow runs `opt/luckfox/prepare-app-checkout.sh`, which also clones the app repo **with `--recurse-submodules`** and runs `git submodule update --init --recursive`.

Both paths therefore **recurse into this repository's `.gitmodules`**. The `seedsigner-os` submodule entry here is configured with `update = none` (see below) so that the recursive clone **skips it entirely** — avoiding:
- Cloning the OS repo a second time inside the build container.
- Recursing into the OS repo's own nested `opt/buildroot` submodule (hundreds of MB).
- Accidentally shipping OS source or Buildroot toolchain inside the final image.

The `seedsigner-translations` submodule (required for runtime translations) is fetched normally and compiled into the image.

## Release Pairing Rule

**Each application release corresponds to exactly one SeedSigner-OS release tag.** The submodule pointer in this repository is updated **only at release time** to the OS tag that was used to build the images uploaded to that release.

### Current Pin

| This Repo Release | Submodule Commit | OS Tag | OS Commit |
|-------------------|------------------|--------|-----------|
| 0.8.7 (pending)   | `6a9433a32d588cafbfbc94e9dd93d3abdaa1d806` | `SeSi-0.8.7+ShSi-B12` | `6a9433a32d588cafbfbc94e9dd93d3abdaa1d806` |

(Update this table when the pin moves.)

### Bump Procedure (at Release)

```bash
# 1. Ensure you're on the release branch/tag of this repo (e.g. main at the release commit)
git checkout main

# 2. Inside the submodule, check out the matching OS release tag
git -C seedsigner-os fetch --tags
git -C seedsigner-os checkout SeSi-X.Y.Z+ShSi-Bnn   # use the exact tag for this release

# 3. Stage the updated gitlink
git add seedsigner-os

# 4. Commit with a clear message
git commit -m "chore: pin seedsigner-os to SeSi-X.Y.Z+ShSi-Bnn for release X.Y.Z"

# 5. Tag this repo's release (e.g. X.Y.Z) and push; CI will build images using the pinned OS commit
```

**Do not** run `git submodule update --remote` or casually advance the pointer outside of a release. The pin is the audit linkage between the app release and the OS tree that produced its images.

## Audit Quickstart

### Browse on GitHub (no clone needed)
1. Open this repository on GitHub.
2. Click the `seedsigner-os/` directory in the file tree — GitHub renders the pinned commit's file listing directly (driven by `.gitmodules` URL).
3. Click through into `opt/buildroot/` — you will see the Buildroot fork at the pinned commit (the OS repo's own submodule is also clickable on GitHub).

### Full Local Source Tree

```bash
# Clone this repo (submodules not initialized by default)
git clone https://github.com/3rdIteration/seedsigner.git
cd seedsigner

# Initialize ONLY the OS submodule (small, ~few MB)
git submodule update --init seedsigner-os

# Optional: also fetch the Buildroot toolchain for full toolchain audit
git -C seedsigner-os submodule update --init opt/buildroot
```

**Why `update = none`?** The `.gitmodules` entry for `seedsigner-os` carries `update = none`. This means:
- `git clone --recurse-submodules` (or CI's `actions/checkout submodules: recursive`) **will not** fetch it.
- `git submodule update --init --recursive` from the superproject **will skip it**.
- You must explicitly request it: `git submodule update --init seedsigner-os`.
- This keeps default clones and CI fast, avoids pulling the nested Buildroot fork unintentionally, and still allows auditors to fetch the complete tree with one explicit command.

### Verifying a Shipped Image

Every SeedSigner-OS image bakes a provenance marker at `/etc/seedsigner-os-release` (see `src/seedsigner/helpers/seedsigner_os.py`). On a running device:

```bash
cat /etc/seedsigner-os-release
```

Output example:
```
SEEDSIGNER_OS_REPO=3rdIteration/seedsigner-os
SEEDSIGNER_OS_BRANCH=main
SEEDSIGNER_OS_COMMIT=6a9433a32d588cafbfbc94e9dd93d3abdaa1d806
SEEDSIGNER_OS_DATE=2026-08-21 15:04:14
SEEDSIGNER_APP_REPO=3rdIteration/seedsigner
SEEDSIGNER_APP_BRANCH=dev
SEEDSIGNER_APP_COMMIT=abcdef123456...
SEEDSIGNER_APP_DATE=2026-08-25 12:00:00
```

Match `SEEDSIGNER_OS_COMMIT` to the submodule gitlink in this repo at the release tag, and `SEEDSIGNER_APP_COMMIT` to the release tag of this repo. This is the cryptographic linkage that makes the build **reproducible and auditable**.

## Reproducible Builds

See the SeedSigner-OS repository's [`docs/building.md`](https://github.com/3rdIteration/seedsigner-os/blob/main/docs/building.md) for step-by-step instructions to rebuild an image from source and verify its hash matches the published release.

## Submodule Configuration Reference

Current `.gitmodules` snippet for `seedsigner-os`:

```ini
[submodule "seedsigner-os"]
	path = seedsigner-os
	url = https://github.com/3rdIteration/seedsigner-os.git
	update = none
```

- `update = none` is **load-bearing**: it prevents recursive clones (CI, `git clone --recurse-submodules`) from descending into this submodule and its nested `opt/buildroot`. Removing it would re-break OS image builds by pulling Buildroot into every build container.
- No `branch =` key is set intentionally — release pins are explicit tags, not a moving branch.

## Related Documentation

- `docs/code_structure.md` — application code architecture
- `docs/hardware_platform_support.md` — board/SoC matrix and which OS profiles build for each
- SeedSigner-OS: `docs/building.md`, `docs/build_profiles.md`, `docs/structure.md`