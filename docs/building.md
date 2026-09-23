# Building SeedSigner OS Images

SeedSigner runs on a minimal, purpose-built Linux image called **SeedSigner OS**. It is built with [Buildroot](https://buildroot.org) and is an order of magnitude smaller than a stock Raspberry Pi OS image — the whole system is loaded into RAM at boot, so the microSD card can be removed once the splash screen appears.

The OS lives in a separate repository, included here as the [`seedsigner-os/`](https://github.com/3rdIteration/seedsigner-os) git submodule and pinned per release (see [Repositories and releases](./repositories.md)).

## Two build pipelines

| Hardware family | Toolchain | Reference |
|---|---|---|
| Raspberry Pi / Libre Computer La Frite | Mainline Buildroot (the `opt/buildroot` submodule) | [OS repo `docs/building.md`](https://github.com/3rdIteration/seedsigner-os/blob/main/docs/building.md) |
| Luckfox Pico (`RV1103` / `RV1106`) | Rockchip Luckfox Pico vendor SDK, with SeedSigner injected | [OS repo `docs/luckfox/README.md`](https://github.com/3rdIteration/seedsigner-os/blob/main/docs/luckfox/README.md) |

A dispatcher at the OS repo root routes to the right pipeline:

```bash
./build.sh --pi0 --smartcard --dev                  # Raspberry Pi / La Frite
./build.sh --luckfox build --microsd --model mini   # Luckfox Pico
```

## Quickstart (Docker, reproducible build)

Prerequisites: Docker (Desktop or Engine) and `git`. On Windows, WSL2 is recommended.

```bash
git clone --recursive https://github.com/3rdIteration/seedsigner-os.git
cd seedsigner-os

export DOCKER_DEFAULT_PLATFORM=linux/amd64
export BOARD_TYPE=pi0
export RELEASE_TAG=x.y.z          # e.g. 0.8.7

git checkout $RELEASE_TAG
git submodule init
git submodule update

SS_ARGS="--$BOARD_TYPE --app-repo=https://github.com/3rdIteration/seedsigner --smartcard" \
  docker compose up --force-recreate --build
```

A build takes roughly 25 minutes to 2.5 hours and needs 20–30 GB of free disk space. The finished image is written to `images/` along with its SHA256 hash — this hash should match the published release image for the same tag and board, which is how reproducible builds are verified.

## Board configs

| Board | Image name | Build option |
|---|---|---|
| Raspberry Pi Zero / Zero W | `seedsigner_os.<tag>.pi0.img` | `--pi0` |
| Raspberry Pi 2 Model B | `seedsigner_os.<tag>.pi2.img` | `--pi2` |
| Raspberry Pi Zero 2 W / Pi 3 | `seedsigner_os.<tag>.pi02w.img` | `--pi02w` |
| Raspberry Pi 4 Model B | `seedsigner_os.<tag>.pi4.img` | `--pi4` |
| La Frite (AML-S805X-AC) | `seedsigner_os.<tag>.lafrite.img` | `--lafrite` |
| Luckfox Pico (Mini / Pro Max / Pi) | `opt/luckfox/build-output/` | `--luckfox --model mini\|max\|pi\|both` |

## Build variants

- **Smartcard** (`-smartcard`) — adds the NFC reader stack, JavaCard crypto tools and DIY tooling needed for the smartcard features. Recommended if you are unsure which to pick.
- **Dev** (`-dev`) — adds networking (SSH, git, curl, WiFi), a writable rootfs and a MicroSD source override so the app can be run from source. Much less secure — never use it with real funds.
- **Non-dev** — hardened, air-gapped production image (no networking, HDMI or serial console; read-only rootfs on Luckfox).

The full matrix — dev vs non-dev, smartcard vs non-smartcard, and per-platform kernel config — is documented in the OS repo's [`docs/build_profiles.md`](https://github.com/3rdIteration/seedsigner-os/blob/main/docs/build_profiles.md).

## Building without Docker / customizing

- [Building without Docker](https://github.com/3rdIteration/seedsigner-os/blob/main/docs/without_docker.md)
- [Customizing Buildroot](https://github.com/3rdIteration/seedsigner-os/blob/main/docs/customize_buildroot.md)
- [SeedSigner OS structure](https://github.com/3rdIteration/seedsigner-os/blob/main/docs/structure.md)

## Development

- [SeedSigner OS dev workflow](https://github.com/3rdIteration/seedsigner-os/blob/main/docs/dev_workflow.md) — interactive Docker container (`--no-op`), and SSH/WiFi access to dev images
- [Raspberry Pi OS build instructions](./raspberry_pi_os_build_instructions.md) — running the app on a standard Raspberry Pi OS install
- [Development device setup](./dev_device_setup_instructions.md)
- [Desktop simulation](./desktop_simulation.md) — run SeedSigner on a regular PC
- [Developer tips](./developer_tips.md) and [code structure](./code_structure.md)

## CI builds

`build-buildroot.yml` and `build-luckfox.yml` in this repository dispatch the OS repo's reusable workflows to build images. Every pull request gets a development image built automatically, downloadable from the PR checks.
