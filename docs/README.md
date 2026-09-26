# SeedSigner + Satochip Documentation

This directory documents the extra features this fork adds on top of stock SeedSigner,
with a focus on smartcards, plus the quick-start guides most users need and documentation
for building, developing and assembling your own hardware.

New to the smartcard features? Start with the
[applet reference](./javacard_applets.md) to decide what to install, then the relevant
quick start below.

## Quick starts

| Guide | What it walks you through |
|---|---|
| [01 – Install applets on DIY JavaCards](./quickstarts/01-install-applets-diy-javacard.md) | Preparing a card and flashing SeedKeeper (and friends) |
| [02 – Mnemonic to a SeedKeeper](./quickstarts/02-mnemonic-seedkeeper.md) | Create a seed, save it, load it back |
| [03 – Multisig descriptor to a SeedKeeper](./quickstarts/03-multisig-descriptor-seedkeeper.md) | Load, save and reload a descriptor |
| [04 – Initialise a Satochip with a seed](./quickstarts/04-satochip-init-with-seed.md) | Seed a Satochip and export an xpub |
| [05 – Password generator to a SeedKeeper](./quickstarts/05-password-generator-seedkeeper.md) | Generate a password and store it on a card |
| [06 – First-time DIY card setup](./quickstarts/06-diy-card-first-time.md) | GlobalPlatform keys and locking a card |
| [07 – SLIP-39 backup](./quickstarts/07-slip39-backup.md) | Split and store SLIP-39 shares |
| [08 – BIP85 child seed](./quickstarts/08-bip85-child-seed.md) | Derive a child wallet from a parent |
| [09 – SeedQR backup](./quickstarts/09-seedqr-backup.md) | Transcribe a seed to a SeedQR |
| [10 – Flash a MicroSD card](./quickstarts/10-flash-microsd.md) | Flash and verify a SeedSigner image in-app |

## Feature reference

### Smartcards
- [Bundled JavaCard applets](./javacard_applets.md) — what each CAP is, which to install
- [Smartcard integration and installation](./smartcard_support_installation.md) — readers, wiring, build prerequisites
- [SeedKeeper](./seedkeeper.md)
- [Satochip](./satochip.md)
- [Keycard](./keycard.md)
- [Satodime](./satodime.md)
- [Specter-DIY](./specter_diy.md)

### Seeds and backups
- [Multisig descriptors](./multisig_descriptors.md)
- [SLIP-39 shares](./slip39.md)
- [BIP85 child seeds](./bip85.md)
- [Seed QR formats](./seed_qr/README.md)
- [Dice verification](./dice_verification.md)
- [Electrum seeds](./electrum.md)
- [WIF and BIP38 signing](./wif_bip38.md)

### Tools
- [Password Generator](./password_generator.md)
- [Text QR Code tool](./text_qr.md)
- [MicroSD Tools](./microsd_tools.md)
- [GPG Tools](./gpg_tools.md)
- [GPG trusted signers](./gpg_trusted_signers.md)
- [BIP85 GPG version history](./bip85_gpg_version_history.md)

### Hardware
- [Shopping list](./shopping_list.md) — what to buy, including store links
- [Hardware shopping and assembly](./hardware.md) — platform/board options, cases and assembly
- [Hardware platform support](./hardware_platform_support.md)
- [IO config](./io_config.md)
- [Battery](./battery.md)
- [Legacy hardware](./legacy_hardware.md)

### Building and development
- [Building SeedSigner OS images](./building.md)
- [Raspberry Pi OS build instructions](./raspberry_pi_os_build_instructions.md)
- [Development device setup](./dev_device_setup_instructions.md)
- [Repositories and releases](./repositories.md)
- [Desktop simulation](./desktop_simulation.md)
- [Developer tips](./developer_tips.md)
- [Code structure](./code_structure.md)

## SeedSigner OS documentation

The operating system that runs on SeedSigner devices lives in the separate
[seedsigner-os](https://github.com/3rdIteration/seedsigner-os) repository. Its docs are
mirrored into this site at build time, pinned to the same OS commit this release is built
against. They cover how OS images are built, verified and hardened — useful for users
flashing or reproducing official images, and for OS development as a secondary focus.

- [Building an SD card image](./os/building.md) — reproducible-build quickstart and board configs
- [Build profiles](./os/build_profiles.md) — dev vs non-dev and smartcard profiles
- [Reproducibility](./os/reproducibility.md) — verifying a build matches the published image
- [DIY tools](./os/diy_tools.md)
- [Hardware RNG (hwrng)](./os/hwrng.md) — how hardware entropy reaches the app
- [Repository structure](./os/structure.md)
- [Development workflow](./os/dev_workflow.md) — faster docker cycles, dev configs, SSH
- [Building without Docker](./os/without_docker.md)
- [Customizing Buildroot](./os/customize_buildroot.md)
- [Luckfox Pico build & development](./os/luckfox/README.md) — including
  [secure boot](./os/luckfox/secure-boot.md),
  [verifying a release](./os/luckfox/verifying-a-release.md) and
  [airgapped signing](./os/luckfox/airgapped-signing.md)
