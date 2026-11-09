# ForgeBox offline firmware signing

**Tools → ForgeBox Signing** can recover a dedicated signing key from a loaded
seed using BIP85, export its public key, and sign firmware or registration
requests transferred by microSD. It supports mnemonic-backed seeds and XprvSeed
through `seed.get_root()`. No private key or WIF is exported.

Install the paired SeedSigner OS change providing
`/usr/lib/seedsigner/secure-boot/forgebox_sign.py`. The menu hides when that
module is absent. The app loads only trusted OS code, never code from the card.
Desktop development can set `SEEDSIGNER_SECURE_BOOT_DIR` to the OS checkout's
`opt/luckfox/secure-boot` directory.

1. Load the intended root/passphrase. Choose **Export BIP85 Public Key**, select a
   dedicated index and record the displayed `m/83696968'/2'/index'` path and public
   key. Restore independently and repeat export before enrolling that key.
2. Keep a trusted PC copy of the exported `pubkey.pem`. The OS repository's PC
   helper compresses a full firmware image with official forgebox-cli 1.2.0 and
   writes a small request to `forgebox-signing/request.json` on the card.
3. Choose **Sign Request on Card**, review the digest-only warning and both
   hashes, select the same root/index, compare the public key and confirm Sign.
4. Return the card. The PC helper verifies `response.json` against the trusted
   public key, original image and unchanged unsigned package, then assembles the
   signed OTA. It will not overwrite an existing output.

The OS helper can also hold a factory USB session open while SeedSigner signs a
registration proof of possession. This keeps the private key off the PC during
initial enrollment too. Physical registration/nonce lifetime are untested; the
adapter is covered with an injected device. Enrollment is once per device
lifetime, so verify the seed/passphrase/index recovery and device display first.

This signs hashes; it cannot inspect firmware or vouch for the build PC. It
does not flash a device or implement JavaCard/secure-element key storage.
Pure-Python ECDSA and Python memory management do not provide constant-time
execution or guaranteed secret erasure. Keys remain short-lived local objects,
are not cached/logged/written, and all cancel/error paths drop their references.

The complete commands, build pairing, threat assumptions and validation status
are in the OS repo's
[ForgeBox offline signing guide](https://github.com/3rdIteration/seedsigner-os/blob/feat/forgebox-offline-signing/docs/forgebox-offline-signing.md).

For a paired image build, select the OS PR branch and this app's exact commit
using the existing build workflow/app-ref inputs. Keep the app's `seedsigner-os`
release gitlink unchanged until the paired release is cut.
