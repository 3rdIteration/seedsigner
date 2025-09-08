# GPG Tools

SeedSigner includes tools to interact with GPG. When `gpg2` is available on the host system, the Tools menu offers a **Load BIP85 Key** option. This feature deterministically derives a keypair (NIST P-256, Brainpool P-256, RSA 2048, RSA 3072, RSA 4096, or secp256k1) from the currently loaded seed using [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#user-content-RSA_GPG) and imports it into GPG. Selecting RSA 2048, RSA 3072, or RSA 4096 displays a warning that generation on a Pi Zero may take about 3 minutes, 15 minutes, or an hour respectively; NIST or Brainpool keys are faster and smaller.

In addition to verifying detached signatures, the **Sign** submenu offers two workflows. Selecting **File** prompts for a file on the microSD card and a private key from the local GPG keyring; a detached signature (`.sig`) is saved alongside the original file.

Choosing **Manifest** creates a `sha256.txt` file listing each file's SHA256 hash and signs it in one step, saving both `sha256.txt` and `sha256.txt.sig` to the same microSD folder. The manifest uses the same format as the `sha256sum` utility so it can be verified with the existing **Verify File Sig** workflow. When the `sha256sum` utility isn't available (such as on Windows), SeedSigner calculates the hashes internally for both manifest creation and verification so the workflow still works.

Additional menu options can export existing GPG keys. Public keys are written to the microSD card in ASCII armor, while private keys are first exported and then symmetrically encrypted with a user-provided passphrase before being saved.

The **Advanced** submenu offers more key management through **Subkey Operations**. **Add Subkeys** attaches three new subkeys—encryption, authentication, and signing—to an existing primary key, with the user selecting the key type (NIST P-256, Brainpool P-256, RSA 2048/3072/4096, secp256k1, or Ed25519). If the primary key was derived via BIP85, these additional subkeys are deterministically derived via BIP85 and continue from the last subkey index. Other options can revoke or delete existing subkeys, change their expiration, or export up to three selected subkey secrets (one signing, one encryption, one authentication) as a passphrase-protected armored file, animated QR, or directly onto a smartcard.

For SeedSignerOS, everything is stateless. If running on desktop or some other normal system, you will be interacting with your system GPG2 install...

During import, SeedSigner prompts for the key type, user name, email address, and expiration date. The expiration defaults to **the end of 2029 for RSA 2048 keys and the end of 2035 for all other key types**. (Noting that NIST guidelines have RSA2048 deprecated in 2030 and non-quantum safe keys, including ECC keys, being discontinued for government applications after 2035)

Note: The key derivation with BIP85 is deterministic, meaning the key and fingerprint will always be the same, but metadata like the username, email address and expiration date can be changed. (And are not saved on-device, but can be exported to a Smartcard, etc)

Existing GPG keys can also be exported. After selecting a key, SeedSigner offers to save the ASCII-armored public key either to the microSD card or directly to a connected Seedkeeper smartcard. On Seedkeeper, the key is saved as ASCII-armored text so it can be copied and pasted easily.

## SmartPGP Applet Installation

SeedSigner can install the [SmartPGP](https://github.com/ANSSI-FR/SmartPGP) applet onto a JavaCard via the **Smartcard Tools → Satochip DIY → Install Applet** menu. When a SmartPGP CAP file is selected, SeedSigner now generates a random 4‑byte serial number and embeds it into the application identifier (AID) during installation, following the [flexsecure applet procedure](https://github.com/DangerousThings/flexsecure-applets/blob/master/docs/applets/1-pgp.md).

