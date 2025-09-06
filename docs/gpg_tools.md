# GPG Tools

SeedSigner includes tools to interact with GPG. When `gpg2` is available on the host system, the Tools menu offers a **Load BIP85 Key** option. This feature deterministically derives a keypair (NIST P-256, Brainpool P-256, RSA 2048, RSA 3072, or secp256k1) from the currently loaded seed using [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#user-content-RSA_GPG) and imports it into GPG.

In addition to verifying detached signatures, the **Sign** submenu offers two workflows. Selecting **File** prompts for a file on the microSD card and a private key from the local GPG keyring; a detached signature (`.sig`) is saved alongside the original file.

Choosing **Manifest** generates a SHA256 manifest for every file in the directory and signs it in one step. Both the manifest and its detached signature are written to the same microSD folder.

Additional menu options can export existing GPG keys. Public keys are written to the microSD card in ASCII armor, while private keys are first exported and then symmetrically encrypted with a user-provided passphrase before being saved.

For SeedSignerOS, everything is stateless. If running on desktop or some other normal system, you will be interacting with your system GPG2 install...

During import, SeedSigner prompts for the key type, user name, email address, and expiration date. The expiration defaults to **10 years in the future**. (Noting that NIST guidelines have RSA2048 deprecated in 2030 and non-quantum safe keys, including ECC keys, being discontinued for government applications after 2035)

Note: The key derivation with BIP85 is deterministic, meaning the key and fingerprint will always be the same, but metadata like the username, email address and expiration date can be changed. (And are not saved on-device, but can be exported to a Smartcard, etc)

Existing GPG keys can also be exported. After selecting a key, SeedSigner offers to save the ASCII-armored public key either to the microSD card or directly to a connected Seedkeeper smartcard. On Seedkeeper, the key is saved as ASCII-armored text so it can be copied and pasted easily.

## SmartPGP Applet Installation

SeedSigner can install the [SmartPGP](https://github.com/ANSSI-FR/SmartPGP) applet onto a JavaCard via the **Smartcard Tools → Satochip DIY → Install Applet** menu. When a SmartPGP CAP file is selected, SeedSigner now generates a random 4‑byte serial number and embeds it into the application identifier (AID) during installation, following the [flexsecure applet procedure](https://github.com/DangerousThings/flexsecure-applets/blob/master/docs/applets/1-pgp.md).

