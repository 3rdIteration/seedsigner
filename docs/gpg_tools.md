# GPG Tools

SeedSigner includes tools to interact with GPG. When `gpg2` is available on the host system, the Tools menu offers a **Load BIP85 Key** option. This feature deterministically derives a keypair (NIST P-256, Brainpool P-256, RSA 2048, RSA 3072, or secp256k1) from the currently loaded seed using [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#user-content-RSA_GPG) and imports it into GPG.

For SeedSignerOS, everything is stateless. If running on desktop or some other normal system, you will be interacting with your system GPG2 install...

During import, SeedSigner prompts for the key type, user name, email address, and expiration date. The expiration defaults to **10 years in the future**. (Noting that NIST guidelines have RSA2048 deprecated in 2030 and non-quantum safe keys, including ECC keys, being discontinued for government applications after 2035)

Note: The key derivation with BIP85 is deterministic, meaning the key and fingerprint will always be the same, but metadata like the username, email address and expiration date can be changed. (And are not saved on-device, but can be exported to a Smartcard, etc)

Existing GPG keys can also be exported. After selecting a key, SeedSigner offers to save the ASCII-armored public key either to the microSD card or directly to a connected Seedkeeper smartcard.

