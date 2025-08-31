# GPG Tools

SeedSigner includes tools to interact with GPG. When `gpg2` is available on the host system, the Tools menu offers a **Load BIP85 Key** option. This feature deterministically derives a keypair (RSA 4096, RSA 2048, or secp256k1) from the currently loaded seed using [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#user-content-RSA_GPG) and imports it into GPG.

During import, SeedSigner prompts for the key type, user name, email address, and expiration date. The expiration defaults to **10 years in the future**.

After the key is imported, all metadata can be changed within GPG. You may edit the name, email address, and adjust the expiration, including setting future deprecation or end-of-use dates, using standard commands such as `gpg --edit-key`.

