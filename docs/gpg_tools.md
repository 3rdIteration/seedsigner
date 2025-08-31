# GPG Tools

SeedSigner includes tools to interact with GPG. When `gpg2` is available on the host system, the Tools menu offers a **Load BIP85 Key** option. This feature deterministically derives an RSA keypair from the currently loaded seed using [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#user-content-RSA_GPG) and imports it into GPG.

During import, SeedSigner prompts for the key's user name, email address, and expiration date. The expiration defaults to **2035-12-31** (the last day of 2035) in line with NIST guidelines. 

After the key is imported, all metadata can be changed within GPG. You may edit the name, email address, and adjust the expiration, including setting future deprecation or end-of-use dates, using standard commands such as `gpg --edit-key`.

