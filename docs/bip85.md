# BIP85 Child Seeds

[BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) deterministically
derives **child seeds** from a parent seed. The same parent seed and index always
produce the same child, so you can back up one seed phrase and derive as many child
wallets as you like from it.

SeedSigner's BIP85 support lets you generate a child seed, load it, and use it like any
other in-memory seed. (BIP85 is also used for [GPG keys](./gpg_tools.md), which have
their own documentation.)

## Generating a child seed

1. Load the **parent** seed.
2. On the seed's **Seed Options** screen choose **BIP-85 child seed**.
3. Choose the child's word count: **12**, **18** or **24 words**.
4. Choose the **index** (0, 1, 2, …). Different indexes give different children.
5. SeedSigner derives the child and shows it. You can verify/transcribe it like any
   seed, or finalize it into memory to use for signing.

**BIP-85 child seeds** must be enabled in Settings → Advanced (enabled by default).

## Using a child seed

A finalized child seed behaves like a normal seed:

- **Seed Options → Export xpub / Address explorer / Sign message**
- **Backup seed** (words, SeedQR, or to a SeedKeeper)
- Scan a PSBT to sign with it.

Because derivation is deterministic, you do **not** need to back up each child seed —
backing up the parent seed and recording the index is enough. That is the point of
BIP85, and also its risk: anyone with the parent seed can derive every child.

## BIP85 in the Password Generator

The [Password Generator](./password_generator.md) can use **BIP85** as its entropy
source to derive a password deterministically from a loaded seed, for password types it
supports.

## Version history

SeedSigner's BIP85-derived **GPG** keys have changed derivation scheme across releases;
see [BIP85 GPG version history](./bip85_gpg_version_history.md). Plain BIP85 child seeds
use the standard BIP85 path.

## Related

- [GPG Tools](./gpg_tools.md)
- [Password Generator](./password_generator.md)
- [SeedKeeper](./seedkeeper.md)
