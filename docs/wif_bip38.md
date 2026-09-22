# WIF and BIP38 Key Signing

SeedSigner can sign with **raw single private keys** in addition to BIP-39/BIP32 seeds.
Two key formats are supported:

- **WIF** — a plain Wallet Import Format private key (e.g. from an Electrum address
  import, or an unsealed [Satodime](./satodime.md) Bitcoin slot).
- **BIP38** — a passphrase-encrypted WIF key.

Both features are **disabled by default** because a raw key has no BIP32 tree behind it,
so the usual "which seed signs this?" safety checks do not apply. Enable them only if
you need them:

- Settings → Advanced → **WIF keys**
- Settings → Advanced → **BIP38 keys**

## How it works

A WIF/BIP38 key signs as a **raw key**, not as a seed. When you scan a PSBT, SeedSigner
matches the raw key against the input itself (the same test embit's signer uses) rather
than against BIP32 fingerprints. This is what allows a watch-only wallet's PSBT — which
contains no derivation data — to be signed by a single key.

## Signing with a WIF key

1. Enable **WIF keys**.
2. Provide the key by scanning a WIF QR code, or by loading an unsealed Satodime slot
   (**Satodime → slot → Load Key to SeedSigner**).
3. Scan the PSBT from a wallet that watches that key's address.
4. Review and sign.

## Signing with a BIP38 key

1. Enable **BIP38 keys**.
2. Scan the encrypted BIP38 key QR.
3. Enter the decryption passphrase when prompted.
4. Scan the PSBT and sign.

The passphrase is held in memory only for the operation and is not written to the card
or MicroSD.

## Security notes

- A raw key is a single point of failure and offers no seed-level recovery. Treat the
  WIF/BIP38 source as you would the private key itself.
- Prefer enabling these settings only for the session in which you need them, then turn
  them back off.
- The Satodime workflow that produces a WIF requires **unsealing** a slot, which is
  one-way. See [Satodime](./satodime.md).

## Related

- [Satodime](./satodime.md)
- [PSBT / transaction signing](./qr_formats.md)
