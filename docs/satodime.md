# Satodime Support

A [Satodime](https://satochip.io/product/satodime/) is a bearer card. Each of its key
slots holds a private key the card generated and has never revealed: you can read the
slot's deposit address and send funds to it, and the key only becomes visible when you
*unseal* the slot, which is a one-way operation the card records. Whoever holds the card
holds the coins.

SeedSigner reads slots, seals and unseals them, and can sign a Bitcoin transaction with
an unsealed key. Everything here is designed to agree byte-for-byte with the official
[Satodime apps](https://github.com/Toporin/Satodime-Android), so a card set up on one
reads correctly on the other.

Tools -> Smartcard -> Satodime.

## Claiming a card

A factory-fresh Satodime has no owner. The first `SETUP` command claims it, generating
the card's *unlock code* and handing it back exactly once — it can never be read again.
SeedSigner claims a card the first time you ask it to do something that changes card
state, after an explicit confirmation.

Satodime has **no PIN**. If you are ever asked to set one for a Satodime, that is a bug.

### The unlock code, and when it matters

The applet only checks the unlock code over a **contactless (NFC)** reader. Over a
**contact** reader it skips the check entirely, so:

- **Contact reader** — nothing to back up. SeedSigner claims the card and moves on.
- **NFC reader** — SeedSigner walks you through backing the code up, because without it
  an NFC-only setup can no longer seal, unseal, reset, *or even transfer* the card.

The backup flow shows the code as a QR and asks you to scan it back, so a code you never
actually captured cannot be mistaken for a backup. You can additionally save it to the
MicroSD card. Codes are held in RAM for the session only — they are never written to the
device. Restore one later with Card Settings -> Restore Unlock Code.

> **The unlock code is not theft protection.** Anyone holding the card and a contact
> reader can unseal it without the code. It protects against a contactless attacker
> in proximity to the card, and nothing else. The tamper-evident seal is what tells you
> whether a card has been interfered with.

## Supported coins

A slot records which coin it holds as a SLIP-44 code. SeedSigner derives the deposit
address and the private-key format from that code, matching
[Javacryptotools](https://github.com/Toporin/Javacryptotools), the library the official
apps use:

| Coin | Address format | Unsealed key format |
|------|----------------|---------------------|
| BTC  | bech32 P2WPKH (`bc1q…`)      | WIF |
| LTC  | bech32 P2WPKH (`ltc1q…`)     | WIF |
| BCH  | CashAddr (`bitcoincash:q…`)  | WIF |
| XCP  | legacy base58 (`1…`)         | WIF |
| ETH  | keccak, EIP-55 (`0x…`)       | raw hex |
| POL  | keccak, EIP-55 (`0x…`)       | raw hex |

Mainnet vs testnet follows SeedSigner's own Network setting, exactly as it follows the
testnet toggle in the official apps — the card records the coin, never the network.

Slots sealed for any other chain are shown as an unsupported coin rather than given a
guessed address. The official apps treat them the same way.

**Signing is Bitcoin-only.** Sign Transaction offers Bitcoin slots only. Other chains can
be viewed and unsealed; export the key and import it into a wallet for that chain.

## Signing a Bitcoin transaction from a Satodime

Unsealing hands SeedSigner a single private key with no BIP32 tree behind it, so the
usual "which seed signs this?" routing does not apply. The transaction has to be built by
a watch-only wallet that knows the slot's address.

Electrum is the reference:

1. **Read the slot's deposit address** in SeedSigner: Satodime -> View Deposit Addresses.
   Use this address verbatim.
2. **Create a watch-only wallet in Electrum** for that address:
   `File -> New/Restore`, choose *Import Bitcoin addresses or private keys*, and paste the
   address. This gives a wallet that can build transactions but cannot sign them.
3. **Build the transaction** in Electrum as normal. Because the wallet has no keys, it
   produces an unsigned PSBT.
4. **Export it as a QR code** and scan it with SeedSigner.
5. In SeedSigner: Satodime -> **Sign Transaction**, pick the sealed Bitcoin slot, and
   confirm. The slot is unsealed (one-way) and the transaction is signed.
6. SeedSigner displays the **finished raw transaction** as a QR code — not a partially
   signed PSBT, because a single-key spend is complete once signed. Scan it with a
   broadcasting tool, or paste it into Electrum's `Tools -> Load transaction -> From text`.

### If this did not work for you before

Two things used to break this, both fixed:

- **The address format was wrong.** SeedSigner derived a legacy `1…` address where the
  official apps derive `bc1q…`. Both are controlled by the same key, but a watch-only
  wallet built around the legacy address is watching a different address than the one the
  Satodime app shows, and any deposit made to it is invisible in that app. If you set up
  an Electrum wallet from an address SeedSigner showed before this fix, re-check it
  against View Deposit Addresses.
- **The key was silently dropped.** The screen that decides which key signs a PSBT
  matched on BIP32 fingerprints. An Electrum watch-only wallet exports a PSBT with no
  derivation data at all, so the check found nothing and fell through to the seed picker —
  where a raw key is not on offer. Raw keys are now matched on the key itself, the same
  test embit's signer uses.

### PSBT requirements

The PSBT needs nothing beyond what Electrum already puts in it:

- a `witness_utxo` for segwit inputs, or the full previous transaction (`non_witness_utxo`)
  for legacy ones — this is how the input amount is proven;
- a `redeem_script` for P2SH-wrapped segwit.

Derivation fields (`bip32_derivation`) are *not* required and are not expected.

SeedSigner accepts PSBTs as base64, base43, Specter, UR2 and BBQr QR codes.

## Transferring a card

Transfer Ownership releases the card: the applet clears its setup flag so the next holder
can claim it and mint their own unlock code. Over NFC this needs the current unlock code;
over a contact reader it does not.

## Testing

- `tests/test_satodime_coins.py` — address and key formats, pinned to the EIP-55 and
  CashAddr specification vectors and to Javacryptotools' parameters.
- `tests/test_wif.py` — raw-key signing against PSBTs shaped the way an Electrum
  watch-only wallet exports them, across P2PKH, P2WPKH, P2SH-P2WPKH and P2TR.
- `tests/test_real_screen_flows_satodime_simulated.py` — the views driven against a real
  Satodime applet in jcardsim, including a golden vector taken off a card the official
  Android app sealed.
- `tests/test_smartcard_hardware.py` — the same flows against a real card and reader.
