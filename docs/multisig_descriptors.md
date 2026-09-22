# Multisig Descriptors

A **wallet descriptor** is a compact, exact description of a wallet — its script type,
keys and derivation paths. SeedSigner uses descriptors to understand multisig wallets
(which keys, what threshold, change/receive branches) and to verify addresses and
transactions against them.

This fork keeps a loaded descriptor **in memory until you clear it**, and makes it
available to the Address Explorer. That makes descriptor workflows far less repetitive
than re-scanning each time.

## Loading a descriptor

A descriptor can come from:

- **A wallet's exported descriptor QR** — e.g. Sparrow, Specter Desktop, Nunchuk.
  Scanned from the normal **Scan** flow, or from **Tools → Address explorer →
  Scan wallet descriptor**.
- **A SeedKeeper card** — see
  [SeedKeeper → Load a descriptor](./seedkeeper.md#load-a-descriptor).
- **A Satochip card** — **Satochip Functions → Load as Descriptor** builds a
  single-sig descriptor from the card's master key.

The descriptor-load screen offers **Scan descriptor**, **Load SeedKeeper** and
**Cancel**.

## Reviewing a loaded descriptor

After loading, SeedSigner shows the descriptor summary: the multisig policy (e.g.
"2 of 3") and the fingerprint of every key, with buttons for the next action:

- **Address explorer** — derive and display receive/change addresses from the
  descriptor.
- **Verify addr** — when the descriptor was loaded while verifying an address.
- **Return to transaction** — when the descriptor was loaded from a PSBT review.

Use the **Address explorer** to check that a wallet's first receive addresses match what
SeedSigner derives from the same descriptor.

## Why the descriptor matters for signing

When you scan a PSBT from a multisig watch-only wallet, the wallet's change output can
look like an ordinary payment. With the matching descriptor loaded, SeedSigner can
identify which outputs are **change** and verify them properly. Without it, you may get
an **Identify Change** prompt or an "unidentified change" warning.

## Storing descriptors on a SeedKeeper

**Tools → Smartcard Tools → SeedKeeper Functions → Save MultiSig Descriptor** stores the
currently loaded descriptor. **Load MultiSig Descriptor** brings it back.

The storage format depends on the card:

- **SeedKeeper v0.2** stores the whole descriptor as a single `Descriptor` secret.
- **SeedKeeper v0.1** cannot store a full descriptor, so it is split into an
  `msig_desc_…` template plus one `xpub_…` secret per key, reassembled on load.

## Clearing a descriptor

**Tools → Clear Multisig Descriptor** removes the loaded descriptor from memory. Do this
when you are finished, so a different wallet's descriptor cannot be mistaken for the
current one.

## Related

- [SeedKeeper](./seedkeeper.md)
- [Satochip](./satochip.md)
- [PSBT / transaction review](./qr_formats.md)
- [Quick start: multisig descriptor to a SeedKeeper](./quickstarts/03-multisig-descriptor-seedkeeper.md)
