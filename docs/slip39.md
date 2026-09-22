# SLIP-39 Shares

**SLIP-39** splits a secret into multiple mnemonic *shares*. A chosen number of shares
(the threshold) recombines into the original seed; fewer than the threshold reveals
nothing. This is different from simply writing a seed down several times: any single
share is useless on its own.

SeedSigner can create SLIP-39 shares, import and extend them, load them from text, QR or
a SeedKeeper, and store individual shares on a SeedKeeper.

![Load a seed – SLIP-39 entry](img/guide/seed_views/LoadSeedView.png)

## Enabling SLIP-39

SLIP-39 is **disabled by default**. Enable **SLIP-39 seeds** in
Settings → Advanced. Enable **Extendable SLIP-39 shares** if you want shares that can be
extended with additional groups later (also the default for Satochip/Specter
compatibility).

## Creating shares

Two entropy sources:

- **Tools → SLIP39 seed** (camera) — entropy from the camera.
- **Tools → SLIP39 seed** (dice) — entropy from dice rolls.

You choose the share configuration (how many groups, how many shares, and the
threshold) and the word length (20 or 33 words), then the shares are generated and
shown. Write each share down (or save it to a SeedKeeper). Keep enough to meet the
threshold.

## Loading and recombining shares

**Seeds → Load a seed → SLIP-39 Shares**, then enter shares from any of:

- **Text** – type each word.
- **QR** – scan a share QR.
- **SeedKeeper** – load a stored share.

SeedSigner collects shares until the threshold is met, then reconstructs the seed and
shows its fingerprint.

## Saving shares to a SeedKeeper

When backing up a SLIP-39 seed, choose **To SeedKeeper** and select which share to
store. Each share is stored as its own labelled secret (`SLIP39:<label>`). Because a
single share is not enough to reconstruct the seed, distributing shares across multiple
cards is a reasonable multi-location scheme.

## Initialising a Satochip from a reconstructed SLIP-39 seed

Once the shares are combined, the resulting seed is a normal in-memory seed and can be
used anywhere a seed can — including
**Satochip Functions → Initialise with Seed → SLIP-39 Shares**.

## Related

- [SeedKeeper](./seedkeeper.md)
- [Satochip](./satochip.md)
- [Seed QR formats](./seed_qr/README.md)
