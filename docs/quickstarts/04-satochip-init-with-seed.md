# Quick start 04 — Initialise a Satochip card with a seed

A Satochip holds a seed on the card and can sign with it. This guide seeds a Satochip
and proves it works by exporting an xpub.

## What you need

- A blank Satochip card (`SatoChip-0.12-official.cap` installed) — see
  [Quick start 01](./01-install-applets-diy-javacard.md).
- **Smartcard support** and **Satochip support** enabled (both default Enabled).
- The seed you want to store. A Satochip can only be seeded **once**; to change the seed
  you must factory-reset or re-flash the card.

## Steps

1. Load the seed in SeedSigner (create, scan, load from a SeedKeeper, or type it).

2. Go to **Tools → Smartcard Tools → Satochip Functions**.

   ![Satochip menu](../img/guide/satochip/01_Satochip.png)

3. Choose **Initialise with Seed**.

4. If the card is blank, SeedSigner shows an uninitialised warning and asks you to set a
   **New Card PIN**. Satochip PINs are numeric; remember it.

5. On the **Seed to Import** screen, choose the loaded seed from the top of the list (you
   can also scan or type a seed here). If you are moving a SLIP-39 seed, choose
   **SLIP-39 Shares**.

6. Wait for **Seed Imported**.

   > If the card already contains a seed, you will see **Already Seeded** instead. Reset
   > the card (Satochip Functions → Card Settings → Factory Reset Card) if you really
   > want a different seed. **A factory reset erases the card's key material.**

7. Confirm with **Satochip Functions → View Master Fingerprint** — it should match the
   seed's fingerprint.

   ![Master Fingerprint](../img/guide/satochip/03_Master_Fingerprint.png)

## Export an xpub for a watch-only wallet

1. **Satochip Functions → Export Xpub**.
2. Choose **Single Sig** or **Multisig**.
3. Choose the script type.

   ![Export xpub — script type](../img/guide/smartcard/SatochipExportXpubScriptTypeView.png)

4. Choose the coordinator/QR format, accept the warning, and review the derivation
   details.
5. Scan the xpub QR into your wallet.

## Optional — check the card

**Satochip Functions → Card Settings → Card Info** shows the card type, version, PIN
tries, seed state and NFC policy.

![Card Info](../img/guide/satochip/02_Card_Info.png)

## Related

- [Satochip](../satochip.md)
- [Keycard](../keycard.md)
- [Multisig descriptors](../multisig_descriptors.md)
