# Quick start 09 — SeedQR backup

A **SeedQR** encodes a seed phrase as a QR you can scan back into SeedSigner instantly.
There are two formats: **Standard** (words as decimal numbers) and **Compact**
(hexadecimal). Standard is human-transcribable; Compact is smaller.

## Part 1 — Choose the format and transcribe

1. Load the seed and choose **Backup seed → Export as SeedQR**.
2. Choose the SeedQR format (Standard or Compact) and size.

   > **Compact SeedQR** must be enabled in Settings → Advanced to appear.

3. SeedSigner shows the QR as a grid. Options:
   - **Whole QR** — show the entire code for a printer or camera.
   - **Zoomed in** — step through the modules to hand-transcribe onto a printed template.

4. Transcribe carefully using the printable templates:
   - Standard: 12-word = 25×25; 24-word = 29×29.
   - Compact: 12-word = 21×21; 24-word = 25×25.

   Templates live in [Seed QR printable templates](../seed_qr/printable_templates/) and
   are described in the [Seed QR README](../seed_qr/README.md).

## Part 2 — Verify the SeedQR

SeedSigner can scan the SeedQR back and confirm it decodes to the same seed. Use
**Seed Transcribe → Confirm** from the flow to scan your handwritten code before
trusting it as a backup.

## Part 3 — Load from a SeedQR

1. **Seeds → Load a seed → Scan a SeedQR** (or **Scan a seed**).
2. Point the camera at the SeedQR.
3. SeedSigner loads the seed and shows its fingerprint.

SeedQRs are plaintext. Store them like you would the written words — preferably
somewhere offline and protected.

## Related

- [Seed QR formats](../seed_qr/README.md)
- [Dice verification](../dice_verification.md)
- [SeedKeeper](../seedkeeper.md)
