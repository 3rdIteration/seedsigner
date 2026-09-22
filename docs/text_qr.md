# Text QR Code Tool

**Tools → Text QR Code** encodes arbitrary text into a QR code, and decodes text QR
codes back. It is the general-purpose counterpart to the seed/PSBT QR flows — useful for
moving a password, a note, a URL or any other short string between an air-gapped
SeedSigner and another device.

![Tools menu](img/guide/tools/ToolsMenuView.png)

## Encode text

1. **Tools → Text QR Code → Encode text**.
2. Type the text using the on-screen keyboard. There are lower-case, upper-case, digit
   and two symbol keyboards; switch between them with the on-screen buttons.
3. Save, then choose how to display it:
   - **Transcribe mode** shows a grid you can copy by hand.
   - **Full-screen mode** shows the QR as large as possible for scanning.

The Password Generator's **Show as QR** option uses this same machinery.

> Text QRs are plain text. Do not use them for secrets unless you control who can see
> the screen.

## Decode a QR code

**Tools → Text QR Code → Decode QR code** opens the camera. Point it at any text QR code
and SeedSigner shows the decoded contents. This is handy for reading a URL or a note
without a phone.

## Related

- [Password Generator](./password_generator.md)
- [QR formats](./qr_formats.md)
