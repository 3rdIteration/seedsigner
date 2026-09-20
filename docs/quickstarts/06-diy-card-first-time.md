# Quick start 06 — First-time DIY card setup (GlobalPlatform keys)

A blank JavaCard is protected by GlobalPlatform keys. Until you change them, the card
uses the well-known **default development keys**, so anyone with a reader can
reinstall or wipe your applet. This guide sets your own keys.

> Do this **after** installing the applet(s) you want. Once the card is locked with your
> own keys, applet installation/uninstallation requires those keys.

## What you need

- A card with the applet(s) already installed ([Quick start 01](./01-install-applets-diy-javacard.md)).
- **DIY Tools → Card Keys**.

   ![Card Keys](../img/guide/smartcard/ToolsJavacardKeysView.png)

## 1. Generate keys

1. **Card Keys → Generate Key Set** (or **Generate Single Key**).

   - A **key set** contains ENC/MAC/DEK keys.
   - A **single key** is one 16-byte key.

2. **Card Keys → Save Keys → To MicroSD** to write `javacard-keys.txt` at the card
   root. You can also save to a SeedKeeper (**To Seedkeeper**), which stores them under
   the `jc_keys_` prefix.

   > **Back these keys up.** If you lock the card with keys you cannot reproduce, you
   > can no longer install or remove applets on it.

## 2. Lock the card

1. **Card Keys → Lock Card**.
2. Confirm. SeedSigner authenticates with the default keys, writes your ENC/MAC/DEK
   keys, and the card is now locked.
3. Verify by trying to **Install Applet** again — it will fail without the keys loaded.

## 3. Unlock (reset to default keys)

If you need to get back in — or want to return a card to a known state:

1. Load your keys first (if the card is locked): **Card Keys → Load Keys**, choose
   **From MicroSD** or **From Seedkeeper**.
2. **Card Keys → Unlock Card**. This authenticates with the loaded keys and resets the
   card to the **default development keys** (`404142434445464748494A4B4C4D4E4F`).
3. Remember the card is now unprotected again.

> **Unlock Card resets the card to the default dev keys.** Only use it on a card you
> intend to leave open, or immediately re-lock it.

## 4. Clear loaded keys

**Card Keys → Clear Loaded Keys** forgets the keys held in memory. Use it when you are
done so keys do not linger in RAM.

## Related

- [Bundled JavaCard applets](../javacard_applets.md#javacard-keys-globalplatform)
- [Smartcard integration and installation](../smartcard_support_installation.md)
