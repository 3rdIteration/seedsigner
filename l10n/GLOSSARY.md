# Fork translation glossary & rules

Shared decisions for filling the fork's translation overlays
(`l10n/fork/<locale>/messages.po`). Used by the `/translate-gaps` workflow.
The **upstream catalog for the locale is always the primary glossary** — match
its terminology exactly, even when a textbook translation would differ. This
file records decisions that upstream's catalogs don't settle.

## BIP39 / SLIP39 mnemonic words are NEVER translated

The seed words themselves (reading, backing up, entering, backup-test choices)
must always render exactly as the English wordlist words. The code guarantees
this — words are drawn directly (`SeedWordsScreen`), injected via `.format()`
after template translation (calc-final-word), or use
`ButtonOptionWithoutTranslation` (backup test) — so they never flow through
gettext. To keep it that way:

- Never add an overlay entry whose msgid exactly equals a BIP39/SLIP39 word
  (`fork_translations.py check` errors on this). Upstream's "change"/"fee"
  msgids are PSBT UI labels, not wordlist renderings — they're fine upstream
  but must not be duplicated into overlays.
- When touching seed/share word UI code, keep words out of `_()` and plain
  `ButtonOption` labels; use `ButtonOptionWithoutTranslation`.

## Never translate (all locales)

1. **Mis-extracted internal data keys** — these are GPG colon-format /
   dict-lookup keys that Babel's extractor caught by accident. Translating
   them is wrong; leave them out of every overlay (English fallback is a
   no-op): `fpr`, `uid`, `uiduidfpr`, `fprcaps`, `fingerprintseed_type`, `.`
2. **Brand / protocol names**: SeedSigner, SeedKeeper, Seedkeeper, Satochip,
   Keycard, Specter, Specter-DIY, BitBox02, Passport, TAPSIGNER, Electrum,
   LND, Diceware, SmartGPG, OpenGPG, GPG, NDEF, PCSC, NFC, PIN, PUK, RNG,
   BIP39/BIP38/BIP32/BIP85, SLIP39, xpub, xprv, WIF, PSBT, SeedQR,
   CompactSeedQR, EncryptedQR, QR.
3. **Universal tokens**: `Base64`, `Base85`, `Hex` (unless the locale's
   upstream catalog translates it), `microSD`, byte sizes (`64MB`, `4 KB`, …),
   bit counts (`128 bits` — translate only the "bits" word if upstream does).

## SLIP-39 "share"

Follow Trezor firmware's per-language convention (checked at
trezor-firmware `b235e018`):

| locale | term |
|--------|------|
| es | parte / partes |
| ca | part / parts (mirrors es; no Trezor ca) |
| cs | podíl / podíly |
| de | Share / Shares (Trezor de keeps English, capitalized noun) |
| el | μερίδιο / μερίδια (no Trezor el; natural Greek) |
| fr | fragment / fragments |
| pt_BR | share / shares (Trezor pt keeps English) |

For locales not listed: check Trezor first, else follow the pattern of the
closest sibling language and note the decision here.

## Per-locale conventions (from upstream catalogs)

- **es**: seed = *semilla*; passphrase = *Passphrase* (kept); fingerprint =
  *huella*; wallet = *billetera*; buttons in infinitive (*Cargar*, *Escanear*);
  sentences address the user as *tú*.
- **ca**: seed = *llavor*; passphrase = *Passphrase*; fingerprint = *empremta*;
  wallet = *bitlletera*; mixes infinitive and imperative like upstream.
- **cs**: seed = *seed* (kept, declined: *seedu*, *seedy*); passphrase =
  *bezpečnostní fráze*; fingerprint = *otisk*; wallet = *peněženka*.
- **de**: seed = *Seed* (kept); passphrase = *Passphrase*; fingerprint =
  *Fingerabdruck*; wallet = *Wallet* (kept); Tools = *Tools* (kept); informal
  *du*-form; verb-final button style (*Seed laden*, *… eingeben*).
- **el**: seed = *seed* (kept); passphrase = *συνθηματική φράση*; fingerprint =
  *αποτύπωμα*; wallet = *πορτοφόλι*; noun-style buttons (*Φόρτωση seed*).

## Formatting rules

- `{}` / `{name}` placeholders verbatim, same count and names.
- Preserve `\n` counts and leading/trailing spaces exactly (icon-padded
  labels like `" New seed"` and value labels like `"Voltage: "`).
- Body copy ≤ ~120 chars over ≤ 2 lines; buttons/titles as short as English
  (240px screen, no horizontal scroll — see AGENTS.md).
