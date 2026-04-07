# Demo QR Codes for PR #345

These QR codes demonstrate both the **ambiguity bug** that [PR #345](https://github.com/3rdIteration/seedsigner/pull/345) fixes and the **new functionality** it introduces.

> **⚠️ WARNING:** These QR codes contain test seed mnemonics. Do **NOT** use any of these mnemonics for real funds.

---

## Decryption Key QR Codes

Scan these instead of typing the encryption keys manually:

| QR Code | Key | Used by |
|---------|-----|---------|
| ![key_testkey](key_testkey.png) | `testkey` | issue_1, issue_2, feature_2, feature_5 |
| ![key_outerkey](key_outerkey.png) | `outerkey` | feature_3 (outer layer) |
| ![key_innerkey](key_innerkey.png) | `innerkey` | feature_3 (inner layer) |
| ![key_textkey](key_textkey.png) | `textkey` | feature_4 (encrypted text) |

---

## Issue Demonstration

PR #345 fixes a bug where valid **EncryptedQR** codes could be **misidentified as CompactSeedQR** when their total byte length happened to match a valid CompactSeedQR entropy size (16, 20, 24, 28, or 32 bytes).

### How the bug works

The old `detect_segment_type()` code checked byte lengths **first**:
1. If `len(data) in (16, 20, 24, 28, 32)` → **always** returned `CompactSeedQR`
2. Only checked for EncryptedQR if the length didn't match

This meant a carefully-crafted (or unlucky) EncryptedQR whose KEF envelope totaled exactly one of those lengths would be silently treated as a CompactSeedQR — loading a **completely wrong seed** with no warning.

### `issue_1_ambiguous_24byte.png` — 24-byte EncryptedQR

![issue_1](issue_1_ambiguous_24byte.png)

| Field | Value |
|-------|-------|
| **QR type** | EncryptedQR (AES-ECB, version 5) |
| **ID** | *(empty)* |
| **Encryption key** | `testkey` (scan ![key](key_testkey.png)) |
| **PBKDF2 iterations** | 10,000 |
| **Encrypted content** | `crush inherit small egg include title slogan mom remain blouse boost bonus` |
| **Total bytes** | 24 (same as 18-word CompactSeedQR) |
| **Hex** | `0005000001dd7c1653e19fca2029c65271a95f9d8e3971c3` |

**Old behavior:** Treated as 18-word CompactSeedQR → loads wrong seed:
`abandon chimney abandon admit style arctic exhibit crop sketch access immense pilot box quit involve shrimp impact bunker`

**New behavior:** Detected as ambiguous → user prompted to choose between CompactSeedQR and EncryptedQR.

---

### `issue_2_ambiguous_32byte.png` — 32-byte EncryptedQR

![issue_2](issue_2_ambiguous_32byte.png)

| Field | Value |
|-------|-------|
| **QR type** | EncryptedQR (AES-ECB, version 5) |
| **ID** | `SeedSign` |
| **Encryption key** | `testkey` (scan ![key](key_testkey.png)) |
| **PBKDF2 iterations** | 10,000 |
| **Encrypted content** | `crush inherit small egg include title slogan mom remain blouse boost bonus` |
| **Total bytes** | 32 (same as 24-word CompactSeedQR) |
| **Hex** | `08536565645369676e05000001e1ddd5b745e463646fa0905b2442724be0fab0` |

**Old behavior:** Treated as 24-word CompactSeedQR → loads wrong seed:
`analyst open flock silly custom recipe retreat parade abandon audit jazz problem inmate vendor mirror mistake party lizard simple lumber caution vacant turn again`

**New behavior:** Detected as ambiguous → user prompted to choose between CompactSeedQR and EncryptedQR.

---

## New Functionality Demonstration

### `feature_1_compactseedqr_12word.png` — Normal CompactSeedQR (unambiguous)

![feature_1](feature_1_compactseedqr_12word.png)

A standard 12-word CompactSeedQR (16 bytes). This is **unambiguous** — 16 bytes is too small to be a valid KEF envelope, so it can only be CompactSeedQR.

| Field | Value |
|-------|-------|
| **Mnemonic** | `crush inherit small egg include title slogan mom remain blouse boost bonus` |
| **Entropy** | `350e7b31a36727c5f2fc76b58304668c` (16 bytes) |

---

### `feature_2_normal_encryptedqr.png` — Normal EncryptedQR (unambiguous)

![feature_2](feature_2_normal_encryptedqr.png)

A standard EncryptedQR using AES-CBC mode. At 49 bytes, it doesn't match any CompactSeedQR entropy size, so it's **unambiguous**.

| Field | Value |
|-------|-------|
| **ID** | `MyWallet` |
| **Encryption key** | `testkey` (scan ![key](key_testkey.png)) |
| **Mode** | AES-CBC |
| **PBKDF2 iterations** | 10,000 |
| **Encrypted content** | `crush inherit small egg include title slogan mom remain blouse boost bonus` |

---

### `feature_3_nested_encryptedqr.png` — Nested EncryptedQR (NEW)

![feature_3](feature_3_nested_encryptedqr.png)

An EncryptedQR whose **decrypted content is another EncryptedQR**. PR #345 adds the ability to detect and handle this nesting — after decrypting the outer layer, the firmware recognizes the inner payload as another EncryptedQR and prompts for a second decryption key.

| Layer | Field | Value |
|-------|-------|-------|
| **Outer** | ID | `outer` |
| | Encryption key | `outerkey` (scan ![key](key_outerkey.png)) |
| | Mode | AES-CBC |
| | PBKDF2 iterations | 10,000 |
| **Inner** | ID | `inner` |
| | Encryption key | `innerkey` (scan ![key](key_innerkey.png)) |
| | Mode | AES-ECB |
| | PBKDF2 iterations | 10,000 |
| **Final content** | Mnemonic | `crush inherit small egg include title slogan mom remain blouse boost bonus` |

**Decryption flow:**
1. Scan QR → shows "Encrypted QR Code: ID: outer, Version: AES-CBC"
2. Enter outer key (`outerkey`) → decrypts to another EncryptedQR
3. Shows "Encrypted QR Code: ID: inner, Version: AES-ECB"
4. Enter inner key (`innerkey`) → reveals the final seed mnemonic

---

### `feature_4_encrypted_text_qr.png` — Encrypted Text QR (NEW)

![feature_4](feature_4_encrypted_text_qr.png)

An EncryptedQR whose decrypted content is **plain text** (not a seed mnemonic or xprv). PR #345 adds the `ScanDecryptedTextView` to display arbitrary decrypted text.

| Field | Value |
|-------|-------|
| **ID** | `msg01` |
| **Encryption key** | `textkey` (scan ![key](key_textkey.png)) |
| **Mode** | AES-CBC +p |
| **PBKDF2 iterations** | 10,000 |
| **Decrypted text** | `Hello from SeedSigner! This is a secret message.` |

---

### `feature_5_base43_encryptedqr.png` — Base43-encoded EncryptedQR

![feature_5](feature_5_base43_encryptedqr.png)

An EncryptedQR encoded as a **Base43 text string** instead of raw binary. This uses the QR code's alphanumeric mode for potentially better scanning compatibility.

| Field | Value |
|-------|-------|
| **ID** | `b43test` |
| **Encryption key** | `testkey` (scan ![key](key_testkey.png)) |
| **Mode** | AES-CBC |
| **Base43 string** | `M8DOXUK9:0KV1/E-2C*WG8RFNFEDZ/0DU-X6R:U$8W$.7WUK54IYHT67+L-.CAO3*D:MBE` |
| **Encrypted content** | `crush inherit small egg include title slogan mom remain blouse boost bonus` |

---

## Reference QR Codes

These are legitimate, unambiguous CompactSeedQR codes for comparison:

### `ref_1_compactseedqr_24word.png` — 24-word CompactSeedQR (32 bytes)

![ref_1](ref_1_compactseedqr_24word.png)

| Field | Value |
|-------|-------|
| **Mnemonic** | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art` |

### `ref_2_compactseedqr_18word.png` — 18-word CompactSeedQR (24 bytes)

![ref_2](ref_2_compactseedqr_18word.png)

| Field | Value |
|-------|-------|
| **Mnemonic** | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent` |

---

## Ambiguous QR Settings (NEW)

PR #345 adds a new **"Ambiguous QR"** setting under Settings → Advanced:

| Option | Behavior |
|--------|----------|
| **Prefer CompactSeedQR** | Automatically treat ambiguous QR codes as CompactSeedQR |
| **Prefer EncryptedQR** | Automatically treat ambiguous QR codes as EncryptedQR |
| **Ask each time** (default) | Show a prompt letting the user choose the interpretation |

> **Note:** The original PR #345 code set the default to "Prefer CompactSeedQR"
> (`AMBIGUOUS_QR_COMPACT`). This has been corrected to "Ask each time"
> (`AMBIGUOUS_QR_PROMPT`) in `settings_definition.py` line:
> ```python
> default_value=SettingsConstants.AMBIGUOUS_QR_PROMPT
> ```
> The root cause was simply the wrong constant being used as `default_value` in
> the `SettingsEntry` for `SETTING__AMBIGUOUS_QR`.

This change also hides the legacy AES v1 modes (AES-ECB v1, AES-CBC v1) from the
encryption mode selector.

---

## How to Reproduce the Bug

1. Build SeedSigner from the **base branch** (before PR #345)
2. Scan `issue_1_ambiguous_24byte.png` or `issue_2_ambiguous_32byte.png`
3. Observe: the device loads a **wrong seed mnemonic** without any warning
4. Compare: scan `ref_2_compactseedqr_18word.png` (same 24 bytes) — this is what the old code thinks issue_1 is

## How to Verify the Fix

1. Build SeedSigner from the **PR #345 branch**
2. Scan `issue_1_ambiguous_24byte.png` or `issue_2_ambiguous_32byte.png`
3. Observe: the device either prompts you to choose the QR type (if "Ask each time" is set) or uses your preferred default
4. Choose "EncryptedQR" → enter key `testkey` → see the correct mnemonic
5. Scan `feature_3_nested_encryptedqr.png` → decrypt outer (`outerkey`) → decrypt inner (`innerkey`) → see mnemonic
6. Scan `feature_4_encrypted_text_qr.png` → decrypt (`textkey`) → see the plain text message
