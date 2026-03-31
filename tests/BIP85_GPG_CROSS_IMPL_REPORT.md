# BIP85 GPG Cross-Implementation Validation Report

## Summary

SeedSigner's BIP85 GPG implementation was validated against the bipsea reference
test vectors (commit `d8f8d9075a7ed6677c3be993f67c5d79e4bd63e1`), OpenSSL (via
python-cryptography), and PyCryptodome (FIPS 186-4).

**All vectors now match.** RSA vectors were updated in bipsea to use PyCryptodome
for generation. The P-521 scalar derivation was fixed in SeedSigner to use bit
masking (matching bipsea's reference implementation) instead of modular reduction.

---

## RSA: ✓ RESOLVED — All vectors match

### Background

In the initial validation, bipsea used a pure-Python `_is_prime()` with fixed
small-prime witnesses (2, 3, 5, …, 53) for Miller-Rabin primality testing. This
consumed zero DRNG bytes for Miller-Rabin rounds, producing different primes than
PyCryptodome's FIPS 186-4 implementation (which uses random witnesses from the DRNG).

### Resolution

As of bipsea commit `d8f8d9075a`, the reference implementation uses PyCryptodome's
`RSA.generate(key_bits, randfunc=drng.read)` for RSA generation. All RSA test
vectors have been regenerated and now match PyCryptodome exactly.

### Validated RSA fingerprints

| Key size | Fingerprint | bipsea | PyCryptodome | OpenSSL cross-sign |
|----------|-------------|--------|--------------|-------------------|
| RSA-1024 | `874A 3964 4ED0 255D EEC1 8E0E 1E63 8864 9672 CF70` | ✓ | ✓ | ✓ |
| RSA-2048 | `9987 9DF6 D21E 34C8 A086 A4BD 8B44 8E5B C298 294A` | ✓ | ✓ | ✓ |
| RSA-4096 | `24C2 5A48 383E 1175 4687 1767 D9A0 5CA6 4F2F 6A85` | ✓ | ✓ | ✓ |

---

## NIST P-521: ✓ RESOLVED — Scalar derivation and fingerprint match

### Problem

The P-521 private scalar was derived differently between SeedSigner and bipsea:

- **bipsea**: reads 66 bytes from SHAKE256 DRNG, applies **bit mask**
  `& ((1 << 521) - 1)` to truncate to 521 bits
- **SeedSigner (old)**: reads 66 bytes from SHAKE256 DRNG, applies **modular
  reduction** `% order`

The 66-byte DRNG value has 528 bits (66 × 8). The bit mask clears the top 7 bits,
while modular reduction folds them into the result. For most DRNG outputs these
produce different scalars, different public keys, and different PGP fingerprints.

### Resolution

SeedSigner's `bip85_p521_from_root()` was updated to use bit masking followed by
range checking (matching bipsea's approach). The scalar, public point, and PGP
fingerprint now all match the bipsea reference vector.

---

## Curve25519 (Ed25519 + Cv25519): Implementation Note

The BIP85 entropy derivation for Curve25519 keys is straightforward: 32 bytes
from the HMAC-SHA512 output. The Ed25519 primary key fingerprint is deterministic
and matches across all implementations.

However, an OpenPGP key using Ed25519 for signing also requires a **Cv25519 (X25519)
ECDH subkey** for encryption. This subkey is derived from the same entropy source
(via BIP85 sub-index) and requires two OpenPGP-level post-processing steps that are
**not part of the BIP85 spec** but are necessary for gpg-agent compatibility:

1. **RFC 7748 §5 clamping**: The 32-byte Cv25519 scalar must be clamped before
   storage in the OpenPGP secret-key packet:
   ```
   d[0]  &= 248   # clear bits 0-2
   d[31] &= 127   # clear bit 255
   d[31] |= 64    # set bit 254
   ```
   The `X25519PrivateKey.from_private_bytes()` API (python-cryptography, libsodium)
   clamps internally for public key derivation, so the public key is always correct.
   But gpg-agent validates the stored scalar directly and rejects unclamped values
   with "Bad secret key" during export.

2. **Little-endian MPI byte order**: pgpy stores Cv25519 secret MPIs as
   `int.from_bytes(native_bytes, "little")`, unlike all other curve types which use
   big-endian. This matches the native X25519 wire format (RFC 7748 uses
   little-endian).

**These are OpenPGP serialization requirements, not BIP85 changes.** The BIP85
entropy output (32 raw bytes) is identical regardless of clamping or byte order.
The Ed25519 *primary key* fingerprint is unaffected. Only the Cv25519 *subkey*
packet serialization was corrected.

No additions to the BIP85 specification are needed for this fix, but implementors
building OpenPGP keys from BIP85-derived Cv25519 entropy should be aware of these
requirements.

---

## What was validated successfully

All key types were cross-validated against **three independent implementations**:

| Key type | Entropy | Private key | OpenSSL pubkey | OpenSSL sign/verify | PGP fingerprint (bipsea) |
|----------|---------|-------------|----------------|---------------------|--------------------------|
| RSA-1024 | ✓ | ✓ | ✓ (cross-sign) | ✓ | ✓ |
| RSA-2048 | ✓ | ✓ | ✓ (cross-sign) | ✓ | ✓ |
| RSA-4096 | ✓ | ✓ | ✓ (cross-sign) | ✓ | ✓ |
| Curve25519 (Ed25519) | ✓ | ✓ | ✓ | ✓ | ✓ |
| secp256k1 (256) | ✓ | ✓ | ✓ | ✓ | ✓ |
| NIST P-256 | ✓ | ✓ | ✓ | ✓ | ✓ |
| NIST P-384 | ✓ | ✓ | ✓ | ✓ | ✓ |
| NIST P-521 | ✓ | ✓ | ✓ | ✓ | ✓ |
| Brainpool P-256 | ✓ | ✓ | ✓ | ✓ | ✓ |
| Brainpool P-384 | ✓ | ✓ | ✓ | ✓ | ✓ |
| Brainpool P-512 | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## Proposed BIP85 spec paragraph for RSA determinism

The following paragraph should be added to the BIP85 specification under the
GPG (OpenPGP) section, after the RSA key type description:

~~~
### RSA Key Generation Algorithm

RSA key generation from the BIP85-DRNG MUST use the FIPS 186-4 (§B.3.1,
§C.3.1) algorithm for probable prime generation.  Specifically, the
Miller-Rabin primality test MUST use random bases drawn from the same
DRNG (randfunc) that generates prime candidates — NOT fixed or
deterministic witnesses.

The reference algorithm is PyCryptodome's `RSA.generate(key_bits,
randfunc=drng.read)`, which implements FIPS 186-4 with random
Miller-Rabin witnesses drawn from the provided `randfunc`.

Implementations that use fixed Miller-Rabin witnesses (e.g., small
primes 2, 3, 5, …) will consume DRNG bytes at a different rate than
the reference algorithm, producing different primes and therefore
different RSA keys from the same entropy.  Such implementations are
NOT compliant with this specification.

The use of random witnesses is also cryptographically stronger, as
fixed small-prime witnesses cannot detect Carmichael numbers that are
strong pseudoprimes to all tested bases.
~~~

---

## Proposed BIP85 spec paragraph for ECC scalar derivation (P-521 / large curves)

The following paragraph should be added to the BIP85 specification under the
GPG (OpenPGP) section, after the ECC key type descriptions:

~~~
### ECC Scalar Derivation for Curves Exceeding 64 Bytes

For elliptic curves whose base length (⌈log₂(order) / 8⌉) exceeds the
64-byte HMAC-SHA512 entropy output — currently only NIST P-521 (base
length 66 bytes) — the private scalar MUST be derived using the
BIP85-DRNG (SHAKE256) as follows:

1. Read `baselen` bytes from the DRNG (66 bytes for P-521).
2. Interpret the bytes as a big-endian unsigned integer.
3. Mask the integer to `order.bit_length()` bits:
   `scalar = raw_int & ((1 << bit_length) - 1)`
4. If `scalar == 0` or `scalar >= order`, apply the fallback:
   `scalar = (scalar % (order - 1)) + 1`

Implementations MUST use bit masking (step 3) rather than direct
modular reduction (`raw_int % order`).  The two methods produce
different scalars when the raw integer has more bits than the curve
order, because bit masking discards the top bits while modular
reduction folds them in.

For curves with base length ≤ 64 bytes (all others in this spec),
the scalar is derived directly from the first `baselen` bytes of the
64-byte HMAC-SHA512 entropy, reduced modulo the curve order with the
same fallback.
~~~

---

## Dependency analysis: pgpy removal feasibility

SeedSigner currently depends on three crypto libraries for GPG functionality:

| Library | Version | Purpose |
|---------|---------|---------|
| **pgpy** | 0.6.0 | OpenPGP packet construction, key assembly, serialization (ASCII armor, fingerprints), message encryption/decryption, key parsing |
| **cryptography** | 45.0.5 | EC public key derivation from scalars (Ed25519, X25519, NIST/Brainpool curves) — also a **transitive dependency of pgpy** |
| **pycryptodomex** | 3.23.0 | RSA key generation with deterministic DRNG, SHAKE256 DRNG, AES, RIPEMD160 fallback |

### What pgpy provides (5 categories of usage)

**1. OpenPGP packet construction** — `fields.RSAPriv`, `fields.ECDSAPriv`,
`fields.EdDSAPriv`, `fields.ECDHPriv`, `fields.ECPoint`, `fields.MPI`,
`_compute_chksum()`.  Used in every `bip85_*_from_root()` function and
`_rsa_to_privpacket()`.

**2. Key assembly** — `PGPKey`, `PrivKeyV4`, `PrivSubKeyV4`, `PGPUID.new()`,
`add_uid()`, `add_subkey()`.  These build complete OpenPGP keys with
self-signatures, user IDs, and subkey binding signatures.

**3. Serialization** — `str(key)` for ASCII armor export, `key.fingerprint`
for v4 fingerprint computation, `key.pubkey` for public key extraction.

**4. Message encryption/decryption** — `PGPMessage.new()`, `.encrypt()`,
`.decrypt()`, `.sign()`, `.verify()` in `gpg_message.py`.

**5. Key parsing** — `PGPKey.from_blob()`, `.subkeys`, `.key_flags` /
`._get_key_flags()`, `._key.keymaterial` in `smartpgp_import.py`.

### What python-cryptography provides

Used **only** for EC public key derivation from BIP85-derived scalars:
- `ed25519.Ed25519PrivateKey.from_private_bytes()` → `.public_key().public_bytes()`
- `x25519.X25519PrivateKey.from_private_bytes()` → `.public_key().public_bytes()`
- `ec.derive_private_key(scalar, curve)` → `.public_key().public_numbers()`

These compute EC public points from private scalars (7 curve types).
python-cryptography is also a **mandatory transitive dependency of pgpy**,
so removing pgpy alone would not eliminate it.

### Feasibility assessment: replacing pgpy with pycryptodomex only

**Short answer: technically possible but a major undertaking (~2000+ lines).**

What would need to be reimplemented from scratch:

1. **OpenPGP v4 packet format** (RFC 4880 §5.5–5.12) — Binary serialization of
   secret key packets, public key packets, MPI encoding (big-endian length-prefixed
   integers), S2K specifiers, key material checksums.

2. **V4 fingerprint computation** (RFC 4880 §12.2) — SHA-1 hash of specific
   packet header + key material bytes.  Must exactly match gpg's computation
   for key identity.

3. **Self-signature and binding signature packets** (RFC 4880 §5.2) — The
   `add_uid()` and `add_subkey()` calls create signature packets with hashed
   subpackets (key flags, preferred algorithms, creation time, expiration).
   These require signing with the primary key's algorithm.

4. **ASCII armor encoding** (RFC 4880 §6) — Base64 with CRC24 checksum,
   headers, and packet framing.

5. **PGP message encryption/decryption** (RFC 4880 §5.1, 5.7, 5.13) —
   Session key encryption (ECDH, RSA), symmetric data encryption (AES-256),
   MDC computation, literal data packets.

6. **EC public key derivation** — This is the python-cryptography part.
   PyCryptodome supports NIST P-256 and P-384 via `ECC.construct()` but does
   **not** support:
   - Ed25519 / X25519 (Curve25519 family)
   - secp256k1
   - Brainpool curves (P-256r1, P-384r1, P-512r1)
   - NIST P-521

   For the missing curves, you'd need either a pure-Python EC implementation
   or a different C library.

### Recommendation

The most practical approach is **not** a monolithic replacement but rather a
phased strategy:

1. **Phase 1 (low effort)**: Keep pgpy for packet construction and
   serialization.  The `gpg` binary handles the heavy crypto (signing,
   encryption) on SeedSignerOS.  pgpy is only used to build the initial key
   structure and for offline key operations.

2. **Phase 2 (medium effort)**: Replace python-cryptography EC point derivation
   with pure-Python implementations where possible.  PyCryptodome's `ECC` module
   handles P-256 and P-384.  For Ed25519/X25519, a pure-Python implementation
   (~200 lines) could replace the cryptography dependency for just public key
   derivation.  secp256k1 could use embit's existing implementation.

3. **Phase 3 (high effort)**: Replace pgpy entirely with a minimal OpenPGP
   packet builder.  This is ~1500–2000 lines of code covering v4 key packets,
   signatures, ASCII armor, and fingerprint computation.  The message
   encryption/decryption in `gpg_message.py` could delegate to the `gpg`
   binary instead.

The blocking issue for a pycryptodomex-only solution is that PyCryptodome
**does not support** Ed25519, X25519, secp256k1, Brainpool, or P-521 in its
`ECC` module.  These curves would require either keeping python-cryptography
as a dependency or adding pure-Python curve arithmetic.

---

## Follow-up: python-gnupg as an alternative to pgpy

### What is python-gnupg?

**python-gnupg** (`gnupg` on PyPI) is a thin Python wrapper around the `gpg`
command-line binary.  It calls `gpg` via `subprocess` and parses its
`--status-fd` output.  It has **zero** Python-level crypto dependencies — no
python-cryptography, no pycryptodome.  All actual cryptography is performed
by the native `gpg2` binary.

### Would it remove the python-cryptography dependency?

**Yes, partially — but with important caveats.**

python-gnupg itself does not depend on python-cryptography.  However:

1. **python-cryptography is currently used directly** in `tools_views.py`
   (lines 10833–11624) for EC public key derivation from BIP85 scalars
   (`Ed25519PrivateKey.from_private_bytes()`, `X25519PrivateKey`,
   `ec.derive_private_key()`).  These 9 import sites across 7 ECC key
   derivation functions are **not part of pgpy** — they call
   python-cryptography directly.  Replacing pgpy with python-gnupg would
   not eliminate these.

2. **pgpy uses python-cryptography internally** for its signing, encryption,
   and EC operations.  Removing pgpy would remove this *transitive*
   dependency.

So switching to python-gnupg removes the *transitive* path through pgpy but
**does not** remove the direct usage in `bip85_ed25519_from_root()`,
`bip85_secp256k1_from_root()`, `bip85_p256_from_root()`, etc.  Those would
need separate replacement (see Phase 2 in the phased strategy above).

### What python-gnupg can and cannot replace

| Current pgpy usage | python-gnupg replacement? | Notes |
|---|---|---|
| **Key import** (`gpg --batch --import`) | ✅ `gpg.import_keys(armored)` | Already done via subprocess; trivial to wrap |
| **Key listing** (`gpg --list-secret-keys --with-colons`) | ✅ `gpg.list_keys(secret=True)` | Already done via subprocess; python-gnupg returns structured objects |
| **Subkey add** (`gpg --quick-addkey`) | ✅ python-gnupg doesn't wrap this but can call `gpg` generically | Current code already uses subprocess |
| **UID operations** (`--quick-add-uid`, `--quick-revoke-uid`) | ✅ Same — subprocess-based | No change needed |
| **File encrypt/decrypt** (Tools → File Operations) | ✅ `gpg.encrypt()` / `gpg.decrypt()` | Already uses subprocess `gpg` binary |
| **OpenPGP packet construction** (PrivKeyV4, MPI, ECPoint) | ❌ **Not possible** | python-gnupg is a CLI wrapper; it cannot construct custom key packets |
| **BIP85 key material injection** (setting `pk.keymaterial`) | ❌ **Not possible** | The core use case: deterministically setting private key bytes from BIP85 entropy |
| **ASCII armor serialization** (`str(pgp_key)`) | ❌ Only via gpg binary round-trip | pgpy serializes in-memory; python-gnupg requires the key to exist in the gpg keyring first |
| **Fingerprint computation** (`key.fingerprint`) | ❌ Only after gpg import | pgpy computes fingerprints from raw packet data before import |
| **Message encrypt/decrypt in gpg_message.py** | ⚠️ Possible but requires `gpg` binary | Current `gpg_message.py` explicitly avoids the gpg binary for portability |
| **SmartPGP card import** (parsing key material) | ❌ **Not possible** | Needs direct access to MPI values (n, e, d, p, q) from key packets |

### The core problem: BIP85 deterministic key construction

The fundamental issue is that **BIP85 GPG key derivation requires constructing
OpenPGP key packets from raw entropy bytes**.  This means:

1. Deriving a private scalar from BIP85 entropy
2. Computing the corresponding public key point
3. Encoding both into OpenPGP MPI format
4. Assembling a v4 secret key packet with correct creation timestamp
5. Adding self-signatures with the correct key flags
6. Computing the v4 fingerprint from the packet bytes
7. Exporting as ASCII armor

python-gnupg cannot do steps 1–7 because it only wraps the `gpg` CLI.
The `gpg` binary does not accept raw key material — it either generates
keys internally or imports fully-formed OpenPGP packets.

### What would need to change

To use python-gnupg instead of pgpy, you would need:

1. **Keep a minimal OpenPGP packet builder** (~800–1000 lines) to construct
   secret key packets from BIP85 entropy.  This replaces pgpy's
   `PrivKeyV4`, `fields.*Priv`, `MPI`, `ECPoint`, `PGPUID.new()`,
   `add_uid()`, `add_subkey()`, and `str(key)` (ASCII armor).

2. **Replace the ~40 subprocess.run("gpg", ...) calls** with python-gnupg's
   API for key listing, import, UID management, etc.  This is mostly
   cosmetic since both approaches call the same binary.

3. **Replace gpg_message.py** with python-gnupg's `encrypt()`/`decrypt()`
   methods, or keep the current subprocess approach.  This would make
   message operations depend on the `gpg` binary (currently pgpy handles
   them in pure Python).

4. **Replace smartpgp_import.py** key parsing with the minimal packet
   reader from step 1, or keep pgpy just for this module.

### Summary

| Approach | Removes pgpy? | Removes python-cryptography? | Effort | Risk |
|---|---|---|---|---|
| **python-gnupg only** | ✅ | ❌ (direct usage remains) | Medium | Loses pure-Python message encrypt/decrypt |
| **python-gnupg + minimal packet builder** | ✅ | ❌ (direct EC point derivation remains) | Medium-High | ~1000 LOC new code to test and maintain |
| **python-gnupg + packet builder + embit/pure-Python ECC** | ✅ | ✅ | High | Most curves need custom implementations |
| **Keep pgpy, replace direct cryptography usage** | ❌ | ❌ (pgpy depends on it) | Low | Not useful for the goal |

**Bottom line**: python-gnupg is a good replacement for the **subprocess.run("gpg", ...)**
calls that are already in the codebase (~40+ call sites).  It provides
structured output parsing and error handling.  However, it **cannot** replace
pgpy's core function of constructing OpenPGP key packets from raw BIP85
entropy.  A minimal packet builder would still be needed, and
python-cryptography would still be needed for EC public key derivation
unless replaced by pure-Python or embit-based implementations.
