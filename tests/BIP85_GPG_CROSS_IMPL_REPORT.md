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
