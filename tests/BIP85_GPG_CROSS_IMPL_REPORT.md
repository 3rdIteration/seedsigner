# BIP85 GPG Cross-Implementation Validation Report

## Summary

SeedSigner's BIP85 GPG implementation was validated against the bipsea reference
test vectors (commit `d8f8d9075a7ed6677c3be993f67c5d79e4bd63e1`), OpenSSL (via
python-cryptography), and PyCryptodome (FIPS 186-4).

**RSA vectors now fully match** — bipsea has been updated to use PyCryptodome for
RSA generation per our earlier recommendation. **One remaining issue**: NIST P-521
PGP fingerprint still diverges between pgpy and bipsea due to EC point encoding
differences in the V4 public-key packet.

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

## NIST P-521 PGP Fingerprint: ✗ Still diverges

### Problem

The bipsea P-521 test vector lists fingerprint `EE26 13AE C231 FD42 ECB6 264E F0D6 7F7D 7541 0C0B`.
pgpy computes a different V4 fingerprint from the same private key scalar.

The private key scalar `0xa9b5a5af…` is correct and matches between implementations.
OpenSSL independently confirms the public point derivation. The divergence is in how
the EC public point is encoded in the V4 public-key packet body.

### Status

This remains an open issue. The underlying key material is correct — only the PGP
fingerprint differs. This likely stems from differences in MPI encoding of the
uncompressed P-521 point (which has coordinates that may need zero-padding to 66 bytes).

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
| NIST P-521 | ✓ | ✓ | ✓ | ✓ | ✗ (encoding) |
| Brainpool P-256 | ✓ | ✓ | ✓ | ✓ | ✓ |
| Brainpool P-384 | ✓ | ✓ | ✓ | ✓ | ✓ |
| Brainpool P-512 | ✓ | ✓ | ✓ | ✓ | ✓ |

---

## Prompt for fixing P-521 fingerprint in bipsea

The following can be used as a prompt to investigate the P-521 fingerprint issue:

~~~
Investigate the NIST P-521 PGP V4 fingerprint encoding in bipsea.

### Problem

The P-521 private key scalar and public point are correct (verified
against OpenSSL/python-cryptography), but the PGP V4 fingerprint
differs between bipsea and pgpy.

bipsea produces: `EE26 13AE C231 FD42 ECB6 264E F0D6 7F7D 7541 0C0B`
pgpy produces a different fingerprint from the same key material.

### Likely cause

The V4 fingerprint is SHA-1(0x99 || len || packet_body), where
packet_body = version(1) + timestamp(4) + algorithm(1) + OID + MPI.

For P-521, the uncompressed point is 04 || x(66 bytes) || y(66 bytes)
= 133 bytes. The MPI encoding uses bit-length prefix followed by raw
bytes. If the MPI bit-length or leading zero handling differs between
bipsea's openpgp.py and pgpy, the fingerprint will differ.

### Suggested investigation

1. Compare the exact bytes of the V4 public-key packet body produced
   by bipsea vs pgpy for the P-521 key at index 0
2. Check MPI bit-count calculation for EC points
3. Check whether uncompressed point leading byte 04 is included in
   the MPI bit-count
~~~

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
