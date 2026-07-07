# BIP85 GPG Version History

SeedSigner implements [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
for deterministic GPG key derivation. The derivation scheme has evolved through
several versions as the spec and available hardware matured.

## Overview

| Version | Period | Tags | Key change |
|---------|--------|------|------------|
| v0 | Aug 31 – Sep 14, 2025 | *(development only, no release)* | Initial implementation; all keys use app 828365 |
| v1 | Sep 15, 2025 – Mar 8, 2026 | `SS0.8.6+Satochip+Earthdiver-B4` … `SeSi-0.8.6+ShSi-B8` | Separate BIP85 app per curve |
| v2 | Mar 9, 2026 – Jun 2026 | `SeSi-0.8.6+ShSi-B9`, `SeSi-0.8.6+ShSi-B10` | Unified app 828365 with `key_type` codes |
| v3 | Jun 2026+ (planned) | *(B11-TestingFixes branch, unreleased)* | Split RSA (828365) and ECC (828366) apps |

## Detailed per-version description

### v0 (development — unreleased)

First working implementation. Every curve used the same BIP85 app number and
a simple `[param, index]` path.

- **App**: `828365'` for all key types
- **Path format**: `m/83696968'/828365'/{param}'/{index}'`
- **Param**: `{key_bits}` for RSA (e.g. 2048), `259` for Curve25519, `256` for ECDSA curves
- **Curves**: RSA 2048/3072/4096, Curve25519, secp256k1, NIST P-256
- **Tags**: None — development-only. The compatible upstream
  [bipsea](https://github.com/3rdIteration/bipsea) test vectors were never
  generated for this version.

### v1 (tagged releases B4 through B8)

Each curve got its own BIP85 app number. ECC was restricted to 256-bit.

- **Apps**:

  | Curve | App |
  |-------|-----|
  | RSA | `828365'` |
  | Curve25519 | `828366'` |
  | secp256k1 | `828367'` |
  | NIST P-256 | `828368'` |
  | Brainpool P-256 | `828369'` |

- **Path format**: `m/83696968'/{app}'/256'/{index}'` (ECC); `m/83696968'/828365'/{bits}'/{index}'` (RSA)
- **Key type codes**: Not used — the curve was encoded in the app number
- **Curves**: RSA, Curve25519, secp256k1, NIST P-256, Brainpool P-256
- **Tags**: `SS0.8.6+Satochip+Earthdiver-B4` through `SeSi-0.8.6+ShSi-B8`

### v2 (tagged releases B9, B10)

Unified all curves under a single app number with a `key_type` discriminator.
Added P-384, P-521, Brainpool P-384, Brainpool P-512.

- **App**: `828365'` for all key types
- **Path format**: `m/83696968'/828365'/{key_type}'/{key_bits}'/{index}'[/{sub_index}']`
- **Key type codes**:

  | Code | Curve |
  |------|-------|
  | 0 | RSA |
  | 1 | Curve25519 |
  | 2 | secp256k1 |
  | 3 | NIST P-256 / P-384 / P-521 |
  | 4 | Brainpool P-256 / P-384 / P-512 |

- **Curves**: RSA, Curve25519, secp256k1, NIST (P-256/P-384/P-521), Brainpool (P-256/P-384/P-512)
- **Tags**: `SeSi-0.8.6+ShSi-B9`, `SeSi-0.8.6+ShSi-B10`

### v3 (B11-TestingFixes branch — unreleased)

**Breaking change for ECC keys only.** RSA key derivation is identical to v2.

Splits RSA and ECC into separate apps and remaps ECC `key_type` codes so the
least-used curve (Brainpool) occupies code 0, reducing migration friction.

- **Apps**:

  | Family | App |
  |--------|-----|
  | RSA | `828365'` (unchanged from v2) |
  | ECC | `828366'` (new) |

- **Path format**:
  - RSA: `m/83696968'/828365'/0'/{bits}'/{index}'[/{sub_index}']`
  - ECC: `m/83696968'/828366'/{key_type}'/{key_bits}'/{index}'[/{sub_index}']`
- **ECC key type codes** (remapped):

  | Code | Curve |
  |------|-------|
  | 0 | Brainpool P-256 / P-384 / P-512 |
  | 1 | Curve25519 |
  | 2 | secp256k1 |
  | 3 | NIST P-256 / P-384 / P-521 |

- **RSA key type code**: 0 (unchanged from v2)
- **Curves**: Same as v2

## Summary table

```
           v0 (dev)         v1 (B4-B8)        v2 (B9-B10)       v3 (B11)
         ────────────────────────────────────────────────────────────────
App      828365'           828365'-828369'    828365'            828365' (RSA)
                                                                 828366' (ECC)

Path     [param, idx]      [256, idx] (ECC)   [kt, bits, idx]   [kt, bits, idx]
                           [bits, idx] (RSA)

ECC kt   N/A               N/A                1=C25519          1=C25519
                                              2=secp256k1       2=secp256k1
                                              3=NIST            3=NIST
                                              4=Brainpool       0=Brainpool

RSA kt   N/A               N/A                0                 0

P-384/   ✗                 ✗                  ✓                 ✓
P-521

Brainpool ✗                P-256 only          ✓                 ✓
```

## Notes

- **v0 was never released** — no tagged release or public build contains it.
  The compatible bipsea test vectors were generated starting from v1.
- **v2 → v3 is a breaking change for ECC keys** — the app number changed
  from `828365'` to `828366'` and key_type codes were remapped. RSA keys
  are unaffected.
- **Upstream SeedSigner (v0.8.7)** does **not** contain any GPG support.
  All versions described above are on the
  [3rdIteration](https://github.com/3rdIteration/SeedSigner) fork.

## See also

- [`docs/gpg_tools.md`](gpg_tools.md) — user-facing GPG feature documentation
- [`tools/bip85_pgp.py`](../tools/bip85_pgp.py) — standalone CLI tool
- [bipsea test vectors](https://github.com/3rdIteration/bipsea/blob/main/test_vectors.md)
