"""Pure-Python and PyCryptodome helpers for EC public-key derivation.

These replace direct usage of ``python-cryptography`` for deriving EC
public-key points from private scalars.  PyCryptodome handles NIST
curves (P-256, P-384, P-521), Ed25519, and Curve25519.  Brainpool
curves use a minimal pure-Python implementation because PyCryptodome
does not support them.  secp256k1 delegates to embit's native
implementation.
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
# Pure-Python EC point multiplication (for Brainpool curves)
# ---------------------------------------------------------------------------

def _ec_point_mul(p: int, a: int, Gx: int, Gy: int, d: int) -> tuple[int, int]:
    """Compute ``d * G`` on the curve ``y² = x³ + ax + b  (mod p)``.

    Uses the standard double-and-add algorithm.  The ``b`` coefficient is
    not needed for point operations — only ``p`` (field prime) and ``a``
    are required.

    Returns the affine coordinates ``(x, y)`` of the result.
    """

    def _add(px: int, py: int, qx: int, qy: int) -> tuple[int, int]:
        # Identity element represented as (0, 0).
        if px == 0 and py == 0:
            return qx, qy
        if qx == 0 and qy == 0:
            return px, py
        if px == qx:
            if py == qy and py != 0:
                lam = (3 * px * px + a) * pow(2 * py, -1, p) % p
            else:
                return 0, 0
        else:
            lam = (qy - py) * pow(qx - px, -1, p) % p
        rx = (lam * lam - px - qx) % p
        ry = (lam * (px - rx) - py) % p
        return rx, ry

    rx, ry = 0, 0
    tx, ty = Gx, Gy
    while d > 0:
        if d & 1:
            rx, ry = _add(rx, ry, tx, ty)
        tx, ty = _add(tx, ty, tx, ty)
        d >>= 1
    return rx, ry


# ---------------------------------------------------------------------------
# Brainpool curve parameters (field prime, coefficient a, generator point)
# from RFC 5639 — verified against OpenSSL ``ecparam -param_enc explicit``.
# ---------------------------------------------------------------------------

_BRAINPOOL_P256R1 = (  # (p, a, Gx, Gy)
    0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377,
    0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9,
    0x8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262,
    0x547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997,
)

_BRAINPOOL_P384R1 = (  # (p, a, Gx, Gy)
    0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53,
    0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826,
    0x1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E,
    0x8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315,
)

_BRAINPOOL_P512R1 = (  # (p, a, Gx, Gy)
    0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3,
    0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA,
    0x81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822,
    0x7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def ed25519_pub_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte seed."""
    from Cryptodome.PublicKey import ECC
    return ECC.construct(curve="Ed25519", seed=seed).public_key().export_key(format="raw")


def curve25519_pub_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte Curve25519 (X25519) public key from a 32-byte seed."""
    from Cryptodome.PublicKey import ECC
    return ECC.construct(curve="Curve25519", seed=seed).public_key().export_key(format="raw")


def secp256k1_pub_xy(d: int) -> tuple[int, int]:
    """Derive the secp256k1 public key ``(x, y)`` from private scalar *d*."""
    from embit import ec
    priv = ec.PrivateKey(d.to_bytes(32, "big"))
    pub = priv.get_public_key()
    pub.compressed = False
    raw = pub.sec()          # 0x04 || x (32 bytes) || y (32 bytes)
    return int.from_bytes(raw[1:33], "big"), int.from_bytes(raw[33:65], "big")


def nist_pub_xy(curve_name: str, d: int) -> tuple[int, int]:
    """Derive NIST public key ``(x, y)`` from private scalar *d*.

    *curve_name* must be one of ``"P-256"``, ``"P-384"``, or ``"P-521"``.
    """
    from Cryptodome.PublicKey import ECC
    key = ECC.construct(curve=curve_name, d=d)
    return int(key.pointQ.x), int(key.pointQ.y)


def brainpool_pub_xy(bits: int, d: int) -> tuple[int, int]:
    """Derive a Brainpool public key ``(x, y)`` from private scalar *d*.

    *bits* must be ``256``, ``384``, or ``512``.
    """
    params = {
        256: _BRAINPOOL_P256R1,
        384: _BRAINPOOL_P384R1,
        512: _BRAINPOOL_P512R1,
    }
    p, a, Gx, Gy = params[bits]
    return _ec_point_mul(p, a, Gx, Gy, d)
