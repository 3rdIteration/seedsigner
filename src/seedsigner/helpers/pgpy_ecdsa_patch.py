"""Monkey-patch PGPy to support secp256k1 and Brainpool ECDSA/ECDH operations.

PyCryptodome does not support secp256k1 or Brainpool curves for ``ECC.construct()``,
``ECC.generate()``, ECDSA signing/verification, or ECDH key agreement with those
curves.

This module patches PGPy's ``ECDSAPriv`` (sign, key generation), ``ECDSAPub``
(verify), ``ECDHPub`` (public key construction), ``ECDHPriv`` (private key
construction), and ``ECDHCipherText`` (encrypt/decrypt) to use the ``ecdsa``
library (already a seedsigner dependency) for those curves.  The original
PyCryptodome codepath is preserved for natively supported curves (P-256,
P-384, P-521, Ed25519, Curve25519).

Call :func:`apply` **once** before any PGPy operations involving secp256k1
or Brainpool keys.
"""

from __future__ import annotations

import hashlib
import os

import ecdsa as _ecdsa_lib
from ecdsa.util import sigencode_der, sigdecode_der

from pgpy.constants import EllipticCurveOID, PubKeyAlgorithm
from pgpy.packet import fields as _fields
from pgpy.packet.types import MPI

# ---------------------------------------------------------------------------
# Curve / hash mappings
# ---------------------------------------------------------------------------

_ECDSA_CURVES = {
    EllipticCurveOID.SECP256K1: _ecdsa_lib.SECP256k1,
    EllipticCurveOID.Brainpool_P256: _ecdsa_lib.BRAINPOOLP256r1,
    EllipticCurveOID.Brainpool_P384: _ecdsa_lib.BRAINPOOLP384r1,
    EllipticCurveOID.Brainpool_P512: _ecdsa_lib.BRAINPOOLP512r1,
}

# PyCryptodome hash modules are identified by digest_size (bytes).
_HASHLIB_BY_SIZE = {
    20: hashlib.sha1,
    28: hashlib.sha224,
    32: hashlib.sha256,
    48: hashlib.sha384,
    64: hashlib.sha512,
}

# ---------------------------------------------------------------------------
# Stash originals before patching
# ---------------------------------------------------------------------------

_orig_sign = None
_orig_verify = None
_orig_generate = None
_orig_ecdh_pub_pubkey = None
_orig_ecdh_priv_privkey = None
_orig_ecdh_ct_encrypt = None
_orig_ecdh_ct_decrypt = None

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_patched_curve(oid) -> bool:
    """Return True if this OID requires the ecdsa-library codepath."""
    return oid in _ECDSA_CURVES


def _hashfunc_for(hash_alg) -> callable:
    """Map a PyCryptodome hash *module* to a :mod:`hashlib` constructor."""
    size = getattr(hash_alg, "digest_size", None)
    if size and size in _HASHLIB_BY_SIZE:
        return _HASHLIB_BY_SIZE[size]
    return hashlib.sha256


def _ecdh_shared_x(curve, priv_scalar: int, pub_x: int, pub_y: int) -> bytes:
    """Compute ECDH shared secret x-coordinate.

    Returns big-endian bytes of the x-coordinate of ``priv_scalar * (pub_x, pub_y)``.
    """
    order = curve.generator.order()
    pub_point = _ecdsa_lib.ellipticcurve.PointJacobi(
        curve.curve, pub_x, pub_y, 1, order
    )
    shared = pub_point * priv_scalar
    byte_size = (curve.baselen)
    return int(shared.x()).to_bytes(byte_size, "big")


# ---------------------------------------------------------------------------
# ECDSA patches
# ---------------------------------------------------------------------------


def _patched_sign(self, sigdata, hash_alg):
    """ECDSA sign using the ``ecdsa`` library for unsupported curves."""
    curve = _ECDSA_CURVES.get(self.oid)
    if curve is None:
        return _orig_sign(self, sigdata, hash_alg)

    sk = _ecdsa_lib.SigningKey.from_secret_exponent(int(self.s), curve=curve)
    return sk.sign_deterministic(
        sigdata,
        hashfunc=_hashfunc_for(hash_alg),
        sigencode=sigencode_der,
    )


def _patched_verify(self, sigbytes, sigdata, hash_alg):
    """ECDSA verify using the ``ecdsa`` library for unsupported curves."""
    curve = _ECDSA_CURVES.get(self.oid)
    if curve is None:
        return _orig_verify(self, sigbytes, sigdata, hash_alg)

    try:
        x, y = int(self.p.x), int(self.p.y)
        order = curve.generator.order()
        point = _ecdsa_lib.ellipticcurve.PointJacobi(
            curve.curve, x, y, 1, order
        )
        vk = _ecdsa_lib.VerifyingKey.from_public_point(point, curve=curve)
        hashfunc = _hashfunc_for(hash_alg)
        vk.verify(sigbytes, sigdata, hashfunc=hashfunc, sigdecode=sigdecode_der)
    except (_ecdsa_lib.BadSignatureError, ValueError, TypeError):
        return False
    return True


def _patched_generate(self, oid):
    """Generate ECDSA key using the ``ecdsa`` library for unsupported curves."""
    oid_enum = EllipticCurveOID(oid)
    curve = _ECDSA_CURVES.get(oid_enum)
    if curve is None:
        return _orig_generate(self, oid)

    from pgpy.errors import PGPError

    if any(c != 0 for c in self):
        raise PGPError("Key is already populated!")

    self.oid = oid_enum
    sk = _ecdsa_lib.SigningKey.generate(curve=curve)
    vk = sk.get_verifying_key()
    key_bytes = curve.baselen
    x = int.from_bytes(vk.to_string()[:key_bytes], "big")
    y = int.from_bytes(vk.to_string()[key_bytes:], "big")
    self.p = _fields.ECPoint.from_values(
        self.oid.key_size,
        _fields.ECPointFormat.Standard,
        MPI(x),
        MPI(y),
    )
    self.s = MPI(int.from_bytes(sk.to_string(), "big"))
    self._compute_chksum()


# ---------------------------------------------------------------------------
# ECDH patches
# ---------------------------------------------------------------------------


def _patched_ecdh_ct_encrypt(cls, pk, *args):
    """ECDHCipherText.encrypt() with ecdsa-library fallback for unsupported curves."""
    from Cryptodome.Cipher import AES as _AES
    from Cryptodome.Util.Padding import pad as _pkcs7_pad

    km = pk.keymaterial
    if not _is_patched_curve(km.oid):
        return _orig_ecdh_ct_encrypt.__func__(cls, pk, *args)

    curve = _ECDSA_CURVES[km.oid]
    (_m,) = args
    m = _pkcs7_pad(_m, 8, style="pkcs7")
    ct = cls()

    # Generate ephemeral key pair
    eph_sk = _ecdsa_lib.SigningKey.generate(curve=curve)
    eph_vk = eph_sk.get_verifying_key()
    key_bytes = curve.baselen
    eph_x = int.from_bytes(eph_vk.to_string()[:key_bytes], "big")
    eph_y = int.from_bytes(eph_vk.to_string()[key_bytes:], "big")
    ct.p = _fields.ECPoint.from_values(
        km.oid.key_size, _fields.ECPointFormat.Standard, MPI(eph_x), MPI(eph_y)
    )

    # Compute shared secret: eph_priv * recipient_pub
    pub_x, pub_y = int(km.p.x), int(km.p.y)
    eph_d = int.from_bytes(eph_sk.to_string(), "big")
    s = _ecdh_shared_x(curve, eph_d, pub_x, pub_y)

    # Derive wrapping key and wrap
    z = km.kdf.derive_key(s, km.oid, PubKeyAlgorithm.ECDH, pk.fingerprint)
    ct.c = _AES.new(z, _AES.MODE_KW).seal(m)
    return ct


def _patched_ecdh_ct_decrypt(self, pk, *args):
    """ECDHCipherText.decrypt() with ecdsa-library fallback for unsupported curves."""
    from Cryptodome.Cipher import AES as _AES
    from Cryptodome.Util.Padding import unpad as _pkcs7_unpad

    km = pk.keymaterial
    if not _is_patched_curve(km.oid):
        return _orig_ecdh_ct_decrypt(self, pk, *args)

    curve = _ECDSA_CURVES[km.oid]

    # Reconstruct ephemeral public key from ciphertext
    eph_x, eph_y = int(self.p.x), int(self.p.y)
    priv_d = int(km.s)
    s = _ecdh_shared_x(curve, priv_d, eph_x, eph_y)

    # Derive wrapping key and unwrap
    z = km.kdf.derive_key(s, km.oid, PubKeyAlgorithm.ECDH, pk.fingerprint)
    _m = _AES.new(z, _AES.MODE_KW).unseal(bytes(self.c))
    return _pkcs7_unpad(_m, 8, style="pkcs7")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_applied = False


def apply():
    """Apply the monkey-patch (idempotent)."""
    global _orig_sign, _orig_verify, _orig_generate, _applied
    global _orig_ecdh_ct_encrypt, _orig_ecdh_ct_decrypt
    if _applied:
        return

    # ECDSA sign/verify/generate
    _orig_sign = _fields.ECDSAPriv.sign
    _orig_verify = _fields.ECDSAPub.verify
    _orig_generate = _fields.ECDSAPriv._generate
    _fields.ECDSAPriv.sign = _patched_sign
    _fields.ECDSAPub.verify = _patched_verify
    _fields.ECDSAPriv._generate = _patched_generate

    # ECDH encrypt/decrypt
    _orig_ecdh_ct_encrypt = _fields.ECDHCipherText.encrypt
    _orig_ecdh_ct_decrypt = _fields.ECDHCipherText.decrypt
    _fields.ECDHCipherText.encrypt = classmethod(_patched_ecdh_ct_encrypt)
    _fields.ECDHCipherText.decrypt = _patched_ecdh_ct_decrypt

    _applied = True
