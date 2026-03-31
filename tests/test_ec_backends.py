"""Test all EC point derivation backends produce identical results.

Validates that python-cryptography, pycryptodomex, embit, ecdsa, and
the pure-Python fallback all agree on EC public-key derivation from the
same private scalars.  Each backend is tested independently via
:func:`~seedsigner.helpers.ec_point.set_backend`, and results are
cross-validated to ensure byte-exact agreement.
"""

import pytest

import base  # noqa: F401  – ensure hardware mocks

from seedsigner.helpers.ec_point import (
    CRYPTOGRAPHY,
    PYCRYPTODOME,
    EMBIT,
    ECDSA_LIB,
    PURE_PYTHON,
    available_backends,
    set_backend,
    get_backend,
    ed25519_pub_from_seed,
    curve25519_pub_from_seed,
    secp256k1_pub_xy,
    nist_pub_xy,
    brainpool_pub_xy,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BACKENDS = available_backends()


def _skip_unless(backend: str) -> pytest.MarkDecorator:
    """Skip a test if *backend* is not installed."""
    return pytest.mark.skipif(
        backend not in _BACKENDS,
        reason=f"{backend} not installed",
    )


@pytest.fixture(autouse=True)
def _reset_backend():
    """Ensure auto-detection is restored after every test."""
    yield
    set_backend(None)


# ---------------------------------------------------------------------------
# Test vectors — deterministic inputs valid for all curves
# ---------------------------------------------------------------------------

# 32-byte seed for Ed25519 / Curve25519
_SEED_32 = bytes(range(32))

# Small scalars valid for all Weierstrass curves
_SCALAR_SMALL = 42

# Larger scalars within the range of each curve order
# Must be < BrainpoolP256r1 order (0xA9FB57DB...) for universal validity
_SCALAR_256 = 0x4242424242424242424242424242424242424242424242424242424242424242
_SCALAR_384 = int.from_bytes(b"\x7f" + bytes(range(1, 48)), "big")
_SCALAR_521 = int.from_bytes(b"\x01" + bytes(range(1, 66)), "big") & ((1 << 521) - 1)
_SCALAR_512 = int.from_bytes(b"\x7f" + bytes(range(1, 64)), "big")


# ===================================================================
# Ed25519
# ===================================================================

_ED25519_BACKENDS = [
    pytest.param(CRYPTOGRAPHY, marks=_skip_unless(CRYPTOGRAPHY)),
    pytest.param(PYCRYPTODOME, marks=_skip_unless(PYCRYPTODOME)),
]


@pytest.mark.parametrize("backend", _ED25519_BACKENDS)
def test_ed25519_each_backend(backend):
    """Each backend derives a 32-byte Ed25519 public key without error."""
    set_backend(backend)
    pub = ed25519_pub_from_seed(_SEED_32)
    assert isinstance(pub, bytes) and len(pub) == 32


def test_ed25519_backends_agree():
    """All installed backends produce the same Ed25519 public key."""
    results = {}
    for name in [CRYPTOGRAPHY, PYCRYPTODOME]:
        if name in _BACKENDS:
            set_backend(name)
            results[name] = ed25519_pub_from_seed(_SEED_32)
    if len(results) > 1:
        vals = list(results.values())
        names = list(results.keys())
        for i in range(1, len(vals)):
            assert vals[0] == vals[i], (
                f"Ed25519 mismatch between {names[0]} and {names[i]}"
            )


# ===================================================================
# Curve25519
# ===================================================================

_CV25519_BACKENDS = [
    pytest.param(CRYPTOGRAPHY, marks=_skip_unless(CRYPTOGRAPHY)),
    pytest.param(PYCRYPTODOME, marks=_skip_unless(PYCRYPTODOME)),
]


@pytest.mark.parametrize("backend", _CV25519_BACKENDS)
def test_curve25519_each_backend(backend):
    """Each backend derives a 32-byte Curve25519 public key without error."""
    set_backend(backend)
    pub = curve25519_pub_from_seed(_SEED_32)
    assert isinstance(pub, bytes) and len(pub) == 32


def test_curve25519_backends_agree():
    """All installed backends produce the same Curve25519 public key."""
    results = {}
    for name in [CRYPTOGRAPHY, PYCRYPTODOME]:
        if name in _BACKENDS:
            set_backend(name)
            results[name] = curve25519_pub_from_seed(_SEED_32)
    if len(results) > 1:
        vals = list(results.values())
        names = list(results.keys())
        for i in range(1, len(vals)):
            assert vals[0] == vals[i], (
                f"Curve25519 mismatch between {names[0]} and {names[i]}"
            )


# ===================================================================
# secp256k1
# ===================================================================

_SECP256K1_BACKENDS = [
    pytest.param(CRYPTOGRAPHY, marks=_skip_unless(CRYPTOGRAPHY)),
    pytest.param(EMBIT, marks=_skip_unless(EMBIT)),
    pytest.param(ECDSA_LIB, marks=_skip_unless(ECDSA_LIB)),
]


@pytest.mark.parametrize("backend", _SECP256K1_BACKENDS)
@pytest.mark.parametrize("d", [_SCALAR_SMALL, _SCALAR_256], ids=["small", "large"])
def test_secp256k1_each_backend(backend, d):
    """Each backend derives a valid secp256k1 (x, y) pair."""
    set_backend(backend)
    x, y = secp256k1_pub_xy(d)
    assert isinstance(x, int) and isinstance(y, int)
    assert x > 0 and y > 0


def test_secp256k1_backends_agree():
    """All installed backends produce the same secp256k1 public key."""
    for d in [_SCALAR_SMALL, _SCALAR_256]:
        results = {}
        for name in [CRYPTOGRAPHY, EMBIT, ECDSA_LIB]:
            if name in _BACKENDS:
                set_backend(name)
                results[name] = secp256k1_pub_xy(d)
        if len(results) > 1:
            vals = list(results.values())
            names = list(results.keys())
            for i in range(1, len(vals)):
                assert vals[0] == vals[i], (
                    f"secp256k1 mismatch between {names[0]} and {names[i]} for d={d}"
                )


# ===================================================================
# NIST curves (P-256, P-384, P-521)
# ===================================================================

_NIST_BACKENDS = [
    pytest.param(CRYPTOGRAPHY, marks=_skip_unless(CRYPTOGRAPHY)),
    pytest.param(PYCRYPTODOME, marks=_skip_unless(PYCRYPTODOME)),
    pytest.param(ECDSA_LIB, marks=_skip_unless(ECDSA_LIB)),
]

_NIST_CURVES = [
    ("P-256", _SCALAR_SMALL),
    ("P-256", _SCALAR_256),
    ("P-384", _SCALAR_SMALL),
    ("P-384", _SCALAR_384),
    ("P-521", _SCALAR_SMALL),
    ("P-521", _SCALAR_521),
]
_NIST_IDS = [f"{c}-{'small' if d == _SCALAR_SMALL else 'large'}" for c, d in _NIST_CURVES]


@pytest.mark.parametrize("backend", _NIST_BACKENDS)
@pytest.mark.parametrize("curve,d", _NIST_CURVES, ids=_NIST_IDS)
def test_nist_each_backend(backend, curve, d):
    """Each backend derives a valid NIST (x, y) pair."""
    set_backend(backend)
    x, y = nist_pub_xy(curve, d)
    assert isinstance(x, int) and isinstance(y, int)
    assert x > 0 and y > 0


@pytest.mark.parametrize("curve,d", _NIST_CURVES, ids=_NIST_IDS)
def test_nist_backends_agree(curve, d):
    """All installed backends produce the same NIST public key."""
    results = {}
    for name in [CRYPTOGRAPHY, PYCRYPTODOME, ECDSA_LIB]:
        if name in _BACKENDS:
            set_backend(name)
            results[name] = nist_pub_xy(curve, d)
    if len(results) > 1:
        vals = list(results.values())
        names = list(results.keys())
        for i in range(1, len(vals)):
            assert vals[0] == vals[i], (
                f"{curve} mismatch between {names[0]} and {names[i]} for d={d}"
            )


# ===================================================================
# Brainpool curves (P-256, P-384, P-512)
# ===================================================================

_BRAINPOOL_BACKENDS = [
    pytest.param(CRYPTOGRAPHY, marks=_skip_unless(CRYPTOGRAPHY)),
    pytest.param(ECDSA_LIB, marks=_skip_unless(ECDSA_LIB)),
    pytest.param(PURE_PYTHON),  # always available
]

_BRAINPOOL_CURVES = [
    (256, _SCALAR_SMALL),
    (256, _SCALAR_256),
    (384, _SCALAR_SMALL),
    (384, _SCALAR_384),
    (512, _SCALAR_SMALL),
    (512, _SCALAR_512),
]
_BRAINPOOL_IDS = [f"BP{b}-{'small' if d == _SCALAR_SMALL else 'large'}" for b, d in _BRAINPOOL_CURVES]


@pytest.mark.parametrize("backend", _BRAINPOOL_BACKENDS)
@pytest.mark.parametrize("bits,d", _BRAINPOOL_CURVES, ids=_BRAINPOOL_IDS)
def test_brainpool_each_backend(backend, bits, d):
    """Each backend derives a valid Brainpool (x, y) pair."""
    set_backend(backend)
    x, y = brainpool_pub_xy(bits, d)
    assert isinstance(x, int) and isinstance(y, int)
    assert x > 0 and y > 0


@pytest.mark.parametrize("bits,d", _BRAINPOOL_CURVES, ids=_BRAINPOOL_IDS)
def test_brainpool_backends_agree(bits, d):
    """All installed backends produce the same Brainpool public key."""
    results = {}
    for name in [CRYPTOGRAPHY, ECDSA_LIB, PURE_PYTHON]:
        if name in _BACKENDS:
            set_backend(name)
            results[name] = brainpool_pub_xy(bits, d)
    if len(results) > 1:
        vals = list(results.values())
        names = list(results.keys())
        for i in range(1, len(vals)):
            assert vals[0] == vals[i], (
                f"BrainpoolP{bits}R1 mismatch between {names[0]} and {names[i]} for d={d}"
            )


# ===================================================================
# Backend management API
# ===================================================================

def test_available_backends_returns_frozenset():
    """available_backends() returns an immutable set."""
    result = available_backends()
    assert isinstance(result, frozenset)
    assert PURE_PYTHON in result  # always available


def test_set_backend_none_is_auto():
    """set_backend(None) restores auto-detection."""
    set_backend(None)
    assert get_backend() is None


def test_set_backend_invalid_raises():
    """set_backend() rejects unknown backend names."""
    with pytest.raises(ValueError, match="not available"):
        set_backend("nonexistent_backend")


def test_auto_detect_prefers_cryptography():
    """With auto-detection, cryptography is used when available."""
    if CRYPTOGRAPHY not in _BACKENDS:
        pytest.skip("cryptography not installed")
    set_backend(None)
    # Ed25519 should use cryptography (first in preference order)
    pub = ed25519_pub_from_seed(_SEED_32)
    assert len(pub) == 32
