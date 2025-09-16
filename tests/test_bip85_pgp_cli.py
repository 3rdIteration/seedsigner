import inspect
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parent.parent / "tools"))
import bip85_pgp

try:
    from pgpy.constants import EllipticCurveOID
except ImportError:  # pragma: no cover - dependency missing in environment
    EllipticCurveOID = None
else:
    _curve_cls = EllipticCurveOID.Brainpool_P256.curve
    if _curve_cls is not None and inspect.isabstract(_curve_cls):
        _BRAINPOOL_P256_ORDER = (
            0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
        )

        class _BrainpoolP256R1Fixed(_curve_cls):
            @property
            def group_order(self):  # pragma: no cover - simple property
                return _BRAINPOOL_P256_ORDER

        EllipticCurveOID.Brainpool_P256.curve = _BrainpoolP256R1Fixed


MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


PGP_PRIMARY_KEY_VECTORS = (
    ("p256", "3374F7A064CB1852FB4125B67425C6BAE0AA45A3"),
    ("brainpoolp256r1", "710ACBBE07535E996F1BCB52137B423AD982C3AB"),
    ("rsa2048", "ECC1557BE1B91255FAC1BB370ABFE55998DF2870"),
    ("rsa3072", "668E7C53F00725C85040FB9F79968E741014229F"),
    ("rsa4096", "6784BC8345BAEF74ED426F55903131B578BB929C"),
    ("secp256k1", "501587912640CB9C6CA3E4A0FAB3C5734A95416E"),
    ("ed25519", "9837B7E85F711F478DBE22EB641301EA97DA37C5"),
)


@pytest.mark.parametrize("primary_type, expected_fingerprint", PGP_PRIMARY_KEY_VECTORS)
def test_primary_key_vectors(primary_type, expected_fingerprint):
    key = bip85_pgp.create_bip85_pgp_key(
        MNEMONIC,
        key_index=0,
        primary_type=primary_type,
        name="Tester",
        email="test@example.com",
    )
    assert key.fingerprint == expected_fingerprint
    pub = bip85_pgp.export_public_key(key)
    priv = bip85_pgp.export_private_key(key)
    assert pub.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert priv.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")


def test_generate_pgp_key_with_subkeys():
    key = bip85_pgp.create_bip85_pgp_key(
        MNEMONIC,
        key_index=0,
        primary_type="p256",
        name="Tester",
        email="test@example.com",
        subkey_type="p256",
        additional_sets=1,
    )
    assert len(key.subkeys) == 6


def test_cli_key_type_choices_include_all_curves():
    expected = {
        "p256",
        "brainpoolp256r1",
        "rsa2048",
        "rsa3072",
        "rsa4096",
        "secp256k1",
        "ed25519",
    }
    assert expected.issubset(set(bip85_pgp.CLI_KEY_TYPE_CODES))
