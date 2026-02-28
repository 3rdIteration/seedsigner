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
    ("p256", "0BF339995A11016A845BACFEABBC8853BA3DF0A1"),
    ("brainpoolp256r1", "A62AE9A4B7ED113DF862C4D51D7E6E45BDAEF94C"),
    ("rsa2048", "0834BA10384C8F2E9D8497AF9529A76933812D71"),
    ("rsa3072", "54815E62E0BDEFF7803CD0071A46ACFB405DBC49"),
    ("rsa4096", "F6CB403856E6FCE0EDD1BE956D20A28AAEB2D96C"),
    ("secp256k1", "3673A1D4C16969043B18F8BB7F4EBA98175298F1"),
    ("ed25519", "14E5E1C61CDF70FBE296DEBD83743E4131F7F3F4"),
    ("p384", "16F9F12C3AF4D4239156B914BE144D9E334240D8"),
    ("p521", "4ED14BBCA7B750D68B1A5CFBEC161884D26C81DA"),
    ("brainpoolp384r1", "4944AABFFF341DB44485B33C7F3F5BBD0B7BCA78"),
    ("brainpoolp512r1", "498270A939A33ECD447C6BFF491BAE6C86CE1A3A"),
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
        "p384",
        "p521",
        "brainpoolp256r1",
        "brainpoolp384r1",
        "brainpoolp512r1",
        "rsa2048",
        "rsa3072",
        "rsa4096",
        "secp256k1",
        "ed25519",
    }
    assert expected.issubset(set(bip85_pgp.CLI_KEY_TYPE_CODES))
