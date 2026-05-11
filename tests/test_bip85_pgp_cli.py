import inspect
import shutil
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
    # pgpy ships ``Brainpool_P256/P384/P512`` as abstract classes missing
    # the ``group_order`` property (cryptography lib upstream removed it
    # at some point); fill it in from RFC 5639 so the BIP85→PGP tests can
    # actually generate keys.
    _BRAINPOOL_ORDERS = {
        "Brainpool_P256": (
            0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
        ),
        "Brainpool_P384": (
            0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565
        ),
        "Brainpool_P512": (
            0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069
        ),
    }
    for _oid_name, _order in _BRAINPOOL_ORDERS.items():
        _oid = getattr(EllipticCurveOID, _oid_name, None)
        if _oid is None:
            continue
        _curve_cls = _oid.curve
        if _curve_cls is None or not inspect.isabstract(_curve_cls):
            continue

        # The closure must capture _order by default arg, not by name —
        # the loop variable is shared across the generated classes.
        class _BrainpoolFixed(_curve_cls):  # noqa: N801 - dynamic name fine
            _order_value = _order

            @property
            def group_order(self):  # pragma: no cover - simple property
                return type(self)._order_value

        _oid.curve = _BrainpoolFixed


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
    ("p521", "DD344D1E23FADA0AF7377745F1CDB8D4298A8ED6"),
    ("brainpoolp384r1", "4944AABFFF341DB44485B33C7F3F5BBD0B7BCA78"),
    ("brainpoolp512r1", "486CC1FE4EDB82714E347153D8D628E15995698F"),
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


# Key types that can be tested quickly (ECC only — RSA takes minutes).
ECC_KEY_TYPES = [
    "ed25519",
    "secp256k1",
    "p256",
    "p384",
    "p521",
    "brainpoolp256r1",
    "brainpoolp384r1",
    "brainpoolp512r1",
]


@pytest.mark.parametrize("primary_type", ECC_KEY_TYPES)
def test_private_key_export_all_types(primary_type):
    """Every key type must produce valid ASCII-armored private key output."""
    key = bip85_pgp.create_bip85_pgp_key(
        MNEMONIC,
        key_index=0,
        primary_type=primary_type,
        name="Export Test",
        email="export@test.com",
    )
    priv = bip85_pgp.export_private_key(key)
    assert priv.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert "-----END PGP PRIVATE KEY BLOCK-----" in priv


@pytest.mark.parametrize("primary_type", ECC_KEY_TYPES)
def test_private_key_export_with_subkeys(primary_type):
    """Every key type with subkeys must produce valid private key output."""
    key = bip85_pgp.create_bip85_pgp_key(
        MNEMONIC,
        key_index=0,
        primary_type=primary_type,
        name="Export Test",
        email="export@test.com",
        subkey_type=primary_type,
    )
    assert len(key.subkeys) >= 3
    priv = bip85_pgp.export_private_key(key)
    assert priv.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert "-----END PGP PRIVATE KEY BLOCK-----" in priv


# Key types that can be tested with GPG import (256-bit keys work with
# SHA-256 self-signatures; larger curves require SHA-384/512 which pgpy
# doesn't configure automatically).
GPG_COMPATIBLE_KEY_TYPES = [
    "ed25519",
    "secp256k1",
    "p256",
    "brainpoolp256r1",
]


@pytest.mark.skipif(
    sys.platform in ("darwin", "win32") or shutil.which("gpg") is None,
    reason="requires working GnuPG2",
)
@pytest.mark.parametrize("primary_type", GPG_COMPATIBLE_KEY_TYPES)
def test_gpg_roundtrip_import_export(primary_type, tmp_path):
    """BIP85 keys must survive a GPG import→export round-trip."""
    import os
    import subprocess

    gnupghome = str(tmp_path / "gnupg")
    os.makedirs(gnupghome, mode=0o700)
    env = {**os.environ, "GNUPGHOME": gnupghome}

    key = bip85_pgp.create_bip85_pgp_key(
        MNEMONIC,
        key_index=0,
        primary_type=primary_type,
        name="Roundtrip Test",
        email="roundtrip@test.com",
        subkey_type=primary_type if primary_type == "ed25519" else None,
    )

    armored = bip85_pgp.export_private_key(key)
    fpr = str(key.fingerprint).replace(" ", "")

    # Import
    r = subprocess.run(
        ["gpg", "--batch", "--import"],
        input=armored.encode(),
        capture_output=True,
        env=env,
    )
    assert r.returncode == 0, f"Import failed: {r.stderr.decode()}"
    assert "lower 3 bits" not in r.stderr.decode(), (
        f"Cv25519 clamping warning during import: {r.stderr.decode()}"
    )

    # Export private key
    r2 = subprocess.run(
        ["gpg", "--armor", "--export-secret-keys", fpr],
        capture_output=True,
        text=True,
        env=env,
    )
    assert r2.returncode == 0, f"Private export failed: {r2.stderr}"
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" in r2.stdout
