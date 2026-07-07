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
    ("p256", "8428627E1E6B48F9004583BD8115D9380DEEC6AF"),
    ("brainpoolp256r1", "EAE13800CA8A5086236AAE17315838E7C0E240B1"),
    ("rsa2048", "0834BA10384C8F2E9D8497AF9529A76933812D71"),
    ("rsa3072", "54815E62E0BDEFF7803CD0071A46ACFB405DBC49"),
    ("rsa4096", "F6CB403856E6FCE0EDD1BE956D20A28AAEB2D96C"),
    ("secp256k1", "2272AE7AF4F3EB1CC901EA1533D98307A7643D10"),
    ("ed25519", "2F9351B971526B7CEE6937B922AD9D3566B9DA58"),
    ("p384", "FF32568051653161A89E121C14D102049BCE01F9"),
    ("p521", "CFE0A4F8C659AE83BC10C6DC04EE2A5F49B28382"),
    ("brainpoolp384r1", "6A9CA22684C850F44FC7ACF40966E83AC7D96A74"),
    ("brainpoolp512r1", "5DA951CBDBEDADB6FD7C0DE651D2BCCC1E9B80C5"),
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
