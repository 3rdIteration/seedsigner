import os
import sys

import pytest

# These tests require access to a physical JavaCard with either the
# Satochip or Seedkeeper applet already installed.  They will be skipped
# automatically unless the RUN_JAVACARD_TESTS environment variable is set.

if os.environ.get("RUN_JAVACARD_TESTS") != "1":
    pytest.skip(
        "Hardware JavaCard tests disabled. Set RUN_JAVACARD_TESTS=1 to run",
        allow_module_level=True,
    )

# Remove MagicMock placeholders inserted by tests/conftest so that we can
# import the real pysatochip and pyscard modules when present.
for mod in list(sys.modules):
    if mod.startswith("pysatochip") or mod.startswith("smartcard"):
        sys.modules.pop(mod, None)
try:
    from pysatochip.CardConnector import CardConnector, WrongPinError  # type: ignore
    from pysatochip.JCconstants import (  # type: ignore
        SEEDKEEPER_DIC_EXPORT_RIGHTS,
        SEEDKEEPER_DIC_TYPE,
    )
except ModuleNotFoundError as e:  # pragma: no cover - dependency check
    pytest.skip(
        f"pysatochip dependency missing: {e}. Install pyscard and pysatochip to run.",
        allow_module_level=True,
    )

from embit import psbt, script
from embit.ec import PublicKey
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from seedsigner.helpers.satochip_signer import (
    sign_message_with_satochip,
    sign_psbt_with_satochip,
)

try:  # pragma: no cover - compatibility shim for older embit versions
    from embit.bip32 import HARDENED_INDEX  # type: ignore
except ImportError:  # pragma: no cover - constant not present
    HARDENED_INDEX = 0x80000000


def _connect_or_skip(card_filter: str):
    """Attempt to connect to the specified card or skip if unavailable."""
    try:
        return CardConnector(card_filter=[card_filter])  # type: ignore
    except Exception as e:  # pragma: no cover - hardware not present
        pytest.skip(f"{card_filter} card not detected: {e}")


def test_satochip_workflow():
    """Exercise signing functionality of an initialized Satochip card."""

    connector = _connect_or_skip("satochip")
    status = connector.card_get_status()
    assert status is not None

    # Sign a message
    message_sig = sign_message_with_satochip(
        "m/84'/0'/0'/0/0", "integration test", connector
    )
    assert message_sig

    # Sign a dummy PSBT
    key, _ = connector.card_bip32_get_extendedkey("m/84'/0'/0'/0/0")
    pub = PublicKey.parse(key.get_public_key_bytes(compressed=True))
    spk = script.p2wpkh(pub)
    inp = TransactionInput(bytes(32), 0, b"", 0xFFFFFFFF)
    out = TransactionOutput(1000, spk)
    tx = Transaction(version=2, vin=[inp], vout=[out], locktime=0)
    p = psbt.PSBT(tx)
    p.inputs[0].witness_utxo = out
    deriv = [84 | HARDENED_INDEX, 0 | HARDENED_INDEX, 0 | HARDENED_INDEX, 0, 0]
    p.inputs[0].bip32_derivations[pub] = psbt.DerivationPath(
        fingerprint=b"\x00\x00\x00\x00", derivation=deriv
    )
    signed = sign_psbt_with_satochip(p, connector)
    assert signed == 1
    assert pub in p.inputs[0].partial_sigs

    connector.disconnect()


def test_seedkeeper_workflow():
    """Exercise secret-management functionality of a Seedkeeper card."""

    connector = _connect_or_skip("seedkeeper")

    # Change and verify card label, then restore to default
    connector.card_set_label("pytest")
    _, _, _, label = connector.card_get_label()
    assert label == "pytest"
    connector.card_set_label("")

    # Set and reset NFC policy
    connector.card_set_nfc_policy(1)
    _, _, _, status_dict = connector.card_get_status()
    assert status_dict.get("nfc_policy") == 1
    connector.card_set_nfc_policy(0)

    # Change PIN (create default if needed) and revert
    old_pin = list(b"123456")
    new_pin = list(b"654321")
    try:
        connector.card_change_PIN(0, old_pin, new_pin)
    except WrongPinError:
        connector.card_create_PIN(0, 3, old_pin, [0] * 16)
        connector.card_change_PIN(0, old_pin, new_pin)
    connector.card_change_PIN(0, new_pin, old_pin)

    # Import, export, and remove all supported secret types
    for code, name in SEEDKEEPER_DIC_TYPE.items():
        header = connector.make_header(
            code,
            SEEDKEEPER_DIC_EXPORT_RIGHTS["Plaintext export allowed"],
            name,
        )
        secret_bytes = f"{name} secret".encode()
        secret_list = [len(secret_bytes)] + list(secret_bytes)
        secret_dic = {"header": header, "secret_list": secret_list}

        sid, _ = connector.seedkeeper_import_secret(secret_dic)
        headers = connector.seedkeeper_list_secret_headers()
        assert any(h[0] == sid for h in headers)

        exported = connector.seedkeeper_export_secret(sid, None)
        assert bytes(exported.get("secret", [])) == secret_bytes

        connector.seedkeeper_reset_secret(sid)
        headers_after_reset = connector.seedkeeper_list_secret_headers()
        assert all(h[0] != sid for h in headers_after_reset)

    connector.disconnect()

