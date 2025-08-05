import os
import sys

import pytest

# These tests require access to a blank JavaCard with either the Satochip
# or Seedkeeper applet already installed but not yet initialised. They are
# skipped unless RUN_JAVACARD_TESTS=1 is set in the environment.

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
    from smartcard.CardConnection import CardConnection  # type: ignore
except ModuleNotFoundError as e:  # pragma: no cover - dependency check
    pytest.skip(
        f"pysatochip dependency missing: {e}. Install pyscard and pysatochip to run.",
        allow_module_level=True,
    )

from embit import psbt, script
from embit.ec import PrivateKey, PublicKey
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
        connector = CardConnector(card_filter=[card_filter])  # type: ignore
        if not getattr(connector, "card_present", False):
            raise RuntimeError("card absent")

        # Ensure we have a live connection object regardless of pyscard version
        if not hasattr(connector.cardservice, "connection"):
            conn = connector.cardservice.createConnection()
            connector.cardservice.connection = conn  # type: ignore[attr-defined]
        connection = connector.cardservice.connection
        try:
            connection.connect(CardConnection.T1_protocol)
        except Exception:
            pass

        # Select the requested applet so subsequent commands target it
        try:
            connector.card_select()
        except Exception:
            pass

        return connector
    except Exception as e:  # pragma: no cover - hardware not present
        pytest.skip(f"{card_filter} card not detected: {e}")


def _parse_path(path: str) -> list[int]:
    """Convert BIP32 path string to list of indices."""
    if path.startswith("m/"):
        path = path[2:]
    if path == "m" or path == "":
        return []
    result = []
    for elem in path.split("/"):
        if elem.endswith("'"):
            result.append(int(elem[:-1]) | HARDENED_INDEX)
        else:
            result.append(int(elem))
    return result


def _setup_blank_card(connector) -> list[int]:
    """Ensure the card is blank and run initial setup with a test PIN."""
    status = connector.card_get_status()
    assert status is not None
    if status[3].get("setup_done"):
        pytest.skip("Card already initialised; tests require a blank card")

    card_pin = list(b"123456")
    connector.card_setup(
        5,
        5,
        card_pin,
        [0] * 16,
        3,
        5,
        [0] * 16,
        [0] * 16,
        1024,
        4096,
        0x01,
        0x01,
        0x01,
        option_flags=0,
        hmacsha160_key=None,
        amount_limit=0,
    )
    connector.set_pin(0, card_pin)
    _resp, sw1, sw2 = connector.card_verify_PIN()
    assert sw1 == 0x90 and sw2 == 0x00
    return card_pin


def _factory_reset(connector):
    """Return the card to an uninitialised state if possible."""
    try:  # pragma: no cover - best effort cleanup
        connector.card_reset_factory_signal()
    except Exception:
        pass


def _build_single_sig_psbt(connector, path: str, stype: str):
    key, _ = connector.card_bip32_get_extendedkey(path)
    pub = PublicKey.parse(key.get_public_key_bytes(compressed=True))
    deriv = _parse_path(path)

    if stype == "p2wpkh":
        spk = script.p2wpkh(pub)
        prev_out = TransactionOutput(1000, spk)
        prev_tx = Transaction(2, [], [prev_out], 0)
        inp = TransactionInput(prev_tx.txid(), 0, b"", 0xFFFFFFFF)
        tx = Transaction(2, [inp], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].witness_utxo = prev_out
    elif stype == "p2sh-p2wpkh":
        inner = script.p2wpkh(pub)
        spk = script.p2sh(inner)
        prev_out = TransactionOutput(1000, spk)
        prev_tx = Transaction(2, [], [prev_out], 0)
        inp = TransactionInput(prev_tx.txid(), 0, b"", 0xFFFFFFFF)
        tx = Transaction(2, [inp], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].witness_utxo = prev_out
        p.inputs[0].redeem_script = inner
    else:  # p2pkh
        spk = script.p2pkh(pub)
        prev_out = TransactionOutput(1000, spk)
        prev_tx = Transaction(2, [], [prev_out], 0)
        inp = TransactionInput(prev_tx.txid(), 0, b"", 0xFFFFFFFF)
        tx = Transaction(2, [inp], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].non_witness_utxo = prev_tx

    p.inputs[0].bip32_derivations[pub] = psbt.DerivationPath(
        fingerprint=b"\x00\x00\x00\x00", derivation=deriv
    )
    return p, pub


def _build_multisig_psbt(connector, path: str, stype: str):
    key, _ = connector.card_bip32_get_extendedkey(path)
    card_pub = PublicKey.parse(key.get_public_key_bytes(compressed=True))
    dummy1 = PrivateKey(b"\x01" * 32).get_public_key()
    dummy2 = PrivateKey(b"\x02" * 32).get_public_key()
    wsh = script.multisig(2, [card_pub, dummy1, dummy2])
    deriv = _parse_path(path)

    if stype == "p2wsh":
        spk = script.p2wsh(wsh)
        prev_out = TransactionOutput(1000, spk)
        prev_tx = Transaction(2, [], [prev_out], 0)
        inp = TransactionInput(prev_tx.txid(), 0, b"", 0xFFFFFFFF)
        tx = Transaction(2, [inp], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].witness_utxo = prev_out
        p.inputs[0].witness_script = wsh
    elif stype == "p2sh-p2wsh":
        inner = script.p2wsh(wsh)
        spk = script.p2sh(inner)
        prev_out = TransactionOutput(1000, spk)
        prev_tx = Transaction(2, [], [prev_out], 0)
        inp = TransactionInput(prev_tx.txid(), 0, b"", 0xFFFFFFFF)
        tx = Transaction(2, [inp], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].non_witness_utxo = prev_tx
        p.inputs[0].redeem_script = inner
        p.inputs[0].witness_script = wsh
    else:  # p2sh
        spk = script.p2sh(wsh)
        prev_out = TransactionOutput(1000, spk)
        prev_tx = Transaction(2, [], [prev_out], 0)
        inp = TransactionInput(prev_tx.txid(), 0, b"", 0xFFFFFFFF)
        tx = Transaction(2, [inp], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].non_witness_utxo = prev_tx
        p.inputs[0].redeem_script = wsh

    p.inputs[0].bip32_derivations[card_pub] = psbt.DerivationPath(
        fingerprint=b"\x00\x00\x00\x00", derivation=deriv
    )
    return p, card_pub


def test_satochip_workflow():
    """Exercise Satochip signing across all script types."""

    connector = _connect_or_skip("satochip")
    _setup_blank_card(connector)

    # Message signing
    msg_sig = sign_message_with_satochip("m/84'/0'/0'/0/0", "integration test", connector)
    assert msg_sig

    single_paths = {
        "p2pkh": "m/44'/0'/0'/0/0",
        "p2sh-p2wpkh": "m/49'/0'/0'/0/0",
        "p2wpkh": "m/84'/0'/0'/0/0",
    }
    for stype, path in single_paths.items():
        p, pub = _build_single_sig_psbt(connector, path, stype)
        signed = sign_psbt_with_satochip(p, connector)
        assert signed == 1
        assert pub in p.inputs[0].partial_sigs

    multi_paths = {
        "p2sh": "m/45'/0'/0'/0/0",
        "p2sh-p2wsh": "m/48'/0'/0'/1'/0/0",
        "p2wsh": "m/48'/0'/0'/2'/0/0",
    }
    for stype, path in multi_paths.items():
        p, pub = _build_multisig_psbt(connector, path, stype)
        signed = sign_psbt_with_satochip(p, connector)
        assert signed == 1
        assert pub in p.inputs[0].partial_sigs

    _factory_reset(connector)
    connector.disconnect()


def test_seedkeeper_workflow():
    """Exercise secret-management functionality of a Seedkeeper card."""

    connector = _connect_or_skip("seedkeeper")
    _setup_blank_card(connector)

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

    _factory_reset(connector)
    connector.disconnect()

