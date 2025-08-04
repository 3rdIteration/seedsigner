import os
import sys
import subprocess
from pathlib import Path

import pytest

# These tests require access to a physical JavaCard and the Satochip-DIY
# toolchain.  They will be skipped automatically unless the
# RUN_JAVACARD_TESTS environment variable is set.  The tests also expect the
# Satochip-DIY repository to be available locally and the system to have a
# working Java environment with the `java` and `ant` commands in PATH.

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
        SEEDKEEPER_DIC_TYPE,
        SEEDKEEPER_DIC_EXPORT_RIGHTS,
    )
except ModuleNotFoundError as e:  # pragma: no cover - dependency check
    pytest.skip(
        f"pysatochip dependency missing: {e}. Install pyscard and pysatochip to run.",
        allow_module_level=True,
    )

from seedsigner.helpers.satochip_signer import (
    sign_message_with_satochip,
    sign_psbt_with_satochip,
)
from embit import psbt, script
from embit.transaction import (
    Transaction,
    TransactionInput,
    TransactionOutput,
)
from embit.ec import PublicKey
from embit.bip32 import HARDENED_INDEX

DIY_PATH = Path(os.environ.get("SATOCHIP_DIY_PATH", "../Satochip-DIY")).resolve()
GP_JAR = DIY_PATH / "gp.jar"
BUILD_DIR = DIY_PATH / "build"
SATOCHIP_CAP = BUILD_DIR / "SatoChip-official-3.0.4.cap"
SEEDKEEPER_CAP = BUILD_DIR / "SeedKeeper-official-3.0.4.cap"

SATOCHIP_AID = "5361746F43686970"
SEEDKEEPER_AID = "536565644b6565706572"


def gp_command(*args: str) -> None:
    """Run a GlobalPlatformPro command."""
    subprocess.check_call(["java", "-jar", str(GP_JAR), *args])


def ensure_caps_present() -> None:
    """Build CAP files if they are missing."""
    if not (SATOCHIP_CAP.exists() and SEEDKEEPER_CAP.exists()):
        subprocess.check_call(["ant"], cwd=str(DIY_PATH))


def test_flash_and_exercise_satochip_and_seedkeeper(tmp_path):
    ensure_caps_present()

    # Ensure the card starts in a clean state.
    gp_command("--delete", SATOCHIP_AID, "-f")
    gp_command("--delete", SEEDKEEPER_AID, "-f")

    # --- Satochip applet ---
    gp_command("--install", str(SATOCHIP_CAP))
    connector = CardConnector(card_filter=["satochip"])  # type: ignore
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
    gp_command("--delete", SATOCHIP_AID, "-f")

    # --- Seedkeeper applet ---
    gp_command("--install", str(SEEDKEEPER_CAP))
    connector = CardConnector(card_filter=["seedkeeper"])  # type: ignore

    # Change and verify card label
    connector.card_set_label("pytest")
    _, _, _, label = connector.card_get_label()
    assert label == "pytest"

    # Set and reset NFC policy
    connector.card_set_nfc_policy(1)
    _, _, _, status_dict = connector.card_get_status()
    assert status_dict.get("nfc_policy") == 1
    connector.card_set_nfc_policy(0)
    _, _, _, status_dict = connector.card_get_status()
    assert status_dict.get("nfc_policy") == 0

    # Change PIN (create default if needed)
    old_pin = list(b"123456")
    new_pin = list(b"654321")
    try:
        connector.card_change_PIN(0, old_pin, new_pin)
    except WrongPinError:
        connector.card_create_PIN(0, 3, old_pin, [0] * 16)
        connector.card_change_PIN(0, old_pin, new_pin)
    # Revert to original PIN
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
    gp_command("--delete", SEEDKEEPER_AID, "-f")
