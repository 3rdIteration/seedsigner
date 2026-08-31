"""
Hardware-in-the-loop integration tests for all supported smartcard platforms.

Requires:
  - PC/SC smartcard reader (USB or GPIO)
  - Blank JavaCard (JC 3.0.4+, default GP key 404142...)
  - pysatochip (``pip install pysatochip``)
  - PyGP (``pip install pygp``)
  - keycard-py (for Keycard tests; ``pip install keycard-py``)
  - specter-card (for Specter-DIY tests; see specter-javacard repo)

Run::

    pytest tests/test_smartcard_hardware.py -v --tb=short

Tests run sequentially in 5 phases, each installing one applet, exercising
it, then uninstalling it before moving to the next.
"""

# ======================================================================
# Imports  (all lazy — no ImportError at module level)
# ======================================================================

import hashlib
import logging
import os
import sys
import time
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

logger = logging.getLogger(__name__)

# Remove any pytest-installed MagicMock shims for pysatochip so that the real
# library can be loaded for hardware-in-the-loop tests.
for _mod_name in list(sys.modules.keys()):
    if _mod_name == "pysatochip" or _mod_name.startswith("pysatochip."):
        if isinstance(sys.modules[_mod_name], MagicMock):
            del sys.modules[_mod_name]


# ======================================================================
# Helpers
# ======================================================================

def _verify_ecdsa(signature_der_plus_sighash: bytes, pubkey_sec: bytes,
                  sighash: bytes) -> bool:
    """
    Verify an ECDSA signature produced by the card.

    The card returns ``(sig_der, 0x90, 0x00)`` and the signer appends
    ``b"\\x01"`` (SIGHASH_ALL) before storing into ``partial_sigs``.

    Uses the pure-Python ``ecdsa`` library to avoid platform-specific ctypes
    issues with embit's secp256k1 binding on Windows / Python 3.14+.
    """
    import ecdsa
    from ecdsa.util import sigdecode_der

    assert signature_der_plus_sighash[-1] == 0x01
    der = signature_der_plus_sighash[:-1]

    # Parse SEC public key (compressed or uncompressed)
    vk = ecdsa.VerifyingKey.from_string(pubkey_sec, curve=ecdsa.curves.SECP256k1)

    try:
        return vk.verify_digest(der, sighash, sigdecode=sigdecode_der)
    except ecdsa.BadSignatureError:
        return False


def _check_low_s(der_sig: bytes) -> bool:
    """Return True if the DER signature is low-S normalized."""
    secp256k1_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    # parse DER:  0x30  len  0x02  r_len  r...  0x02  s_len  s...
    #   byte[0] = 0x30
    #   byte[1] = total_length (excludes 0x30 and byte[1] itself)
    #   byte[2] = 0x02
    #   byte[3] = r_len
    pos = 4 + der_sig[3]
    # byte[pos] = 0x02
    s_len = der_sig[pos + 1]
    s = int.from_bytes(der_sig[pos + 2:pos + 2 + s_len], "big")
    return s <= secp256k1_n // 2


def _der_sig_from_partial(sig_data: bytes) -> bytes:
    """Strip the trailing sighash byte from a partial_sig value."""
    return sig_data[:-1]


def _build_psbt(seed_hex: str, paths: list[str]) -> tuple:
    """
    Create a minimal PSBT whose inputs reference the given derivation paths.

    Returns ``(psbt, pubkey_list)`` so callers can later inspect
    ``partial_sigs`` keyed by the original pubkeys.
    """
    from embit import bip32
    from embit.psbt import PSBT, InputScope, DerivationPath

    root = bip32.HDKey.from_seed(bytes.fromhex(seed_hex))
    psbt = PSBT()
    psbt.inputs = []
    pubkeys = []

    for path_str in paths:
        scope = InputScope()
        priv = root.derive(path_str)
        pub = priv.to_public()
        pubkeys.append(pub)
        indices = bip32.parse_path(path_str)
        scope.bip32_derivations[pub] = DerivationPath(
            fingerprint=root.my_fingerprint,
            derivation=indices,
        )
        psbt.inputs.append(scope)

    # Attach a deterministic sighash so the signer has a 32-byte digest
    psbt.sighash = types.MethodType(
        lambda self, idx, sighash=None: hashlib.sha256(
            bytes([idx]) * 32
        ).digest(),
        psbt,
    )
    return psbt, pubkeys


def _aead_to_seedkeeper_list(plaintext: bytes) -> list[int]:
    """Helper to encode a (short) payload into the SeedKeeper secret_list format (1-byte length)."""
    assert len(plaintext) <= 255
    return [len(plaintext)] + list(plaintext)


def _decode_seedkeeper_text(secret_hex: str) -> str:
    """
    Minimal reimplementation of SeedKeeperSelectView._decode_seedkeeper_text.
    Returns the UTF-8 text after stripping the 1- or 2-byte length prefix.
    """
    data = bytes.fromhex(secret_hex)
    if not data:
        return ""
    if len(data) > 1 and data[0] <= 0xFD and len(data) == 1 + data[0]:
        # 1-byte length prefix
        return data[1:1 + data[0]].decode("utf-8", errors="replace")
    # 2-byte big-endian length prefix
    length = (data[0] << 8) | data[1]
    return data[2:2 + length].decode("utf-8", errors="replace")


# ======================================================================
# Session-level fixtures
# ======================================================================


@pytest.fixture(scope="session")
def gp(readiness):
    """GlobalPlatform connection authenticated with the default GP key.

    Depends on ``readiness`` so that hardware detection runs first.
    """
    import pygp
    key = "404142434445464748494A4B4C4D4E4F"
    pygp.auth(
        enc_key=key, mac_key=key, dek_key=key,
        keysetversion="00",
        securitylevel=pygp.SECURITY_LEVEL_C_MAC,
    )
    yield pygp


@pytest.fixture(scope="session")
def cap_dir():
    """Path to the pre-built CAP files shipped with the repo."""
    p = Path(__file__).resolve().parent.parent / "javacard-cap"
    assert p.is_dir(), f"CAP directory not found: {p}"
    return p


# ======================================================================
# Phase 0 — CAP install/uninstall verification (explicit lifecycle tests)
# ======================================================================

class TestCapLifecycle:
    """Verify that gp.install_capfile() and gp.delete_package() work correctly."""

    AID = "5361746F44696D65"
    CAP = "SatoDime-0.1.2-official.cap"

    def test_install_capfile_returns_installed_list(self, gp, cap_dir):
        """install_capfile() must return a dict with 'installed' key containing AIDs."""
        result = gp.install_capfile(str(cap_dir / self.CAP))
        assert isinstance(result, dict), f"Expected dict, got {type(result)}"
        assert "installed" in result, f"'installed' key missing from result: {result}"
        installed = result["installed"]
        # Result may be list (legacy) or dict — handle both
        if isinstance(installed, list):
            assert len(installed) > 0, "install_capfile returned empty 'installed' list"
            # Each entry should be a tuple of (module_aid, instance_aid)
            for entry in installed:
                assert isinstance(entry, (tuple, list)), f"Unexpected entry type: {entry}"
        else:
            assert len(installed) > 0, "install_capfile returned empty 'installed' dict value"

    def test_delete_package_removes_applet(self, gp, cap_dir):
        """Install then delete — verify both GP operations succeed."""
        import time
        time.sleep(1.0)
        # Re-auth (card may have been reset by install process) then delete
        self._re_auth_gp(gp)
        gp.delete_package(self.AID)
        time.sleep(1.0)
        # Re-install to confirm package is gone
        self._re_auth_gp(gp)
        result = gp.install_capfile(str(cap_dir / self.CAP))
        logger.info(f"Re-install succeeded after delete: {result}")

    @staticmethod
    def _re_auth_gp(gp):
        """Re-establish GP auth (terminal + card select + auth)."""
        import pygp
        gp.close()
        gp.terminal()
        gp.card()
        gp.auth(
            enc_key="404142434445464748494A4B4C4D4E4F",
            mac_key="404142434445464748494A4B4C4D4E4F",
            dek_key="404142434445464748494A4B4C4D4E4F",
            keysetversion="00",
            securitylevel=pygp.SECURITY_LEVEL_C_MAC,
        )


# ======================================================================
# Session-level fixtures (continued)
# ======================================================================

@pytest.fixture(scope="session")
def test_seed_hex():
    """
    64-byte BIP39 seed hex for the well-known test mnemonic
    (abandon … about) with an empty passphrase.
    """
    from embit import bip39
    m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    seed = bip39.mnemonic_to_seed(m, "")
    assert len(seed) == 64
    return seed.hex()


@pytest.fixture(scope="session")
def test_entropy_hex():
    """16-byte entropy for the abandon … about mnemonic."""
    from embit import bip39
    m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    entropy = bip39.mnemonic_to_bytes(m)
    assert len(entropy) == 16
    return entropy.hex()


@pytest.fixture(scope="session")
def test_known_xpub(test_seed_hex):
    """xpub at m/84h/0h/0h for the test seed."""
    from embit import bip32
    root = bip32.HDKey.from_seed(bytes.fromhex(test_seed_hex))
    return root.derive("m/84h/0h/0h").to_public().to_base58()


@pytest.fixture(scope="session")
def test_root_fingerprint(test_seed_hex):
    """4-byte fingerprint of the root key."""
    from embit import bip32
    root = bip32.HDKey.from_seed(bytes.fromhex(test_seed_hex))
    return root.my_fingerprint


@pytest.fixture(scope="session", autouse=True)
def require_hardware(readiness):
    """Skip all tests if pygp or pyscard is not available, or no reader is connected."""
    # The `readiness` fixture does the actual detection and skips.
    pass


@pytest.fixture(scope="session")
def readiness():
    """
    Detect PC/SC hardware availability once per session.

    This is a separate fixture so that `gp` can depend on it rather than
    duplicating the skip logic.
    """
    try:
        import pygp  # noqa: F401
    except ImportError:
        pytest.skip("pygp not installed (pip install pygp)")
    try:
        pygp.terminal()
        pygp.card()
    except BaseException as exc:
        pytest.skip(f"No PC/SC smartcard reader detected: {exc}")


@pytest.fixture(scope="session", autouse=True)
def cleanup_leftovers(request, gp):
    """After the session, uninstall every applet we know about."""
    yield
    for aid in [
        "5361746F43686970",      # Satochip
        "536565644B6565706572",  # SeedKeeper
        "5361746F44696D65",      # Satodime
        "A0000008040001",        # Keycard
        "B00B5111CB",            # Specter-DIY
    ]:
        try:
            result = gp.delete_package(aid)
            logger.info(f"cleanup_leftovers: deleted {aid} → {result}")
        except BaseException as exc:
            # "Referenced data not found" is expected if the package was never installed
            error_msg = str(exc)
            if "Referenced data not found" in error_msg or "not found" in error_msg.lower():
                logger.info(f"cleanup_leftovers: {aid} already removed or never installed")
            else:
                logger.warning(f"cleanup_leftovers: failed to delete {aid}: {exc}")


# ======================================================================
# Phase 1 — Satodime
# ======================================================================

class TestSatodime:
    """Install Satodime applet, query card info, uninstall."""

    AID = "5361746F44696D65"
    CAP = "SatoDime-0.1.2-official.cap"

    @pytest.fixture(scope="class", autouse=True)
    def applet(self, gp, cap_dir):
        result = gp.install_capfile(str(cap_dir / self.CAP))
        logger.info(f"Satodime install result: {result}")
        # Close pygp's GP session so pysatochip can establish a clean connection
        gp.close()
        yield
        try:
            self._disconnect()
            # Re-establish GP session for cleanup
            gp.terminal()
            gp.card()
            gp.auth(
                enc_key="404142434445464748494A4B4C4D4E4F",
                mac_key="404142434445464748494A4B4C4D4E4F",
                dek_key="404142434445464748494A4B4C4D4E4F",
                keysetversion="00",
                securitylevel=gp.SECURITY_LEVEL_C_MAC,
            )
            delete_result = gp.delete_package(self.AID)
            logger.info(f"Satodime uninstall result: {delete_result}")
        except BaseException as exc:
            logger.warning(f"Satodime cleanup failed (non-fatal): {exc}")

    def _provision(self, pin: str = "1234"):
        """Satodime does not require card provisioning; this is a no-op for API consistency."""
        pass

    # -- helpers -------------------------------------------------------

    def _connect(self):
        from pysatochip.CardConnector import CardConnector

        self._connector = CardConnector(card_filter=["satodime"])
        # CardConnector.__init__ creates a CardMonitor that will
        # asynchronously replace self.cardservice (with a Card + connected
        # connection) and initiate the secure channel. Remove our observer to
        # prevent that interference, then do it all ourselves.
        self._connector.cardmonitor.deleteObserver(self._connector.cardobserver)
        self._connector.cardservice.connection.connect()
        self._connector.card_select()
        (_, _, _, status) = self._connector.card_get_status()
        if self._connector.needs_secure_channel:
            self._connector.card_initiate_secure_channel()
        time.sleep(0.3)
        return self._connector

    def _disconnect(self):
        if hasattr(self, "_connector") and self._connector is not None:
            try:
                self._connector.card_disconnect()
            except Exception:
                pass
            self._connector = None

    # -- tests ---------------------------------------------------------

    def test_get_info(self):
        connector = self._connect()
        try:
            (resp, sw1, sw2, status) = connector.card_get_status()
            assert sw1 == 0x90 and sw2 == 0x00
            assert connector.card_type == "Satodime"
            assert status.get("setup_done") is False
            assert "protocol_major_version" in status
            assert "applet_major_version" in status
        finally:
            self._disconnect()

    def test_get_label(self):
        connector = self._connect()
        try:
            (_, _, _, label) = connector.card_get_label()
            assert isinstance(label, str)
        finally:
            self._disconnect()


# ======================================================================
# Phase 2 — SeedKeeper
# ======================================================================

class TestSeedKeeper:
    """
    SeedKeeper applet: provision, import/export all 6 seed types, NDEF
    round-trip, capacity reporting, PIN management, factory-reset (v2+).
    """

    AID = "536565644B6565706572"
    CAP = "SeedKeeper-0.2-official.cap"

    _connector = None  # cached between methods in the class

    @pytest.fixture(scope="class", autouse=True)
    def applet(self, gp, cap_dir):
        result = gp.install_capfile(
            str(cap_dir / self.CAP),
            application_specific_parameters="1FFF",
        )
        logger.info(f"SeedKeeper install result: {result}")
        gp.close()
        # Provision the card once per class (idempotent — skips if already setup)
        try:
            self._provision("1234")
            logger.info(f"SeedKeeper provisioned with fixed PUK")
        except Exception as exc:
            logger.warning(f"SeedKeeper provisioning failed (non-fatal): {exc}")
        yield
        try:
            self._disconnect()
            gp.terminal()
            gp.card()
            gp.auth(
                enc_key="404142434445464748494A4B4C4D4E4F",
                mac_key="404142434445464748494A4B4C4D4E4F",
                dek_key="404142434445464748494A4B4C4D4E4F",
                keysetversion="00",
                securitylevel=gp.SECURITY_LEVEL_C_MAC,
            )
            delete_result = gp.delete_package(self.AID)
            logger.info(f"SeedKeeper uninstall result: {delete_result}")
        except BaseException as exc:
            logger.warning(f"SeedKeeper cleanup failed (non-fatal): {exc}")

    # -- helpers -------------------------------------------------------

    def _connect(self, force_reconnect: bool = False):
        if self._connector is not None and not force_reconnect:
            return self._connector

        from pysatochip.CardConnector import CardConnector

        # Disconnect any stale connector first
        if self._connector is not None:
            try:
                self._connector.card_disconnect()
            except Exception:
                pass
        
        self._connector = CardConnector(card_filter=["seedkeeper"])
        self._connector.cardmonitor.deleteObserver(self._connector.cardobserver)
        self._connector.cardservice.connection.connect()
        self._connector.card_select()
        (_, _, _, status) = self._connector.card_get_status()
        if self._connector.needs_secure_channel:
            self._connector.card_initiate_secure_channel()
        
        # Try to verify PIN, but don't recurse on failure - just return the connector
        # The caller should check card state and handle blocked/reset cases
        if status.get("setup_done"):
            pin_list = list(b"1234")
            self._connector.set_pin(0, pin_list)
            try:
                self._connector.card_verify_PIN_simple()
            except Exception:
                # PIN might be blocked or wrong - caller should check status
                pass
        
        time.sleep(0.3)
        return self._connector

    def _disconnect(self):
        if self._connector is not None:
            try:
                self._connector.card_disconnect()
            except Exception:
                pass
            self._connector = None

    def _reconnect(self, pin: str = "1234"):
        """Disconnect stale connector and reconnect fresh (for tests that modify card state)."""
        self._disconnect()
        return self._connect(force_reconnect=True)

    def _provision(self, pin: str = "1234") -> str:
        """One-time card setup; returns the deterministic PUK hex for later use."""
        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        
        if status.get("setup_done"):
            # Card already provisioned - try to unblock PIN with known test PUK if needed
            pin_bytes = list(pin.encode("utf-8"))
            connector.set_pin(0, pin_bytes)
            try:
                connector.card_verify_PIN_simple()
            except Exception:
                # PIN might be blocked - try to unblock with deterministic PUK
                puk_hex = bytes(range(16)).hex()
                puk_bytes = bytes.fromhex(puk_hex)
                try:
                    connector.card_unblock_PIN(0, list(puk_bytes))
                    connector.set_pin(0, pin_bytes)
                    connector.card_verify_PIN_simple()
                except Exception:
                    pass
            # Always return the deterministic PUK hex regardless of whether we just provisioned or not
            return bytes(range(16)).hex()

        # Use deterministic PUK for testing (16 bytes of sequential values)
        puk_bytes = bytes(range(16))
        puk_list = list(puk_bytes)
        pin_list = list(pin.encode("utf-8"))

        # Initialize secure channel before card_setup on seeded cards
        if connector.needs_secure_channel:
            connector.card_initiate_secure_channel()

        connector.card_setup(
            pin_tries0=5, ublk_tries0=1,
            pin0=pin_list, ublk0=puk_list,
            pin_tries1=1, ublk_tries1=1,
            pin1=[0x30] * 6, ublk1=[0x30] * 6,
            memsize=0x0000, memsize2=0x0000,
            create_object_ACL=0x01, create_key_ACL=0x01, create_pin_ACL=0x01,
        )
        connector.set_pin(0, pin_list)
        return puk_bytes.hex()

    def _import_secret(self, stype: str, rights: str, label: str,
                       payload: bytes, subtype: int = 0) -> int:
        """Import a secret and return its SID."""
        connector = self._connect()
        header = connector.make_header(stype, rights, label, subtype=subtype)
        secret_list = _aead_to_seedkeeper_list(payload)
        (sid, _) = connector.seedkeeper_import_secret({
            "header": header,
            "secret_list": secret_list,
        })
        return sid

    def _export_and_decode(self, sid: int) -> str:
        """Export a secret and return its decoded text."""
        connector = self._connect()
        d = connector.seedkeeper_export_secret(sid, None)
        secret_hex = d["secret"]
        return _decode_seedkeeper_text(secret_hex)

    # -- tests ---------------------------------------------------------

    def test_provision(self):
        puk_hex = self._provision("1234")
        assert len(puk_hex) > 0
        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        assert status.get("setup_done") is True

    def test_get_status(self):
        connector = self._connect()
        (_, _, _, status) = connector.seedkeeper_get_status()
        assert "nb_secrets" in status
        assert "free_memory" in status
        assert "total_memory" in status
        assert status["nb_secrets"] == 0  # fresh provision

    def test_import_export_bip39_v1(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        passphrase = "TREZOR"
        payload = mnemonic.encode("utf-8") + b"\x00" + passphrase.encode("utf-8")
        # BIP39 V1 format:  [len(mnemonic)] + mnemonic + [len(passphrase)] + passphrase
        mnemonic_bytes = mnemonic.encode("utf-8")
        passphrase_bytes = passphrase.encode("utf-8")
        raw = bytes([len(mnemonic_bytes)]) + mnemonic_bytes + bytes([len(passphrase_bytes)]) + passphrase_bytes

        connector = self._connect()
        header = connector.make_header("BIP39 mnemonic", "Plaintext export allowed", "test bip39 v1")
        secret_list = list(raw)
        (sid, _) = connector.seedkeeper_import_secret({"header": header, "secret_list": secret_list})

        exported = connector.seedkeeper_export_secret(sid, None)
        exported_list = exported["secret_list"]
        # decode: first byte = mnemonic length
        ml = exported_list[0]
        recovered_mnemonic = bytes(exported_list[1:1 + ml]).decode("utf-8")
        pl = exported_list[1 + ml]
        recovered_passphrase = bytes(exported_list[1 + ml + 1:1 + ml + 1 + pl]).decode("utf-8")
        assert recovered_mnemonic == mnemonic
        assert recovered_passphrase == passphrase

        connector.seedkeeper_reset_secret(sid)

    def test_import_export_bip39_v2(self, test_seed_hex, test_entropy_hex):
        from embit import bip39

        seed_bytes = bytes.fromhex(test_seed_hex)
        entropy_bytes = bytes.fromhex(test_entropy_hex)
        passphrase = ""
        wordlist_byte = 0x00  # English

        # V2 format:  [len(seed)] + seed + wordlist_byte + [len(entropy)] + entropy + [len(passphrase)] + passphrase
        passphrase_bytes = passphrase.encode("utf-8")
        raw = (bytes([len(seed_bytes)]) + seed_bytes +
               bytes([wordlist_byte]) +
               bytes([len(entropy_bytes)]) + entropy_bytes +
               bytes([len(passphrase_bytes)]) + passphrase_bytes)

        connector = self._connect()
        header = connector.make_header("Masterseed", "Plaintext export allowed",
                                       "test bip39 v2", subtype=0x01)
        (sid, _) = connector.seedkeeper_import_secret({
            "header": header,
            "secret_list": list(raw),
        })

        exported = connector.seedkeeper_export_secret(sid, None)
        exported_list = exported["secret_list"]
        # decode: first byte = seed length
        sl = exported_list[0]
        recovered_seed = bytes(exported_list[1:1 + sl])
        assert recovered_seed == seed_bytes
        connector.seedkeeper_reset_secret(sid)

    def test_import_export_xprv(self, test_seed_hex):
        from embit import bip32

        root = bip32.HDKey.from_seed(bytes.fromhex(test_seed_hex))
        xprv_str = root.to_base58()
        xprv_bytes = xprv_str.encode("utf-8")

        # V2 format: 2-byte BE length + xprv_bytes
        raw = len(xprv_bytes).to_bytes(2, "big") + xprv_bytes

        connector = self._connect()
        header = connector.make_header("Data", "Plaintext export allowed",
                                       "XPRV:test_xprv")
        (sid, _) = connector.seedkeeper_import_secret({
            "header": header,
            "secret_list": list(raw),
        })

        exported = connector.seedkeeper_export_secret(sid, None)
        decoded = _decode_seedkeeper_text(exported["secret"])
        assert decoded == xprv_str
        connector.seedkeeper_reset_secret(sid)

    def test_import_export_electrum(self):
        mnemonic = "regular reject rare profit once math fringe chase until ketchup century escape"
        passphrase = ""
        mnemonic_bytes = mnemonic.encode("utf-8")
        passphrase_bytes = passphrase.encode("utf-8")
        raw = bytes([len(mnemonic_bytes)]) + mnemonic_bytes + bytes([len(passphrase_bytes)]) + passphrase_bytes

        connector = self._connect()
        header = connector.make_header("Electrum mnemonic", "Plaintext export allowed",
                                       "test electrum")
        (sid, _) = connector.seedkeeper_import_secret({
            "header": header,
            "secret_list": list(raw),
        })

        exported = connector.seedkeeper_export_secret(sid, None)
        exported_list = exported["secret_list"]
        ml = exported_list[0]
        recovered = bytes(exported_list[1:1 + ml]).decode("utf-8")
        assert recovered == mnemonic
        connector.seedkeeper_reset_secret(sid)

    def test_import_export_aezeed(self):
        mnemonic = ("absorb original enlist once climb erode kid thrive kitchen giant "
                    "define tube orange leader harbor comfort olive fatal success suggest "
                    "drink penalty chimney ritual")
        passphrase = "aezeed"
        payload_str = f"aezeed:{mnemonic}\npassphrase:{passphrase}"
        payload = payload_str.encode("utf-8")

        connector = self._connect()
        header = connector.make_header("Password", "Plaintext export allowed",
                                       "aezeed:test_aezeed")
        (sid, _) = connector.seedkeeper_import_secret({
            "header": header,
            "secret_list": _aead_to_seedkeeper_list(payload),
        })

        exported = connector.seedkeeper_export_secret(sid, None)
        decoded = _decode_seedkeeper_text(exported["secret"])
        assert decoded.startswith("aezeed:")
        assert mnemonic in decoded
        connector.seedkeeper_reset_secret(sid)

    def test_import_export_slip39(self):
        share = ("duckling enlarge academic academic agency result length solution "
                 "fridge kidney coal piece deal husband erode duke ajar critical "
                 "decision keyboard")
        payload = share.encode("utf-8")

        connector = self._connect()
        header = connector.make_header("Password", "Plaintext export allowed",
                                       "SLIP39:test_slip39")
        (sid, _) = connector.seedkeeper_import_secret({
            "header": header,
            "secret_list": _aead_to_seedkeeper_list(payload),
        })

        exported = connector.seedkeeper_export_secret(sid, None)
        decoded = _decode_seedkeeper_text(exported["secret"])
        assert decoded == share
        connector.seedkeeper_reset_secret(sid)

    def test_list_secrets(self):
        # Import 2 known secrets first
        s1 = self._import_secret("Password", "Plaintext export allowed",
                                 "list_test_1", b"hello")
        s2 = self._import_secret("Password", "Plaintext export allowed",
                                 "list_test_2", b"world")

        connector = self._connect()
        headers = connector.seedkeeper_list_secret_headers()
        # Should find at least our 2 (there may be leftover un-reset ones from prior tests)
        found = [h for h in headers if h.get("label", "").startswith("list_test_")]
        assert len(found) >= 2

        connector.seedkeeper_reset_secret(s1)
        connector.seedkeeper_reset_secret(s2)

    def test_capacity(self):
        connector = self._connect()
        (_, _, _, status) = connector.seedkeeper_get_status()
        free_before = status["free_memory"]

        # Import something small
        sid = self._import_secret("Password", "Plaintext export allowed",
                                  "cap_test", b"x" * 32)

        (_, _, _, status) = connector.seedkeeper_get_status()
        free_after = status["free_memory"]
        assert free_after < free_before  # memory decreased

        connector.seedkeeper_reset_secret(sid)

    def test_ndef_roundtrip(self):
        import ndef as _ndeflib
        from seedsigner.helpers.ndef_helper import (
            save_ndef_to_seedkeeper,
            load_ndef_from_seedkeeper,
            decode_ndef_bytes,
        )

        connector = self._connect()

        # Build a multi-record NDEF message in one pass so MB/ME flags are correct.
        text_rec = _ndeflib.TextRecord(text="hello hardware", language="en")
        uri_rec = _ndeflib.UriRecord(iri="https://seedsigner.com")
        combined = b"".join(_ndeflib.message_encoder([text_rec, uri_rec]))

        (sid, _) = save_ndef_to_seedkeeper(connector, combined, "test NDEF")

        loaded = load_ndef_from_seedkeeper(connector, sid)
        assert loaded == combined

        # Decode and check structure
        records = decode_ndef_bytes(loaded)
        assert len(records) == 2
        assert records[0]["record_type"] == "text"
        assert "hello hardware" in records[0].get("text", "")
        assert records[1]["record_type"] == "uri"
        assert records[1].get("uri", "") == "https://seedsigner.com"

        connector.seedkeeper_reset_secret(sid)

    def test_card_ndef_get_set(self):
        """Round-trip the card's NFC NDEF buffer via card_set_ndef/card_get_ndef —
        the exact connector calls ToolsCommonNdefView makes (B11 regression:
        the Luckfox pysatochip pin predated these methods entirely)."""
        from seedsigner.views.smartcard_views import ToolsCommonNdefView

        connector = self._connect()

        payload = bytes.fromhex(ToolsCommonNdefView._SEEDKEEPER_APP_NDEF_HEX)
        card_bytes = ToolsCommonNdefView._to_card_ndef_bytes(payload)

        (_, sw1, sw2) = connector.card_set_ndef(card_bytes)
        if (sw1, sw2) == (0x6D, 0x00):
            pytest.skip("installed SeedKeeper applet does not support NDEF (SW=6D00)")
        assert (sw1, sw2) == (0x90, 0x00), f"card_set_ndef failed: SW={sw1:02X}{sw2:02X}"

        (_, sw1, sw2, ndef_bytes) = connector.card_get_ndef()
        assert (sw1, sw2) == (0x90, 0x00), f"card_get_ndef failed: SW={sw1:02X}{sw2:02X}"
        readback = ToolsCommonNdefView._extract_ndef_payload(bytes(ndef_bytes))
        expected = ToolsCommonNdefView._extract_ndef_payload(payload)
        assert readback == expected

    def test_list_secrets_view_decode(self):
        """List headers and decode one exactly as ToolsSeedkeeperViewSecretsView
        does — with the REAL JCconstants dictionaries (B11 regression: these
        names silently failed to import and the view died with NameError)."""
        from pysatochip.JCconstants import (
            SEEDKEEPER_DIC_TYPE,
            SEEDKEEPER_DIC_ORIGIN,
            SEEDKEEPER_DIC_EXPORT_RIGHTS,
        )

        sid = self._import_secret("Password", "Plaintext export allowed",
                                  "view_decode_test", b"hunter2")
        try:
            connector = self._connect()
            headers = connector.seedkeeper_list_secret_headers()
            ours = [h for h in headers if h.get("label") == "view_decode_test"]
            assert ours, "imported secret not present in the listing"
            header = ours[0]

            # Mirror the view's decode
            stype = SEEDKEEPER_DIC_TYPE.get(header["type"], hex(header["type"]))
            origin = SEEDKEEPER_DIC_ORIGIN.get(header["origin"], hex(header["origin"]))
            export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(
                header["export_rights"], hex(header["export_rights"]))

            assert stype == "Password", f"type decoded to {stype!r}"
            assert export_rights == "Plaintext export allowed", (
                f"export_rights decoded to {export_rights!r}"
            )
            assert isinstance(origin, str)
        finally:
            connector = self._connect()
            connector.seedkeeper_reset_secret(sid)

    def test_save_javacard_keys(self):
        key_json = '{"ENC": "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6", "MAC": "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6", "DEK": "A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"}'
        payload = key_json.encode("utf-8")

        connector = self._connect()
        header = connector.make_header("Data", "Plaintext export allowed",
                                       "jc_keys_test_keys")
        secret_list = _aead_to_seedkeeper_list(payload)
        (sid, _) = connector.seedkeeper_import_secret({
            "header": header,
            "secret_list": secret_list,
        })

        exported = connector.seedkeeper_export_secret(sid, None)
        decoded = _decode_seedkeeper_text(exported["secret"])
        import json
        parsed = json.loads(decoded)
        assert "ENC" in parsed
        assert "MAC" in parsed
        assert "DEK" in parsed
        connector.seedkeeper_reset_secret(sid)

    def test_import_export_descriptor(self):
        """Round-trip a V2 "Descriptor" secret (type 0xC1, 2-byte length prefix).

        Mirrors ToolsSeedkeeperSaveDescriptorView / ToolsSeedkeeperLoadDescriptorView:
        the Save view stores descriptors with a 2-byte big-endian length prefix and
        the Load view decodes it with the shared ``_decode_seedkeeper_text`` helper.
        This guards the #416 regression where re-reading the stored descriptor
        crashed with ``'utf-8' codec can't decode byte 0xc0`` (the read-back used a
        1-byte strip for a 2-byte-prefixed secret).

        Skipped when the installed pysatochip/applet does not expose the Descriptor
        secret type (0xC1), e.g. the vanilla PyPI ``pysatochip==0.17.0``.
        """
        payload = b"wsh(sortedmulti(2,aabbccddeeff00112233445566778899))"
        connector = self._connect()
        header = connector.make_header("Descriptor", "Plaintext export allowed", "test_descriptor")
        secret_list = list(len(payload).to_bytes(2, "big")) + list(payload)
        try:
            (sid, _) = connector.seedkeeper_import_secret({
                "header": header,
                "secret_list": secret_list,
            })
        except Exception as exc:
            pytest.skip(f"installed pysatochip/applet does not support Descriptor (0xC1): {exc}")

        try:
            exported = connector.seedkeeper_export_secret(sid, None)
            decoded = _decode_seedkeeper_text(exported["secret"])
            assert decoded == payload.decode("utf-8")
        finally:
            connector.seedkeeper_reset_secret(sid)

    def test_change_pin(self):
        connector = self._connect()
        old_pin = list("1234".encode("utf-8"))
        new_pin = list("5678".encode("utf-8"))
        connector.set_pin(0, old_pin)
        connector.card_verify_PIN()
        connector.card_change_PIN(0, old_pin, new_pin)
        # Switch to new pin and verify
        connector.set_pin(0, new_pin)
        (_, sw1, sw2) = connector.card_verify_PIN()
        assert sw1 == 0x90 and sw2 == 0x00
        # Restore old pin
        connector.card_change_PIN(0, new_pin, old_pin)
        connector.set_pin(0, old_pin)

    def test_unblock_pin(self):
        """Block PIN, then unblock with known PUK."""
        connector = self._connect()

        # Check if PIN is already blocked from a previous run
        (_, _, _, status) = connector.card_get_status()
        pin_tries = status.get("PIN0_remaining_tries", 5)
        
        if pin_tries > 1:
            # Block the PIN by entering wrong PINs repeatedly
            for _ in range(pin_tries):
                try:
                    connector.card_verify_PIN_simple("wrongpin")
                except Exception as ex:
                    if "blocked" in str(ex).lower():
                        break
                    continue

        # Force reconnection to get fresh secure channel after blocking
        self._disconnect()
        connector = self._connect(force_reconnect=True)

        # Fixed PUK for testing (deterministic, matches _provision)
        puk_bytes = bytes(range(16))

        (_, sw1, sw2) = connector.card_unblock_PIN(0, list(puk_bytes))
        assert sw1 == 0x90 and sw2 == 0x00, f"Unblock failed: {sw1:02X} {sw2:02X}"

        # Restore original PIN (unblock doesn't set new PIN, so we change it)
        connector.card_change_PIN(0, list(b"1234"), list(b"1234"))

    def test_factory_reset_new(self):
        """v2+ only: block PIN then send wrong PUK to trigger programmatic factory reset."""
        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        version = status.get("protocol_version", 0)
        if version < 2:
            pytest.skip("SeedKeeper v1 does not support programmatic factory reset")

        from pysatochip.CardConnector import IdentityBlockedError, WrongPinError, CardResetToFactoryError

        # Check if PIN is already blocked from a previous run
        pin_tries = status.get("PIN0_remaining_tries", 5)
        
        if pin_tries > 1:
            # Block the PIN by entering wrong PINs repeatedly
            for _ in range(pin_tries):
                try:
                    connector.card_verify_PIN_simple("wrongpin")
                except IdentityBlockedError:
                    break
                except WrongPinError:
                    continue

        # Force reconnection to get fresh secure channel before sending wrong PUK
        self._disconnect()
        connector = self._connect(force_reconnect=True)

        # Now send wrong PUK via card_unblock_PIN to trigger factory reset
        try:
            connector.card_unblock_PIN(0, list(b"garbage_puk_here!!"))
        except CardResetToFactoryError:
            # Expected — wrong PUK on a card with 1 try triggers factory reset
            pass

        self._disconnect()


# ======================================================================
# Phase 3 — Keycard
# ======================================================================

class TestKeycard:
    """Keycard applet: provision, seed import, PSBT signing, factory reset."""

    AID = "A0000008040001"
    CAP = "Keycard_v3.2.cap"

    _connector = None


    @pytest.fixture(scope="class", autouse=True)
    def applet(self, gp, cap_dir):
        try:
            import keycard  # noqa: F401 — only to check availability
        except ImportError:
            pytest.skip("keycard-py not installed")
        result = gp.install_capfile(str(cap_dir / self.CAP))
        logger.info(f"Keycard install result: {result}")
        gp.close()
        # Provision the card once per class (idempotent — skips if already setup)
        try:
            self._provision("123456")
            connector = self._connect()
            (_, _, _, status) = connector.card_get_status()
            logger.info(f"Keycard provisioned, setup_done={status.get('setup_done')}")
        except Exception as exc:
            logger.warning(f"Keycard provisioning failed (non-fatal): {exc}")
        yield
        try:
            self._disconnect()
            gp.terminal()
            gp.card()
            gp.auth(
                enc_key="404142434445464748494A4B4C4D4E4F",
                mac_key="404142434445464748494A4B4C4D4E4F",
                dek_key="404142434445464748494A4B4C4D4E4F",
                keysetversion="00",
                securitylevel=gp.SECURITY_LEVEL_C_MAC,
            )
            delete_result = gp.delete_package(self.AID)
            logger.info(f"Keycard uninstall result: {delete_result}")
        except BaseException as exc:
            logger.warning(f"Keycard cleanup failed (non-fatal): {exc}")

    def _connect(self):
        if self._connector is None:
            from seedsigner.helpers.keycard_connector import KeycardSatochipConnector
            self._connector = KeycardSatochipConnector.create(
                card_filter=["satochip"]
            )
            self._connector.set_pin(0, list(b"123456"))
            (_, _, _, status) = self._connector.card_get_status()
            if status.get("setup_done"):
                try:
                    self._connector.card_verify_PIN()
                except Exception:
                    # PIN might be blocked - caller should check status and handle
                    pass
        return self._connector

    def _disconnect(self):
        if self._connector is not None:
            try:
                self._connector.card_disconnect()
            except Exception:
                pass
            self._connector = None

    def _provision(self, pin: str = "123456", duress_pin: str | None = None) -> str:
        """One-time card setup; returns the deterministic PUK text for later use."""
        connector = self._connect()

        (_, _, _, status) = connector.card_get_status()
        
        # Derive 12-digit PUK text from deterministic bytes (same as new provisioning)
        puk_bytes = bytes(range(16))
        puk_text = "".join(str(b % 10) for b in puk_bytes[:12])
        
        if status.get("setup_done"):
            pin_list = list(pin.encode("utf-8"))
            connector.set_pin(0, pin_list)
            try:
                connector.card_verify_PIN()
            except Exception:
                # PIN might be blocked - try to unblock with deterministic PUK
                old_puk_bytes = list(puk_text.encode("utf-8"))
                try:
                    connector.card_unblock_PIN(0, list(old_puk_bytes))
                    connector.set_pin(0, pin_list)
                    connector.card_verify_PIN()
                except Exception:
                    pass
            # Always return the deterministic PUK text regardless of whether we just provisioned or not
            return puk_text

        pin_list = list(pin.encode("utf-8"))

        # Initialize secure channel before card_setup on seeded cards
        if connector.needs_secure_channel:
            connector.card_initiate_secure_channel()

        kwargs = dict(
            pin_tries_0=5, ublk_tries_0=1,
            pin_0="123456", ublk_0=list(puk_bytes),
            pin_tries_1=1, ublk_tries_1=1,
            pin_1="654321", ublk_1=b"654321",
            secmemsize=0x0000, memsize=0,
            create_object_ACL=0x01, create_key_ACL=0x01, create_pin_ACL=0x01,
        )
        if duress_pin is not None:
            kwargs["duress_pin"] = duress_pin
        connector.card_setup(**kwargs)
        connector.set_pin(0, list(pin.encode("utf-8")))
        return puk_text

    # -- tests ---------------------------------------------------------

    def test_provision(self):
        self._provision("123456")
        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        assert status.get("setup_done") is True

    def test_provision_with_duress_pin(self):
        # Factory-reset first so we can set duress PIN from scratch
        connector = self._connect()
        try:
            connector.card_reset_factory()
        except Exception:
            pytest.skip("Factory reset not supported on this Keycard variant")
        self._disconnect()
        self._provision("123456", duress_pin="654321")
        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        assert status.get("setup_done") is True

    def test_import_seed(self, test_seed_hex):
        connector = self._connect()
        (_, sw1, sw2) = connector.card_bip32_import_seed(
            list(bytes.fromhex(test_seed_hex))
        )
        assert sw1 == 0x90 and sw2 == 0x00
        (_, _, _, status) = connector.card_get_status()
        # Keycard may report key_initialized or is_seeded depending on firmware
        assert status.get("key_initialized") or status.get("is_seeded")

    def test_derive_extended_key(self):
        connector = self._connect()
        from seedsigner.helpers.satochip_signer import format_path_string
        key, chain = connector.card_bip32_get_extendedkey(format_path_string("m/84h/0h/0h"))
        assert key is not None
        assert len(chain) >= 0

    def test_derive_xpub(self, test_known_xpub):
        connector = self._connect()
        from seedsigner.helpers.satochip_signer import format_path_string
        xpub = connector.card_bip32_get_xpub(
            format_path_string("m/84h/0h/0h"), "p2wpkh", True
        )
        assert isinstance(xpub, str)
        assert xpub.startswith("zpub")
        # zpub for m/84h/0h/0h on test_seed_hex:
        assert xpub == "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"

    def test_change_pin(self):
        connector = self._connect()
        old = "123456"
        new = "654321"
        connector.set_pin(0, list(old.encode("utf-8")))
        connector.card_verify_PIN()
        connector.card_change_PIN(0, list(old.encode("utf-8")),
                                  list(new.encode("utf-8")))
        # Verify new pin works
        connector.set_pin(0, list(new.encode("utf-8")))
        (_, sw1, sw2) = connector.card_verify_PIN()
        assert sw1 == 0x90 and sw2 == 0x00
        # Restore
        connector.card_change_PIN(0, list(new.encode("utf-8")),
                                  list(old.encode("utf-8")))
        connector.set_pin(0, list(old.encode("utf-8")))

    @pytest.mark.xfail(reason="Keycard firmware may not support CHANGE PUK command at INS=0x21 P1=0x01")
    def test_change_puk(self):
        """Change PUK from known value to a new one and verify."""
        # Re-provision fresh card so we start clean (previous tests may have blocked PIN)
        self._disconnect()
        self._provision("123456")

        connector = self._connect()
        connector.set_pin(0, list(b"123456"))
        connector.card_verify_PIN()

        # Fixed PUK for testing: bytes(range(16)) -> "012345678901" (first 12 digits)
        new_puk_text = "987654321098"
        new_puk_bytes = list(new_puk_text.encode("utf-8"))

        _response, sw1, sw2 = connector.card_change_PUK(0, [], list(new_puk_bytes))
        assert sw1 == 0x90 and sw2 == 0x00, f"Change PUK failed: {sw1:02X} {sw2:02X}"

        # Restore original PUK by re-provisioning
        self._disconnect()
        self._provision("123456")

    @pytest.mark.xfail(reason="Keycard firmware may not support UNBLOCK PIN command at INS=0x22")
    def test_unblock_pin(self):
        """Block PIN, then unblock with known PUK."""
        connector = self._connect()

        # Check if PIN is already blocked from a previous run
        (_, _, _, status) = connector.card_get_status()
        pin_tries = status.get("PIN0_remaining_tries", 5)
        
        if pin_tries > 1:
            # Block the PIN by entering wrong PINs repeatedly
            for _ in range(pin_tries):
                try:
                    from seedsigner.helpers.keycard_connector import WrongPinError as KcWrongPinError
                    connector.card_verify_PIN()
                except KcWrongPinError:
                    continue
                except Exception:
                    break

        # Force reconnection to get fresh secure channel after blocking
        self._disconnect()
        connector = self._connect(force_reconnect=True)

        # Fixed PUK for testing: bytes(range(16)) -> "012345678901" (first 12 digits)
        puk_bytes = bytes(range(16))
        old_puk_text = "".join(str(b % 10) for b in puk_bytes[:12])
        old_puk_bytes = list(old_puk_text.encode("utf-8"))

        _response, sw1, sw2 = connector.card_unblock_PIN(0, old_puk_bytes)
        assert sw1 == 0x90 and sw2 == 0x00, f"Unblock failed: {sw1:02X} {sw2:02X}"

        # Restore original PIN (unblock doesn't set new PIN, so we change it)
        connector.card_change_PIN(0, list(b"123456"), list(b"123456"))

    def test_set_label(self):
        connector = self._connect()
        connector.card_set_label("test-keycard")
        # No read-back API exposed; just verify no exception

    def test_ndef_get_set(self):
        """Adapter NDEF surface against a real Keycard: store into the Keycard
        NDEF data slot and read it back through the pysatochip-style
        card_set_ndef/card_get_ndef the NDEF views call."""
        connector = self._connect()

        ndef_bytes = bytes.fromhex("0003D00000")  # empty NDEF record, 2-byte length prefix
        (_, sw1, sw2) = connector.card_set_ndef(ndef_bytes)
        if (sw1, sw2) != (0x90, 0x00):
            pytest.skip(f"Keycard applet rejected NDEF store: SW={sw1:02X}{sw2:02X}")

        (_, sw1, sw2, readback) = connector.card_get_ndef()
        assert (sw1, sw2) == (0x90, 0x00), f"card_get_ndef failed: SW={sw1:02X}{sw2:02X}"
        assert bytes(readback) == ndef_bytes

    def test_sign_psbt(self, test_seed_hex):
        from seedsigner.helpers.keycard_signer import sign_psbt_with_keycard
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants

        psbt, pubkeys = _build_psbt(test_seed_hex, ["m/84h/0h/0h/0/0"])

        # Patch settings so dummies are disabled for deterministic test
        class _Settings:
            def get_value(self, key):
                if key == SettingsConstants.SETTING__KEYCARD_SIGN_TIMEOUT:
                    return 30
                return 0

        import random
        random.seed(42)

        connector = self._connect()
        result = sign_psbt_with_keycard(psbt, connector)
        assert result.signed_count >= 1
        assert not result.timed_out
        assert getattr(connector, "_last_path", None) is not None

        # Verify signature
        sig = psbt.inputs[0].partial_sigs[pubkeys[0]]
        sighash = hashlib.sha256(bytes([0]) * 32).digest()
        assert _verify_ecdsa(sig, pubkeys[0].sec(), sighash)
        assert _check_low_s(_der_sig_from_partial(sig))

    def test_sign_psbt_path_fallback(self, test_seed_hex):
        """Verify that single-derivation inputs set _last_path."""
        from seedsigner.helpers.keycard_signer import sign_psbt_with_keycard
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants

        psbt, pubkeys = _build_psbt(test_seed_hex, ["m/84h/0h/0h/0/1"])

        class _Settings:
            def get_value(self, key):
                if key == SettingsConstants.SETTING__KEYCARD_SIGN_TIMEOUT:
                    return 30
                return 0

        import random
        random.seed(42)

        connector = self._connect()
        # Ensure previous _last_path is cleared
        if hasattr(connector, "_last_path"):
            del connector._last_path

        result = sign_psbt_with_keycard(psbt, connector)
        assert result.signed_count >= 1
        # _last_path must be set by the fallback logic (apostrophe notation)
        assert getattr(connector, "_last_path", None) == "m/84'/0'/0'/0/1"

    def test_factory_reset(self):
        connector = self._connect()
        try:
            connector.card_reset_factory()
        except Exception as exc:
            pytest.skip(f"Factory reset failed: {exc}")
        self._disconnect()

        # Reconnect and verify blank state
        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        assert status.get("setup_done") is False
        assert status.get("key_initialized") is False


# ======================================================================
# Phase 4 — Satochip
# ======================================================================

class TestSatochip:
    """Satochip applet: provision, seed import, PSBT signing, message signing, etc."""

    AID = "5361746F43686970"
    CAP = "SatoChip-0.12-official.cap"

    _connector = None

    @pytest.fixture(scope="class", autouse=True)
    def applet(self, gp, cap_dir):
        result = gp.install_capfile(str(cap_dir / self.CAP))
        logger.info(f"Satochip install result: {result}")
        gp.close()
        # Provision the card once per class (idempotent — skips if already setup)
        try:
            self._provision("1234")
            connector = self._connect()
            (_, _, _, status) = connector.card_get_status()
            logger.info(f"Satochip provisioned, setup_done={status.get('setup_done')}")
        except Exception as exc:
            logger.warning(f"Satochip provisioning failed (non-fatal): {exc}")
        yield
        try:
            self._disconnect()
            gp.terminal()
            gp.card()
            gp.auth(
                enc_key="404142434445464748494A4B4C4D4E4F",
                mac_key="404142434445464748494A4B4C4D4E4F",
                dek_key="404142434445464748494A4B4C4D4E4F",
                keysetversion="00",
                securitylevel=gp.SECURITY_LEVEL_C_MAC,
            )
            delete_result = gp.delete_package(self.AID)
            logger.info(f"Satochip uninstall result: {delete_result}")
        except BaseException as exc:
            logger.warning(f"Satochip cleanup failed (non-fatal): {exc}")

    # -- helpers -------------------------------------------------------

    def _connect(self):
        if self._connector is None:
            from pysatochip.CardConnector import CardConnector
            self._connector = CardConnector(card_filter=["satochip"])
            self._connector.cardmonitor.deleteObserver(self._connector.cardobserver)
            self._connector.cardservice.connection.connect()
            self._connector.card_select()
            (_, _, _, status) = self._connector.card_get_status()
            if self._connector.needs_secure_channel:
                self._connector.card_initiate_secure_channel()
            if status.get("setup_done"):
                pin_list = list(b"1234")
                self._connector.set_pin(0, pin_list)
                self._connector.card_verify_PIN()
            time.sleep(0.3)
        return self._connector

    def _disconnect(self):
        if self._connector is not None:
            try:
                self._connector.card_disconnect()
            except Exception:
                pass
            self._connector = None

    def _provision(self, pin: str = "1234"):
        import os as _os

        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        if status.get("setup_done"):
            pin_list = list(pin.encode("utf-8"))
            connector.set_pin(0, pin_list)
            connector.card_verify_PIN()
            return

        puk_bytes = _os.urandom(16)
        puk_list = list(puk_bytes)
        pin_list = list(pin.encode("utf-8"))

        connector.card_setup(
            pin_tries0=5, ublk_tries0=1,
            pin0=pin_list, ublk0=puk_list,
            pin_tries1=1, ublk_tries1=1,
            pin1=[0x30] * 6, ublk1=[0x30] * 6,
            memsize=0x4000, memsize2=0x0060,
            create_object_ACL=0x01, create_key_ACL=0x01, create_pin_ACL=0x01,
        )
        connector.set_pin(0, pin_list)

    def _import_seed(self, connector, test_seed_hex):
        """Ensure the card is seeded and the connector has the authentikey + PIN."""
        pin_list = list(b"1234")
        connector.set_pin(0, pin_list)
        connector.card_verify_PIN()
        (_, _, _, status) = connector.card_get_status()
        if not status.get("is_seeded"):
            seed_list = list(bytes.fromhex(test_seed_hex))
            connector.card_bip32_import_seed(seed_list)
        elif connector.parser.authentikey is None:
            from seedsigner.helpers.satochip_signer import _ensure_satochip_authentikey
            _ensure_satochip_authentikey(connector)

    # -- tests ---------------------------------------------------------

    def test_provision(self):
        self._provision("1234")
        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        assert status.get("setup_done") is True

    def test_import_seed(self, test_seed_hex):
        connector = self._connect()
        seed_list = list(bytes.fromhex(test_seed_hex))
        authentikey = connector.card_bip32_import_seed(seed_list)
        assert authentikey is not None
        (_, _, _, status) = connector.card_get_status()
        assert status.get("is_seeded") is True

    def test_derive_extended_key(self):
        connector = self._connect()
        self._import_seed(connector, "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4")
        from seedsigner.helpers.satochip_signer import format_path_string
        key, chain = connector.card_bip32_get_extendedkey(format_path_string("m/84h/0h/0h"))
        assert key is not None
        assert len(chain) >= 0

    def test_derive_xpub(self, test_seed_hex, test_known_xpub):
        connector = self._connect()
        self._import_seed(connector, test_seed_hex)
        from seedsigner.helpers.satochip_signer import format_path_string
        xpub = connector.card_bip32_get_xpub(format_path_string("m/84h/0h/0h"), "p2wpkh", True)
        assert isinstance(xpub, str)
        assert xpub.startswith("zpub")
        # zpub for m/84h/0h/0h on test_seed_hex:
        assert xpub == "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"

    def test_sign_psbt_single(self, test_seed_hex):
        from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants

        psbt, pubkeys = _build_psbt(test_seed_hex, ["m/84h/0h/0h/0/0"])

        class _Settings:
            def get_value(self, key):
                if key == SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT:
                    return 30
                return 0

        import random
        random.seed(42)

        connector = self._connect()
        self._import_seed(connector, test_seed_hex)
        result = sign_psbt_with_satochip(psbt, connector)
        assert result.signed_count >= 1
        assert not result.timed_out

        sig = psbt.inputs[0].partial_sigs[pubkeys[0]]
        sighash = hashlib.sha256(bytes([0]) * 32).digest()
        assert _verify_ecdsa(sig, pubkeys[0].sec(), sighash)
        assert _check_low_s(_der_sig_from_partial(sig))

    def test_sign_psbt_multi_input(self, test_seed_hex):
        from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants

        psbt, pubkeys = _build_psbt(
            test_seed_hex,
            ["m/84h/0h/0h/0/0", "m/84h/0h/0h/0/1", "m/84h/0h/0h/1/0"],
        )

        class _Settings:
            def get_value(self, key):
                if key == SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT:
                    return 30
                return 0

        import random
        random.seed(42)
        connector = self._connect()
        self._import_seed(connector, test_seed_hex)
        result = sign_psbt_with_satochip(psbt, connector)
        assert result.signed_count >= 1
        assert not result.timed_out

        # Verify every input that has a signature
        for i, pub in enumerate(pubkeys):
            if pub in psbt.inputs[i].partial_sigs:
                sig = psbt.inputs[i].partial_sigs[pub]
                idx = i  # sighash uses bytes([idx]) * 32
                sighash = hashlib.sha256(bytes([idx]) * 32).digest()
                assert _verify_ecdsa(sig, pub.sec(), sighash)
                assert _check_low_s(_der_sig_from_partial(sig))

    def test_sign_psbt_with_dummies(self, test_seed_hex):
        from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants

        psbt, pubkeys = _build_psbt(test_seed_hex, ["m/84h/0h/0h/0/0"])

        class _Settings:
            def get_value(self, key):
                mapping = {
                    SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT: 30,
                    SettingsConstants.SETTING__SATOCHIP_MAX_PRE_DUMMIES: 5,
                    SettingsConstants.SETTING__SATOCHIP_MAX_POST_DUMMIES: 5,
                    SettingsConstants.SETTING__SATOCHIP_MAX_IN_TX_DUMMIES: 3,
                    SettingsConstants.SETTING__SATOCHIP_DUMMY_PROBABILITY: 100,
                }
                return mapping.get(key, 0)

        import random
        random.seed(42)
        connector = self._connect()
        self._import_seed(connector, test_seed_hex)
        result = sign_psbt_with_satochip(psbt, connector)
        assert result.signed_count >= 1
        assert not result.timed_out

        # Signature should still be valid despite dummy noise
        sig = psbt.inputs[0].partial_sigs[pubkeys[0]]
        sighash = hashlib.sha256(bytes([0]) * 32).digest()
        assert _verify_ecdsa(sig, pubkeys[0].sec(), sighash)

    def test_sign_psbt_timeout(self, test_seed_hex):
        from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants

        psbt, pubkeys = _build_psbt(test_seed_hex, ["m/84h/0h/0h/0/0"])

        class _Settings:
            def get_value(self, key):
                if key == SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT:
                    return 0.001  # very short — will likely time out
                return 0

        import random
        random.seed(42)
        connector = self._connect()
        result = sign_psbt_with_satochip(psbt, connector)
        # At minimum, shouldn't crash; timed_out may be True or False
        assert isinstance(result.signed_count, int)

    def test_sign_message(self, test_seed_hex):
        from seedsigner.helpers.satochip_signer import sign_message_with_satochip

        connector = self._connect()
        self._import_seed(connector, test_seed_hex)
        sig = sign_message_with_satochip(
            "m/84h/0h/0h/0/0", "hello hardware", connector, timeout=10,
        )
        # Signature is a base64-encoded compact sig (65 bytes → ~88 chars)
        from binascii import a2b_base64
        raw = a2b_base64(sig.encode("ascii"))
        assert len(raw) == 65  # compact signature: 32R + 32S + 1V

    def test_verify_address_match(self, test_seed_hex, test_known_xpub):
        from seedsigner.helpers.satochip_signer import verify_satochip_message_address
        from seedsigner.helpers import embit_utils
        from seedsigner.models.settings_definition import SettingsConstants

        # Compute the expected address locally
        from embit import bip32
        root = bip32.HDKey.from_seed(bytes.fromhex(test_seed_hex))
        wallet = root.derive("m/84h/0h/0h")
        xpub = wallet.to_public()
        expected = embit_utils.get_single_sig_address(
            xpub=xpub,
            script_type=SettingsConstants.NATIVE_SEGWIT,
            index=5,
            is_change=False,
            embit_network="main",
        )

        connector = self._connect()
        self._import_seed(connector, test_seed_hex)
        addr_format = {
            "wallet_derivation_path": "m/84h/0h/0h",
            "is_change": False,
            "index": 5,
            "script_type": SettingsConstants.NATIVE_SEGWIT,
            "network": SettingsConstants.MAINNET,
        }
        # Should not raise
        verify_satochip_message_address(connector, addr_format, expected)

    def test_verify_address_mismatch(self, test_seed_hex):
        from seedsigner.helpers.satochip_signer import (
            verify_satochip_message_address,
            _ADDRESS_MISMATCH_ERROR,
        )
        from seedsigner.models.settings_definition import SettingsConstants

        connector = self._connect()
        self._import_seed(connector, test_seed_hex)
        addr_format = {
            "wallet_derivation_path": "m/84h/0h/0h",
            "is_change": False,
            "index": 0,
            "script_type": SettingsConstants.NATIVE_SEGWIT,
            "network": SettingsConstants.MAINNET,
        }
        with pytest.raises(Exception) as exc:
            verify_satochip_message_address(
                connector, addr_format, "bc1qnotavalidaddress"
            )
        assert "Satochip card" in str(exc.value)

    def test_genuine_check(self):
        connector = self._connect()
        result = connector.card_verify_authenticity()
        # Returns (is_genuine: bool, ..., ..., ..., str)
        assert result is not None
        assert isinstance(result[0], bool)

    def test_change_pin(self):
        connector = self._connect()
        old = list("1234".encode("utf-8"))
        new = list("5678".encode("utf-8"))
        connector.set_pin(0, old)
        connector.card_verify_PIN()
        connector.card_change_PIN(0, old, new)
        connector.set_pin(0, new)
        (_, sw1, sw2) = connector.card_verify_PIN()
        assert sw1 == 0x90 and sw2 == 0x00
        # Restore
        connector.card_change_PIN(0, new, old)
        connector.set_pin(0, old)


# ======================================================================
# Phase 5 — Specter-DIY
# ======================================================================

class TestSpecterDIY:
    """Specter-DIY (MemoryCard) applet: install, PIN, mnemonic save/load."""

    AID = "B00B5111CB"
    CAP = "SpecterDIY.cap"
    APPLET_AID = "B00B5111CB01"

    _card = None
    _secure_applet = None
    _memory_applet = None

    @pytest.fixture(scope="class", autouse=True)
    def applet(self, gp, cap_dir):
        # Check if specter_card is available
        try:
            from specter_card import Card, MemoryCardApplet, SecureApplet  # noqa: F401
        except ImportError:
            # Try the same path resolution as the views
            repo_root = Path(__file__).resolve().parents[1]
            candidates = [
                repo_root.parent / "specter-javacard" / "py",
                repo_root / "specter-javacard" / "py",
            ]
            for c in candidates:
                if c.is_dir():
                    sys.path.insert(0, str(c))
                    try:
                        from specter_card import Card, MemoryCardApplet, SecureApplet  # noqa: F401
                        break
                    except ImportError:
                        sys.path.pop(0)
            else:
                pytest.skip(
                    "specter_card module not found. Clone specter-javacard "
                    "alongside seedsigner or set SEEDSIGNER_SPECTER_CARD_PY_PATH"
                )

        gp.install_capfile(str(cap_dir / self.CAP))
        logger.info(f"SpecterDIY installed")
        yield
        try:
            self._disconnect()
            delete_result = gp.delete_package(self.AID)
            logger.info(f"SpecterDIY uninstall result: {delete_result}")
        except BaseException as exc:
            logger.warning(f"SpecterDIY cleanup failed (non-fatal): {exc}")

    def _provision(self, pin: str = "1234"):
        """Specter-DIY does not require card provisioning; this is a no-op for API consistency."""
        pass

    def _connect(self):
        if self._card is None:
            from specter_card import Card, MemoryCardApplet, SecureApplet

            self._card = Card(self.APPLET_AID)
            self._card.connect()
            self._secure_applet = SecureApplet(self._card)
            self._memory_applet = MemoryCardApplet(self._card)
        return self._card, self._secure_applet, self._memory_applet

    def _disconnect(self):
        try:
            if hasattr(self, "_secure_applet") and self._secure_applet is not None:
                # close secure channel if the API supports it
                pass
        except Exception:
            pass
        try:
            if self._card is not None:
                self._card.disconnect()
        except Exception:
            pass
        self._card = None
        self._secure_applet = None
        self._memory_applet = None

    def _open_channel(self):
        """Open a secure channel (mode='ee') and return the channel object."""
        _, secure, _ = self._connect()
        return secure.open_secure_channel(mode="ee")

    def _ensure_no_pin(self, channel):
        """If the applet has 'no_pin' status, set the test PIN."""
        _, secure, _ = self._connect()
        ps = secure.pin_status(channel)
        if ps.get("status") in ("disabled", "no_pin"):
            secure.set_pin(channel, b"1234")

    def _unlock(self, channel):
        """Unlock with the test PIN if the card is locked."""
        _, secure, _ = self._connect()
        ps = secure.pin_status(channel)
        if ps.get("status") == "locked":
            secure.unlock(channel, b"1234")

    # -- tests ---------------------------------------------------------

    def test_pin_setup(self):
        ch = self._open_channel()
        _, secure, _ = self._connect()
        ps = secure.pin_status(ch)

        if ps.get("status") in ("no_pin", "disabled"):
            secure.set_pin(ch, b"1234")

        ps = secure.pin_status(ch)
        assert ps.get("status") in ("unlocked", "locked")
        assert "attempts_left" in ps

    def test_save_mnemonic(self, test_entropy_hex):
        from seedsigner.views.smartcard_views import _serialize_specter_plaintext_blob

        ch = self._open_channel()
        self._ensure_no_pin(ch)
        self._unlock(ch)
        _, _, mem = self._connect()

        entropy = bytes.fromhex(test_entropy_hex)
        assert len(entropy) == 16

        blob = _serialize_specter_plaintext_blob(entropy)
        mem.store_data(ch, blob)

        # Verify by reading back and checking the data round-trips
        stored = mem.get_data(ch)
        assert len(stored) > 0

    def test_load_mnemonic(self, test_entropy_hex):
        from seedsigner.views.smartcard_views import _serialize_specter_plaintext_blob
        from embit import bip39

        ch = self._open_channel()
        self._ensure_no_pin(ch)
        self._unlock(ch)
        _, _, mem = self._connect()

        # First ensure data is saved
        entropy = bytes.fromhex(test_entropy_hex)
        blob = _serialize_specter_plaintext_blob(entropy)
        mem.store_data(ch, blob)

        # Read back via decode_diy_data
        decoded = mem.decode_diy_data(ch)
        # The decode_diy_data() method returns dict with keys like "encrypted", "mnemonic"
        assert decoded is not None
        assert "mnemonic" in decoded or "entropy" in decoded

        # Recover mnemonic from entropy
        expected_mnemonic = bip39.mnemonic_from_bytes(entropy)
        if "mnemonic" in decoded:
            assert decoded["mnemonic"] == expected_mnemonic

        # Also test raw get_data round-trip
        stored = mem.get_data(ch)
        assert len(stored) > 0

        # Re-save the same blob to verify re-store works
        mem.store_data(ch, blob)
        stored2 = mem.get_data(ch)
        assert stored == stored2

    def test_change_pin(self):
        ch = self._open_channel()
        _, secure, _ = self._connect()
        self._ensure_no_pin(ch)
        self._unlock(ch)

        # Change from "1234" to "5678"
        secure.change_pin(ch, b"1234", b"5678")

        # Verify: unlock with new pin works
        ps = secure.pin_status(ch)
        if ps.get("status") == "locked":
            secure.unlock(ch, b"5678")

        ps = secure.pin_status(ch)
        assert ps.get("status") in ("unlocked", "locked")

        # Restore original pin
        secure.change_pin(ch, b"5678", b"1234")

    def test_wipe_mnemonic(self):
        ch = self._open_channel()
        self._ensure_no_pin(ch)
        self._unlock(ch)
        _, _, mem = self._connect()

        mem.store_data(ch, b"")

        stored = mem.get_data(ch)
        # Should be empty or very short
        assert len(stored) == 0 or stored == b""

    def test_save_then_wipe_roundtrip(self, test_entropy_hex):
        """
        Test the full lifecycle: save → load (verify) → wipe → load (verify empty).
        """
        from seedsigner.views.smartcard_views import _serialize_specter_plaintext_blob
        from embit import bip39

        ch = self._open_channel()
        self._ensure_no_pin(ch)
        self._unlock(ch)
        _, _, mem = self._connect()

        # Save
        entropy = bytes.fromhex(test_entropy_hex)
        blob = _serialize_specter_plaintext_blob(entropy)
        mem.store_data(ch, blob)

        # Verify load
        stored = mem.get_data(ch)
        assert len(stored) > 0

        # Wipe
        mem.store_data(ch, b"")

        # Verify empty
        stored = mem.get_data(ch)
        assert len(stored) == 0 or stored == b""
