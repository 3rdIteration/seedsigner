"""
Hardware-in-the-loop *flow* tests: walk the real UI against a real card.

``test_smartcard_hardware.py`` drives the card connector directly, which proves
the applet and the helper layer work. It does not prove that the **views** that
sit on top of them route correctly, pass the right seed, or hand the card the
bytes the user actually selected. That gap is exactly where the ``seed_num`` ->
``Seed`` migration could have gone wrong silently, so these tests drive the
Views through ``FlowTest`` and then assert against the card.

Each class follows the same lifecycle as the existing hardware tests: start
from a blank JavaCard, install the applet, provision it, exercise it through
the UI, then uninstall.

Requires (same as ``test_smartcard_hardware.py``):
  - PC/SC smartcard reader
  - Blank JavaCard (JC 3.0.4+, default GP key 404142...) **inserted**
  - ``pip install pysatochip pygp``

Run::

    pytest tests/test_flows_smartcard_hardware.py -v --tb=short

Skips cleanly (does not fail) when no reader or card is present.
"""
import logging
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Must import test base before the Controller.
from base import FlowTest, FlowStep

# base.py installs MagicMock shims for pysatochip so the desktop suite can import
# the views without a card. Drop them again here so the real library loads --
# same dance as test_smartcard_hardware.py, and it must happen after `base` is
# imported (which is what puts them there) and before any card call.
for _mod_name in list(sys.modules.keys()):
    if _mod_name == "pysatochip" or _mod_name.startswith("pysatochip."):
        if isinstance(sys.modules[_mod_name], MagicMock):
            del sys.modules[_mod_name]

from seedsigner.models.seed import Seed, Slip39Seed
from seedsigner.models.settings import SettingsConstants
from seedsigner.views import seed_views, smartcard_views
from seedsigner.views.view import MainMenuView

logger = logging.getLogger(__name__)


GP_KEY = "404142434445464748494A4B4C4D4E4F"
CARD_PIN = "1234"

BIP39_MNEMONIC = "blush twice taste dawn feed second opinion lazy thumb play neglect impact".split()


# ======================================================================
# Fixtures
# ======================================================================

@pytest.fixture(scope="session")
def readiness():
    """Skip the whole module unless a reader with a card is actually present."""
    try:
        import pygp  # noqa: F401
    except ImportError:
        pytest.skip("pygp not installed (pip install pygp)")

    # Probe with pyscard first. pygp's native layer raises a Windows structured
    # exception when the reader is empty, which faulthandler dumps as a wall of
    # traceback even though we catch it -- checking for a card the quiet way
    # keeps a no-card run readable.
    try:
        from smartcard.System import readers
    except ImportError:
        pytest.skip("pyscard not installed")
    if not any(_reader_has_card(r) for r in readers() if not _is_virtual_reader(r)):
        pytest.skip("No smartcard inserted in any physical PC/SC reader")

    try:
        pygp.terminal()
        pygp.card()
    except BaseException as exc:
        pytest.skip(f"No GlobalPlatform-capable card detected: {exc}")


def _is_virtual_reader(reader) -> bool:
    """
    Windows exposes TPM-backed virtual readers ("Windows Hello for Business")
    that answer to SCardConnect with an ATR. They are not JavaCards and will
    never be GlobalPlatform-capable, so they must not satisfy the card probe.
    """
    return "windows hello" in str(reader).lower()


def _reader_has_card(reader) -> bool:
    # Connecting to an empty reader raises a Windows structured exception that
    # pytest's faulthandler prints in full even though pyscard converts it into
    # a normal Python exception. Mute it for the duration of the probe so a
    # no-card run reports one skip line instead of a page of traceback.
    import faulthandler

    was_enabled = faulthandler.is_enabled()
    faulthandler.disable()
    try:
        connection = reader.createConnection()
        connection.connect()
        connection.disconnect()
        return True
    except Exception:
        return False
    finally:
        if was_enabled:
            faulthandler.enable()


@pytest.fixture(scope="session")
def gp(readiness):
    import pygp
    pygp.auth(
        enc_key=GP_KEY, mac_key=GP_KEY, dek_key=GP_KEY,
        keysetversion="00",
        securitylevel=pygp.SECURITY_LEVEL_C_MAC,
    )
    yield pygp


@pytest.fixture(scope="session")
def cap_dir():
    p = Path(__file__).resolve().parent.parent / "javacard-cap"
    assert p.is_dir(), f"CAP directory not found: {p}"
    return p


def _reauth_and_delete(gp, aid):
    """Re-establish GP auth and remove an applet package, tolerating absence."""
    try:
        gp.close()
    except BaseException:
        pass
    try:
        gp.terminal()
        gp.card()
        gp.auth(
            enc_key=GP_KEY, mac_key=GP_KEY, dek_key=GP_KEY,
            keysetversion="00",
            securitylevel=gp.SECURITY_LEVEL_C_MAC,
        )
        gp.delete_package(aid)
    except BaseException as exc:
        logger.warning(f"cleanup: failed to delete {aid}: {exc}")


class SmartcardFlowTest(FlowTest):
    """Shared plumbing for driving Views against a live card."""

    def prime_controller_for_card(self):
        """
        Skip the PIN keypad. `init_satochip` prompts only when
        `controller.Satochip_PIN` is unset, so pre-seeding it keeps the flow
        sequences focused on the routing under test rather than PIN entry
        (which has its own coverage).
        """
        self.controller.Satochip_PIN = list(CARD_PIN.encode("utf-8"))
        self.controller.Satochip_Connector = None
        self.settings.set_value(
            SettingsConstants.SETTING__SMARTCARD_SUPPORT, SettingsConstants.OPTION__ENABLED
        )

    def store_bip39_seed(self) -> Seed:
        seed = Seed(mnemonic=BIP39_MNEMONIC)
        self.controller.storage.set_pending_seed(seed)
        return self.controller.storage.finalize_pending_seed()

    def store_slip39_seed(self, threshold=2, count=3) -> Slip39Seed:
        import shamir_mnemonic
        secret = bytes.fromhex("aa" * 16)
        shares = shamir_mnemonic.generate_mnemonics(1, [(threshold, count)], secret)[0]
        seed = Slip39Seed(mnemonics=shares[:threshold])
        self.controller.storage.set_pending_seed(seed)
        return self.controller.storage.finalize_pending_seed()


def label_screen(label: str):
    """
    Stub SeedAddPassphraseScreen, which the save flow instantiates and
    ``.display()``s directly rather than going through run_screen().
    """
    return patch.object(
        seed_views.seed_screens,
        "SeedAddPassphraseScreen",
        return_value=MagicMock(display=MagicMock(return_value={"passphrase": label})),
    )


# ======================================================================
# SeedKeeper: save a seed to the card through the backup UI
# ======================================================================

class TestSeedKeeperSaveFlows(SmartcardFlowTest):
    """Blank card -> install SeedKeeper -> provision -> save seeds via the UI."""

    AID = "536565644B6565706572"
    CAP = "SeedKeeper-0.2-official.cap"

    _connector = None

    @pytest.fixture(scope="class", autouse=True)
    def applet(self, gp, cap_dir):
        result = gp.install_capfile(
            str(cap_dir / self.CAP),
            application_specific_parameters="1FFF",
        )
        logger.info(f"SeedKeeper install result: {result}")
        gp.close()
        try:
            self._provision()
        except Exception as exc:
            logger.warning(f"SeedKeeper provisioning failed (non-fatal): {exc}")
        yield
        self._disconnect()
        _reauth_and_delete(gp, self.AID)

    # -- card helpers --------------------------------------------------

    def _connect(self):
        from pysatochip.CardConnector import CardConnector

        connector = CardConnector(card_filter=["seedkeeper"])
        connector.cardmonitor.deleteObserver(connector.cardobserver)
        connector.cardservice.connection.connect()
        connector.card_select()
        (_, _, _, status) = connector.card_get_status()
        if connector.needs_secure_channel:
            connector.card_initiate_secure_channel()
        if status.get("setup_done"):
            connector.set_pin(0, list(CARD_PIN.encode("utf-8")))
            connector.card_verify_PIN()
        time.sleep(0.3)
        TestSeedKeeperSaveFlows._connector = connector
        return connector

    def _disconnect(self):
        if TestSeedKeeperSaveFlows._connector is not None:
            try:
                TestSeedKeeperSaveFlows._connector.card_disconnect()
            except Exception:
                pass
            TestSeedKeeperSaveFlows._connector = None

    def _provision(self):
        import os as _os

        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        pin_list = list(CARD_PIN.encode("utf-8"))
        if status.get("setup_done"):
            connector.set_pin(0, pin_list)
            connector.card_verify_PIN()
            return
        connector.card_setup(
            pin_tries0=5, ublk_tries0=1,
            pin0=pin_list, ublk0=list(_os.urandom(16)),
            pin_tries1=1, ublk_tries1=1,
            pin1=[0x30] * 6, ublk1=[0x30] * 6,
            memsize=0x4000, memsize2=0x0060,
            create_object_ACL=0x01, create_key_ACL=0x01, create_pin_ACL=0x01,
        )
        connector.set_pin(0, pin_list)
        self._disconnect()

    def _secret_count(self) -> int:
        connector = self._connect()
        (_, _, _, status) = connector.seedkeeper_get_status()
        count = status["nb_secrets"]
        self._disconnect()
        return count

    def _all_secret_labels(self) -> list:
        connector = self._connect()
        headers = connector.seedkeeper_list_secret_headers()
        self._disconnect()
        return [h.get("label", "") for h in headers]

    # -- tests ---------------------------------------------------------

    def test_save_bip39_seed_via_backup_menu(self):
        """
        Seeds > Backup > To SeedKeeper must put *this* seed on the card.

        The card-side assertion is the point: routing that merely reaches the
        view proves nothing if the wrong seed object arrives.
        """
        self.prime_controller_for_card()
        seed = self.store_bip39_seed()
        before = self._secret_count()

        with label_screen("flowtest-bip39"):
            self.run_sequence(
                initial_destination_view_args=dict(seed=seed),
                sequence=[
                    FlowStep(seed_views.SeedOptionsView,
                             button_data_selection=seed_views.SeedOptionsView.BACKUP),
                    FlowStep(seed_views.SeedBackupView,
                             button_data_selection=seed_views.SeedBackupView.TO_SEEDKEEPER),
                    FlowStep(seed_views.SaveToSeedkeeperView, screen_return_value=0),
                    FlowStep(seed_views.SeedOptionsView),
                ],
            )

        assert self._secret_count() == before + 1
        assert any("flowtest-bip39" in label for label in self._all_secret_labels())

    def test_save_slip39_share_via_backup_menu(self):
        """
        A SLIP-39 seed must route through share selection, and the share the
        user picked is the one that reaches the card.
        """
        self.prime_controller_for_card()
        seed = self.store_slip39_seed()
        before = self._secret_count()

        with label_screen("flowtest-slip39"):
            self.run_sequence(
                initial_destination_view_args=dict(seed=seed),
                sequence=[
                    FlowStep(seed_views.SeedOptionsView,
                             button_data_selection=seed_views.SeedOptionsView.BACKUP),
                    FlowStep(seed_views.SeedBackupView,
                             button_data_selection=seed_views.SeedBackupView.TO_SEEDKEEPER),
                    FlowStep(seed_views.SeedSlip39SelectShareView, screen_return_value=1),
                    FlowStep(seed_views.SaveToSeedkeeperView, screen_return_value=0),
                    FlowStep(seed_views.SeedOptionsView),
                ],
            )

        assert self._secret_count() == before + 1
        assert any("SLIP39:flowtest-slip39" in label for label in self._all_secret_labels())

    def test_saved_secret_round_trips_through_the_card(self):
        """
        Save a seed through the UI, then read it back off the card and confirm
        the mnemonic survived intact -- the property a backup actually needs.
        """
        self.prime_controller_for_card()
        seed = self.store_bip39_seed()

        with label_screen("flowtest-roundtrip"):
            self.run_sequence(
                initial_destination_view_args=dict(seed=seed),
                sequence=[
                    FlowStep(seed_views.SeedOptionsView,
                             button_data_selection=seed_views.SeedOptionsView.BACKUP),
                    FlowStep(seed_views.SeedBackupView,
                             button_data_selection=seed_views.SeedBackupView.TO_SEEDKEEPER),
                    FlowStep(seed_views.SaveToSeedkeeperView, screen_return_value=0),
                    FlowStep(seed_views.SeedOptionsView),
                ],
            )

        connector = self._connect()
        headers = connector.seedkeeper_list_secret_headers()
        sid = next(h["id"] for h in headers if "flowtest-roundtrip" in h.get("label", ""))
        exported = connector.seedkeeper_export_secret(sid, None)
        self._disconnect()

        raw = bytes.fromhex(exported["secret"])
        assert " ".join(BIP39_MNEMONIC).encode("utf-8") in raw


# ======================================================================
# Satochip: initialise a blank card with a seed through the UI
# ======================================================================

class TestSatochipImportSeedFlows(SmartcardFlowTest):
    """Blank card -> install Satochip -> provision -> seed it via the UI."""

    AID = "5361746F43686970"
    CAP = "SatoChip-0.12-official.cap"

    _connector = None

    @pytest.fixture(scope="class", autouse=True)
    def applet(self, gp, cap_dir):
        result = gp.install_capfile(str(cap_dir / self.CAP))
        logger.info(f"Satochip install result: {result}")
        gp.close()
        try:
            self._provision()
        except Exception as exc:
            logger.warning(f"Satochip provisioning failed (non-fatal): {exc}")
        yield
        self._disconnect()
        _reauth_and_delete(gp, self.AID)

    # -- card helpers --------------------------------------------------

    def _connect(self):
        from pysatochip.CardConnector import CardConnector

        connector = CardConnector(card_filter=["satochip"])
        connector.cardmonitor.deleteObserver(connector.cardobserver)
        connector.cardservice.connection.connect()
        connector.card_select()
        (_, _, _, status) = connector.card_get_status()
        if connector.needs_secure_channel:
            connector.card_initiate_secure_channel()
        if status.get("setup_done"):
            connector.set_pin(0, list(CARD_PIN.encode("utf-8")))
            connector.card_verify_PIN()
        time.sleep(0.3)
        TestSatochipImportSeedFlows._connector = connector
        return connector

    def _disconnect(self):
        if TestSatochipImportSeedFlows._connector is not None:
            try:
                TestSatochipImportSeedFlows._connector.card_disconnect()
            except Exception:
                pass
            TestSatochipImportSeedFlows._connector = None

    def _provision(self):
        import os as _os

        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        pin_list = list(CARD_PIN.encode("utf-8"))
        if status.get("setup_done"):
            connector.set_pin(0, pin_list)
            connector.card_verify_PIN()
            self._disconnect()
            return
        connector.card_setup(
            pin_tries0=5, ublk_tries0=1,
            pin0=pin_list, ublk0=list(_os.urandom(16)),
            pin_tries1=1, ublk_tries1=1,
            pin1=[0x30] * 6, ublk1=[0x30] * 6,
            memsize=0x4000, memsize2=0x0060,
            create_object_ACL=0x01, create_key_ACL=0x01, create_pin_ACL=0x01,
        )
        connector.set_pin(0, pin_list)
        self._disconnect()

    def _is_seeded(self) -> bool:
        connector = self._connect()
        (_, _, _, status) = connector.card_get_status()
        self._disconnect()
        return bool(status.get("is_seeded"))

    # -- tests ---------------------------------------------------------

    @pytest.mark.order(1)
    def test_import_stored_seed_onto_blank_satochip(self):
        """
        The card starts unseeded; choosing a stored seed in the import view must
        actually seed it. This is the flow that depends on the Seed object
        carrying real bytes -- an empty or wrong Seed would either raise or
        seed the card with the wrong key.
        """
        if self._is_seeded():
            pytest.skip("card already seeded; run against a freshly installed applet")

        self.prime_controller_for_card()
        self.store_bip39_seed()

        self.run_sequence(
            sequence=[
                # button 0 is the first stored seed's fingerprint
                FlowStep(smartcard_views.ToolsSatochipImportSeedView, screen_return_value=0),
            ],
        )

        assert self._is_seeded(), "Satochip did not report a seeded key after the UI import"

    @pytest.mark.order(2)
    def test_import_refuses_when_card_already_seeded(self):
        """
        A second import must be refused up front rather than failing generically
        deep in the card call.
        """
        if not self._is_seeded():
            pytest.skip("card is not seeded; the already-seeded branch is unreachable")

        self.prime_controller_for_card()
        self.store_bip39_seed()

        self.run_sequence(
            sequence=[
                FlowStep(smartcard_views.ToolsSatochipImportSeedView, screen_return_value=0),
                FlowStep(MainMenuView),
            ],
        )
