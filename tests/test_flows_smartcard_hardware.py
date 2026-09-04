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
    #
    # Everything here must be inside the guard, `readers()` included: on a
    # machine with no PC/SC daemon at all -- every CI runner -- enumerating
    # readers raises EstablishContextException("Access denied") rather than
    # returning an empty list. Absence of the whole subsystem is a reason to
    # skip, exactly like absence of a card.
    try:
        from smartcard.System import readers

        physical = [r for r in readers() if not _is_virtual_reader(r)]
        has_card = any(_reader_has_card(r) for r in physical)
    except ImportError:
        pytest.skip("pyscard not installed")
    except Exception as exc:
        pytest.skip(f"PC/SC unavailable: {_describe(exc)}")

    if not has_card:
        pytest.skip("No smartcard inserted in any physical PC/SC reader")

    try:
        pygp.terminal()
        pygp.card()
    except BaseException as exc:
        pytest.skip(f"No GlobalPlatform-capable card detected: {_describe(exc)}")


def _describe(exc) -> str:
    """
    Render an exception for a skip message without trusting its __str__.

    pyscard's PC/SC exceptions format themselves by calling back into the
    native SCardGetErrorMessage, which can itself raise -- so interpolating
    one into an f-string can replace a clean skip with a spurious error. Fall
    back to the class name, which is the diagnostic part anyway.
    """
    try:
        return f"{type(exc).__name__}: {exc}"
    except BaseException:
        return type(exc).__name__


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


def _reinstall_blank(gp, cap_path, aid, **install_kwargs):
    """
    Install `cap_path` onto a card carrying no prior copy of `aid`.

    install_capfile skips the load and install steps for a package that is
    already on the card, so installing over a previous run leaves that run's PIN
    and key material in place. Provisioning then short-circuits on setup_done,
    the PIN this run expects never matches, and the seed import is refused with a
    bare status word. Deleting first makes "install, initialise, test, uninstall"
    mean what it says.
    """
    _reauth_and_delete(gp, aid)
    result = gp.install_capfile(str(cap_path), **install_kwargs)
    gp.close()
    return result


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
        Save a seed through the UI, then read it back off the card and rebuild
        the mnemonic -- the property a backup actually needs.

        A SeedKeeper v2 Masterseed secret does not store the words. It stores
        the master seed bytes plus the BIP-39 *entropy*, which is why the save
        path converts the mnemonic to entropy on the way in and the restore
        path converts it back on the way out. Asserting on the rebuilt mnemonic
        therefore exercises both halves of that conversion, not just the
        transport.

        Layout (stype "Masterseed", subtype 0x01), mirroring
        SeedKeeperSelectView's decoder:

            masterseed_size | masterseed | wordlist_byte |
            entropy_size    | entropy    | passphrase_size | passphrase
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

        offset = 0
        masterseed_size = raw[offset]; offset += 1
        masterseed = raw[offset:offset + masterseed_size]; offset += masterseed_size
        wordlist_byte = raw[offset]; offset += 1
        entropy_size = raw[offset]; offset += 1
        entropy = raw[offset:offset + entropy_size]; offset += entropy_size

        from embit import bip39
        from pysatochip.JCconstants import BIP39_WORDLIST_DIC

        # English-only, project wide -- the save path must not have written
        # anything else.
        assert BIP39_WORDLIST_DIC.get(wordlist_byte) == "english"

        # The entropy on the card must rebuild the exact mnemonic we saved...
        assert bip39.mnemonic_from_bytes(entropy) == " ".join(BIP39_MNEMONIC)

        # ...and the stored master seed must match what that mnemonic derives,
        # which is what any restoring wallet will actually use.
        assert masterseed == Seed(mnemonic=BIP39_MNEMONIC).seed_bytes


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



# ======================================================================
# PSBT signing against a live card
# ======================================================================
#
# These cover the parser's *card* root mode, which no desktop test can reach.
#
# A seed-backed parse hands PSBTParser the master key: `root` is m, `root_path`
# is empty, and every derivation the psbt names is measured from that same
# point. A card never exports its master private key, so the flow exports an
# account-level xpub instead, and PSBTParser is given three things rather than
# one: `root` (the account key), `root_path` (where that key sits), and
# `master_fingerprint` (which the psbt's derivations actually name). Ownership
# is then established by stripping the root_path prefix and deriving the
# remainder -- see PSBTParser.seed_owns_pubkey.
#
# Each of those three has a plausible-looking wrong answer: comparing against
# the account key's own fingerprint instead of the master's, or deriving a full
# path from an account-level key. Both fail *closed* -- the card verifies
# nothing, so every psbt looks unsignable or every change output looks forged --
# so the failure mode resembles a working refusal. Only a real card proves the
# difference.

ACCOUNT_PATH = "m/84h/1h/0h"
INPUT_PATH = ACCOUNT_PATH + "/0/0"
CHANGE_PATH = ACCOUNT_PATH + "/1/0"

# A seed that is not the card's, for building claims the card cannot honour.
FOREIGN_MNEMONIC = "shove album flame dad equal cook spike cheap hollow exit great forest".split()


def _regtest_root(mnemonic: list[str]):
    from embit import bip32
    from embit.networks import NETWORKS

    return bip32.HDKey.from_seed(
        Seed(mnemonic=mnemonic).seed_bytes, version=NETWORKS["regtest"]["xprv"]
    )


def build_signable_psbt(mnemonic: list[str]):
    """
    A real, parseable 1-in/2-out native segwit psbt: spending to a stranger with
    change coming back to `mnemonic`'s own wallet.

    `_build_psbt` in test_smartcard_hardware.py is deliberately a stub -- enough
    for the signer helper, not enough for PSBTParser, which needs a transaction,
    prevouts and amounts. This builds the real thing, so the parse under test is
    the parse a user's psbt actually gets.
    """
    from embit import bip32, script
    from embit.psbt import PSBT, DerivationPath
    from embit.transaction import Transaction, TransactionInput, TransactionOutput

    root = _regtest_root(mnemonic)
    input_key = root.derive(INPUT_PATH)
    change_key = root.derive(CHANGE_PATH)
    stranger_key = _regtest_root(FOREIGN_MNEMONIC).derive("m/84h/1h/0h/0/7")

    tx = Transaction(
        version=2,
        vin=[TransactionInput(bytes.fromhex("11" * 32), 0)],
        vout=[
            TransactionOutput(70_000, script.p2wpkh(stranger_key.to_public())),
            TransactionOutput(29_000, script.p2wpkh(change_key.to_public())),
        ],
        locktime=0,
    )

    psbt = PSBT(tx)
    psbt.inputs[0].witness_utxo = TransactionOutput(
        100_000, script.p2wpkh(input_key.to_public()))
    psbt.inputs[0].bip32_derivations[input_key.to_public().key] = DerivationPath(
        root.my_fingerprint, bip32.parse_path(INPUT_PATH))
    psbt.outputs[1].bip32_derivations[change_key.to_public().key] = DerivationPath(
        root.my_fingerprint, bip32.parse_path(CHANGE_PATH))
    return psbt


def claim_ownership(scope, mnemonic: list[str], claimed_path: str, public_key):
    """
    Write a derivation asserting that `mnemonic`'s seed owns `public_key` at
    `claimed_path`.

    Forging one needs no key material at all: nothing in a psbt ties a
    fingerprint to the key stored beside it, and the fingerprint is published in
    every psbt that seed has ever been sent. Pass a key the seed does not own and
    the result is a psbt asserting ownership that does not exist.
    """
    from embit import bip32
    from embit.psbt import DerivationPath

    scope.bip32_derivations[public_key] = DerivationPath(
        _regtest_root(mnemonic).my_fingerprint, bip32.parse_path(claimed_path))


def foreign_public_key(path: str = "m/84h/1h/0h/0/0"):
    """A genuine key belonging to a seed that is not the card's."""
    return _regtest_root(FOREIGN_MNEMONIC).derive(path).to_public().key


class CardPSBTSigningFlowTest(SmartcardFlowTest):
    """
    Shared body for the card signing modes. Subclasses supply the applet
    lifecycle, a connector, and which PSBTSelectSeedView button selects them.
    """

    CARD_BUTTON = None       # a PSBTSelectSeedView ButtonOption; set by the subclass

    # Each concrete subclass carries its own `pytestmark = pytest.mark.order(N)`.
    #
    # pytest-order sorts globally rather than per class, and each applet lifecycle
    # is a class-scoped fixture, so two classes sharing an order number interleave
    # and one installs or deletes its applet out from under the other's tests. A
    # distinct number per class keeps each class's install -> initialise -> tests
    # -> uninstall contiguous, and tests within a class keep their definition
    # order, which is the order they are written to run in.
    #
    # The number cannot be set here or derived per-test in this base: a marker
    # applied in the base class body binds at definition time, so every subclass
    # would inherit the same value and collide.

    # -- plumbing ------------------------------------------------------

    def prime_for_psbt(self, psbt):
        """
        Stage a psbt and put the controller in the state PSBTSelectSeedView
        expects, on regtest so the card's testnet account path is the live one.
        """
        from seedsigner.models.settings import SettingsConstants as SC

        self.prime_controller_for_card()
        self.settings.set_value(SC.SETTING__NETWORK, SC.REGTEST)
        self.controller.psbt = psbt
        self.controller.psbt_parser = None
        self.controller.psbt_seed = None
        self.controller.psbt_sign_with_satochip = False

    def run_card_selection(self, psbt, expected_view):
        """
        Drive PSBTSelectSeedView against the real card and stop where expected.

        The card is chosen by ButtonOption rather than by index: the menu is
        built conditionally from settings, so a fixed number silently selects the
        wrong signer as soon as an option above it appears or disappears.
        """
        from seedsigner.views import psbt_views

        self.prime_for_psbt(psbt)
        self.run_sequence([
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=self.CARD_BUTTON),
            FlowStep(expected_view),
        ])

    def reconnect(self):
        """
        Drop every open card session and start a new one.

        Running a flow hands the card to init_satochip, which builds its own
        connector and parks it on the controller. That leaves this class's cached
        connector holding a session the card has already torn down, and the next
        direct call fails with a bare status word (0x9C23) that names nothing
        about the real problem. So every direct card access starts over rather
        than trusting a connector that a flow may have invalidated.
        """
        parked = getattr(self.controller, "Satochip_Connector", None)
        if parked is not None:
            try:
                parked.card_disconnect()
            except Exception:
                pass
            self.controller.Satochip_Connector = None
        self._disconnect()
        return self._connect()

    def card_account_xpub(self) -> str:
        return self.reconnect().card_bip32_get_xpub(ACCOUNT_PATH.replace("h", "'"),
                                                    "p2wpkh", False)

    def card_master_fingerprint(self) -> bytes:
        from embit.bip32 import HDKey

        return HDKey.from_base58(
            self.reconnect().card_bip32_get_xpub("", "p2wpkh", False)).my_fingerprint

    # -- tests ---------------------------------------------------------

    def test_card_holds_the_seed_these_tests_assume(self):
        """
        Everything below compares the card against keys derived from
        BIP39_MNEMONIC. If the card is carrying some other seed, those
        comparisons fail for reasons that have nothing to do with the code under
        test, so establish it once here and fail with a legible message.
        """
        from embit.bip32 import HDKey

        expected = _regtest_root(BIP39_MNEMONIC).my_fingerprint
        actual = self.card_master_fingerprint()
        assert actual == expected, (
            "card master fingerprint %s does not match BIP39_MNEMONIC (%s); "
            "the applet was not re-seeded" % (actual.hex(), expected.hex()))

        on_card = HDKey.from_base58(self.card_account_xpub())
        in_test = _regtest_root(BIP39_MNEMONIC).derive(ACCOUNT_PATH).to_public()
        assert on_card.key.sec() == in_test.key.sec()

    def test_parse_runs_in_account_xpub_root_mode(self):
        """
        The card hands the parser an account-level xpub, not a master key. The
        three fields that make that work have to be set consistently, and the
        ownership scan has to succeed against them.

        Asserting verified_input_derivation_paths is the point: an empty list
        here is exactly what a wrong fingerprint or an unstripped derivation path
        produces, and it is indistinguishable from "this card cannot sign" at
        every layer above.
        """
        from embit import bip32
        from seedsigner.views import psbt_views

        self.run_card_selection(build_signable_psbt(BIP39_MNEMONIC),
                                psbt_views.PSBTOverviewView)

        parser = self.controller.psbt_parser
        assert parser is not None, "card selection did not build a parser"
        assert self.controller.psbt_sign_with_satochip is True

        assert parser.seed is None, "card mode must not carry a Seed"
        assert parser.root_path == bip32.parse_path(ACCOUNT_PATH)
        assert parser.master_fingerprint == self.card_master_fingerprint()
        assert parser.root.my_fingerprint != parser.master_fingerprint, (
            "root should be the account xpub, not the master key -- otherwise this "
            "test proves nothing about the account-relative derivation")
        assert parser.can_verify_derivations is True

        assert parser.verified_input_derivation_paths == [bip32.parse_path(INPUT_PATH)]
        assert parser.verified_output_derivation_paths == [
            None, bip32.parse_path(CHANGE_PATH)]

    def test_card_parse_agrees_with_a_seed_parse(self):
        """
        Same psbt, same wallet, two ways of reaching the keys. Every number the
        user is shown, and every ownership verdict behind it, must come out the
        same -- otherwise the account-relative derivation is subtly wrong in a
        way no single-mode test would notice.
        """
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.models.settings import SettingsConstants as SC
        from seedsigner.views import psbt_views

        self.run_card_selection(build_signable_psbt(BIP39_MNEMONIC),
                                psbt_views.PSBTOverviewView)
        from_card = self.controller.psbt_parser

        from_seed = PSBTParser(build_signable_psbt(BIP39_MNEMONIC),
                               seed=Seed(mnemonic=BIP39_MNEMONIC), network=SC.REGTEST)

        assert from_card.verified_input_derivation_paths == from_seed.verified_input_derivation_paths
        assert from_card.verified_output_derivation_paths == from_seed.verified_output_derivation_paths
        assert from_card.change_data == from_seed.change_data
        assert from_card.spend_amount == from_seed.spend_amount
        assert from_card.change_amount == from_seed.change_amount
        assert from_card.fee_amount == from_seed.fee_amount
        assert from_card.destination_addresses == from_seed.destination_addresses

    def test_forged_change_claim_is_refused(self):
        """
        The attack the ownership scan exists to stop, run against a real card: an
        output claims the card's fingerprint on a key the card does not derive,
        so a naive signer labels it "your change" while the funds leave the
        wallet for good.

        This is the case that would silently regress if the card's account-level
        root were fed to a master-relative ownership check. That refuses
        everything, including this, so the regression still looks like a pass.
        test_parse_runs_in_account_xpub_root_mode is what separates the two.
        """
        from seedsigner.views import psbt_views

        psbt = build_signable_psbt(BIP39_MNEMONIC)
        psbt.outputs[1].bip32_derivations.clear()
        claim_ownership(psbt.outputs[1], BIP39_MNEMONIC, CHANGE_PATH, foreign_public_key())

        self.run_card_selection(psbt, psbt_views.PSBTOutputOwnershipClaimFailedView)

        assert self.controller.psbt_parser is None
        assert self.controller.psbt_sign_with_satochip is False

    def test_forged_input_claim_is_refused(self):
        """
        The same false claim on an input. It cannot cost the user anything -- no
        signature can come of it -- so it is reported as a problem with the
        transaction rather than as an attack, but it still stops the flow.
        """
        from seedsigner.views import psbt_views

        psbt = build_signable_psbt(BIP39_MNEMONIC)
        claim_ownership(psbt.inputs[0], BIP39_MNEMONIC, INPUT_PATH,
                        foreign_public_key("m/84h/1h/0h/0/9"))

        self.run_card_selection(psbt, psbt_views.PSBTInputOwnershipClaimFailedView)

        assert self.controller.psbt_parser is None

    def test_psbt_for_another_wallet_cannot_be_signed(self):
        """
        A psbt belonging to a different wallet must not verify against this card.

        Driven at the parser rather than through the menu, because the menu never
        gets this far: PSBTSelectSeedView compares fingerprints first and sends
        the user back to pick another signer. That earlier guard is also why
        RejectCode.SEED_CANNOT_SIGN, which covers this case for a seed, is not
        reachable through the card path -- but the parser must still be right
        about it, since it is the layer that actually decides.
        """
        import pytest as _pytest
        from embit import bip32
        from embit.bip32 import HDKey
        from seedsigner.models.psbt_parser import InvalidPSBTError, PSBTParser, RejectCode
        from seedsigner.models.settings import SettingsConstants as SC

        with _pytest.raises(InvalidPSBTError) as excinfo:
            PSBTParser(
                build_signable_psbt(FOREIGN_MNEMONIC),
                seed=None,
                root=HDKey.from_base58(self.card_account_xpub()),
                root_path=bip32.parse_path(ACCOUNT_PATH),
                master_fingerprint=self.card_master_fingerprint(),
                network=SC.REGTEST,
            )
        assert excinfo.value.code == RejectCode.SEED_CANNOT_SIGN

    def test_verified_psbt_signs_on_the_card(self):
        """
        End to end: parse in card mode, then let PSBTFinalizeView drive the real
        applet, and check that the signature the card produced verifies against
        the key the parser said the card owns.

        This closes the loop the tests above leave open. They prove the parser
        believes the card owns the input; only a signature that the input's own
        pubkey verifies proves it was right.
        """
        from embit.ec import Signature
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.views import psbt_views

        psbt = build_signable_psbt(BIP39_MNEMONIC)
        self.run_card_selection(psbt, psbt_views.PSBTOverviewView)

        input_pubkey = _regtest_root(BIP39_MNEMONIC).derive(INPUT_PATH).to_public().key
        assert PSBTParser.sig_count(psbt) == 0

        view = psbt_views.PSBTFinalizeView()
        view.run_screen = MagicMock(return_value=0)   # APPROVE_PSBT
        view.run()

        assert PSBTParser.sig_count(psbt) >= 1, "the card produced no signature"
        signature = psbt.inputs[0].partial_sigs.get(input_pubkey)
        assert signature is not None, (
            "the card signed under a key other than the one the parser verified")

        # psbt.sighash resolves the script and value for the input itself; the
        # trailing byte of the signature is the sighash flag, not DER.
        assert input_pubkey.verify(Signature.parse(signature[:-1]), psbt.sighash(0)), (
            "the card's signature does not verify against the verified input key")


class TestSatochipPSBTSigningFlows(CardPSBTSigningFlowTest):
    """Blank card -> install Satochip -> seed it -> sign a psbt through the UI."""

    AID = "5361746F43686970"
    CAP = "SatoChip-0.12-official.cap"
    # Above TestSatochipImportSeedFlows' 1-2 so the two Satochip classes do not
    # interleave their applet lifecycles.
    pytestmark = pytest.mark.order(10)

    _connector = None

    @pytest.fixture(scope="class", autouse=True)
    def applet(self, gp, cap_dir):
        # install -> initialise -> tests -> uninstall. Preparation failures are
        # raised, not skipped: the card is present, so a card that will not
        # provision or seed is a real failure and every test below would
        # otherwise fail somewhere less informative.
        logger.info("Satochip install result: %s",
                    _reinstall_blank(gp, cap_dir / self.CAP, self.AID))
        self._initialise()
        yield
        self._disconnect()
        _reauth_and_delete(gp, self.AID)

    @property
    def CARD_BUTTON(self):
        from seedsigner.views import psbt_views
        return psbt_views.PSBTSelectSeedView.SATOCHIP

    # -- card lifecycle ------------------------------------------------
    #
    # Deliberately not shared with TestSatochipImportSeedFlows: that class
    # provisions a card to be left *unseeded* so its import flow has something to
    # do, while this one needs a card already carrying BIP39_MNEMONIC. Same APDUs,
    # opposite end states.

    def _connect(self):
        from pysatochip.CardConnector import CardConnector

        if TestSatochipPSBTSigningFlows._connector is None:
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
            TestSatochipPSBTSigningFlows._connector = connector
        return TestSatochipPSBTSigningFlows._connector

    def _disconnect(self):
        if TestSatochipPSBTSigningFlows._connector is not None:
            try:
                TestSatochipPSBTSigningFlows._connector.card_disconnect()
            except Exception:
                pass
            TestSatochipPSBTSigningFlows._connector = None

    def _initialise(self):
        """
        Provision the applet and load the seed, on one session. See the Keycard
        version for why setup and seeding must not be split across connectors.
        """
        import os as _os

        connector = self._connect()
        pin_list = list(CARD_PIN.encode("utf-8"))

        (_, _, _, status) = connector.card_get_status()
        if not status.get("setup_done"):
            connector.card_setup(
                pin_tries0=5, ublk_tries0=1,
                pin0=pin_list, ublk0=list(_os.urandom(16)),
                pin_tries1=1, ublk_tries1=1,
                pin1=[0x30] * 6, ublk1=[0x30] * 6,
                memsize=0x4000, memsize2=0x0060,
                create_object_ACL=0x01, create_key_ACL=0x01, create_pin_ACL=0x01,
            )
        connector.set_pin(0, pin_list)
        connector.card_verify_PIN()

        (_, _, _, status) = connector.card_get_status()
        if not status.get("is_seeded"):
            connector.card_bip32_import_seed(list(Seed(mnemonic=BIP39_MNEMONIC).seed_bytes))
            (_, _, _, status) = connector.card_get_status()
            if not status.get("is_seeded"):
                raise RuntimeError(
                    "Satochip accepted the seed import but reports no key: %s" % status)

        self._disconnect()


class TestKeycardPSBTSigningFlows(CardPSBTSigningFlowTest):
    """Blank card -> install Keycard -> seed it -> sign a psbt through the UI."""

    AID = "A0000008040001"
    CAP = "Keycard_v3.2.cap"
    PIN = "123456"
    pytestmark = pytest.mark.order(20)

    _connector = None

    @pytest.fixture(scope="class", autouse=True)
    def applet(self, gp, cap_dir):
        try:
            import keycard  # noqa: F401
        except ImportError:
            pytest.skip("keycard-py not installed (pip install keycard-py)")

        logger.info("Keycard install result: %s",
                    _reinstall_blank(gp, cap_dir / self.CAP, self.AID))
        self._initialise()
        yield
        self._disconnect()
        _reauth_and_delete(gp, self.AID)

    @property
    def CARD_BUTTON(self):
        from seedsigner.views import psbt_views
        return psbt_views.PSBTSelectSeedView.KEYCARD

    def prime_for_psbt(self, psbt):
        from seedsigner.models.settings import SettingsConstants as SC

        super().prime_for_psbt(psbt)
        # PSBTSelectSeedView offers each card only when its own support setting is
        # on. Satochip's happens to default to enabled, Keycard's does not, so
        # without this the menu has no Keycard button to select.
        self.settings.set_value(SC.SETTING__KEYCARD_SUPPORT, SC.OPTION__ENABLED)
        # The Keycard applet has its own PIN, and its own backend: init_satochip
        # only prompts for a PIN when the controller has none cached, and picks
        # the connector class from smartcard_backend_preference.
        self.controller.Satochip_PIN = list(self.PIN.encode("utf-8"))
        self.controller.smartcard_backend_preference = "keycard"

    # -- card lifecycle ------------------------------------------------

    def _connect(self):
        from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

        if TestKeycardPSBTSigningFlows._connector is None:
            connector = KeycardSatochipConnector.create(card_filter=["satochip"])
            connector.set_pin(0, list(self.PIN.encode("utf-8")))
            (_, _, _, status) = connector.card_get_status()
            if status.get("setup_done"):
                connector.card_verify_PIN()
            TestKeycardPSBTSigningFlows._connector = connector
        return TestKeycardPSBTSigningFlows._connector

    def _disconnect(self):
        if TestKeycardPSBTSigningFlows._connector is not None:
            try:
                TestKeycardPSBTSigningFlows._connector.card_disconnect()
            except Exception:
                pass
            TestKeycardPSBTSigningFlows._connector = None

    def _initialise(self):
        """
        Provision the applet and load the seed, on one session.

        This is deliberately a single step. card_setup leaves the session that
        ran it authenticated -- card_get_status returns the applet's full native
        status -- and LOAD KEY is accepted there. A connector built afterwards
        against the same, now set-up card comes back in a reduced state (status
        answers with a four-field fallback rather than the native record) and the
        applet refuses LOAD KEY with 0x6985. So the seed goes on while the card
        is still talking to the session that set it up.

        The class fixture installs a blank applet first, so this always runs the
        full path rather than resuming a half-initialised card.
        """
        connector = self._connect()
        pin_list = list(self.PIN.encode("utf-8"))

        (_, _, _, status) = connector.card_get_status()
        if not status.get("setup_done"):
            if connector.needs_secure_channel:
                connector.card_initiate_secure_channel()
            connector.card_setup(
                pin_tries_0=5, ublk_tries_0=1,
                pin_0=self.PIN, ublk_0=list(bytes(range(16))),
                pin_tries_1=1, ublk_tries_1=1,
                pin_1="654321", ublk_1=b"654321",
                secmemsize=0x0000, memsize=0,
                create_object_ACL=0x01, create_key_ACL=0x01, create_pin_ACL=0x01,
            )
            connector.set_pin(0, pin_list)

        (_, _, _, status) = connector.card_get_status()
        if not (status.get("key_initialized") or status.get("is_seeded")):
            (_, sw1, sw2) = connector.card_bip32_import_seed(
                list(Seed(mnemonic=BIP39_MNEMONIC).seed_bytes))
            # card_bip32_import_seed reports failure in its status word rather
            # than by raising, so an unchecked call looks like a success and only
            # shows up later as an unexplained 0x6985 on every derivation.
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError(
                    "Keycard refused the seed import: SW=%02X%02X" % (sw1, sw2))
            (_, _, _, status) = connector.card_get_status()
            if not (status.get("key_initialized") or status.get("is_seeded")):
                raise RuntimeError(
                    "Keycard accepted the seed import but reports no key: %s" % status)

        self._disconnect()
