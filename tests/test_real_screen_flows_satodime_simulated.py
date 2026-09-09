"""
    Satodime flows driven against a *real* applet running in jcardsim.

    The Satodime menu + views were cherry-picked from PR #66 and call the pysatochip
    ``satodime_*`` APDUs (status, keyslot status, pubkey, seal, unseal). Those calls only
    mean something if SeedSigner's client and the applet agree on the wire format -- exactly
    the class of bug the jcardsim suites exist to catch. Everything here skips when Java
    or the Satochip-DIY sources are absent.

    Three levels:
      * connector-level -- prove the APDUs the views depend on round-trip against the applet;
      * view-level with a stubbed connector -- render slot screens;
      * view-level through the real ``init_satochip`` -- the only level that covers card
        setup state, which is where a factory-fresh Satodime used to demand a PIN.

    Why the earlier version of this file passed while the feature was broken on hardware:

      * ``simulated_satodime`` monkeypatches ``init_satochip`` away, so the setup-state
        handling that prompted for a PIN on a fresh Satodime was never executed.
      * a fresh applet has no sealed slots, so ``satodime_get_pubkey`` raised before the
        views ever reached the address derivation -- hiding ``ec.PublicKey(sec_bytes)``,
        which is the wrong embit constructor and always raises.
      * the address test asserted only on navigation, so a screen whose body was an
        exception message counted as a pass.
      * nothing sealed a slot, so the applet's ``setupDone`` gate (0x9C04 on every
        state-changing APDU) was never hit at all.

    The tests below close each of those: seal for real, and assert on what is rendered.
"""

import re
import sys
from unittest.mock import MagicMock

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401
from base import FlowStep, FlowTest

# base.py stubs pysatochip so the ordinary suite runs cardless; these need it real.
for _name in [m for m in sys.modules if m == "pysatochip" or m.startswith("pysatochip.")]:
    if isinstance(sys.modules[_name], MagicMock):
        del sys.modules[_name]

from jcardsim import JCardSimUnavailable, why_unavailable
from real_screen_fixtures import simulated_satodime, simulated_satodime_raw
from ui_driver import Back, UISession, select

# tools_views must be imported first: it is a facade that star-imports smartcard_views.
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.views import tools_views
from seedsigner.views import smartcard_views
from seedsigner.helpers import satodime_coins, seedkeeper_utils
from seedsigner.models.settings import SettingsConstants
from seedsigner.views.view import MainMenuView


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)


# A mainnet native-segwit (P2WPKH) address, which is what the Satodime views render for
# a live slot -- matching what the official Satodime apps derive. Deliberately strict:
# an exception message must not satisfy it, and neither must a legacy P2PKH address.
BECH32_ADDRESS = re.compile(r"^bc1q[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38}$")

SW_SETUP_NOT_DONE = (0x9C, 0x04)

# The Bitcoin CoinSpec, which is what these Satodime views render by default.
BTC = satodime_coins.COINS[satodime_coins.SLIP44_BTC]


def claim(connector):
    """Run the Satodime setup the views now perform via ``init_satochip``."""
    from seedsigner.helpers import seedkeeper_utils

    (_resp, sw1, sw2) = seedkeeper_utils.claim_satodime_ownership(connector)
    assert (sw1, sw2) == (0x90, 0x00), f"satodime setup failed: {sw1:#x} {sw2:#x}"


def _seal_slot_zero():
    """Claim + seal slot 0 (BTC) by driving the real views. Call inside ``with ctx:``.

    The seal view now reads slot state from the Controller cache, so we pre-build it
    first (by reading slot 0 as uninitialized). The seal view updates the cache on
    success, so subsequent views see the new Sealed state.
    """
    claim_view = smartcard_views.ToolsSatodimeClaimView()
    claim_view.run_screen = ScreenRecorder(0, 0)
    claim_view.run()

    # Pre-populate cache: slot 0 is Uninitialized.
    _populate_cache([(smartcard_views.SATODIME_SLOT_UNINITIALIZED, None, None)])

    seal_view = smartcard_views.ToolsSatodimeSealSlotView(0)
    seal_view.run_screen = ScreenRecorder(0, 0, 0)  # Seal As (BTC) -> No Backup -> Success
    seal_view.run()


def _unseal_slot_zero():
    """Unseal slot 0 by driving the real UnsealSlotView. Call inside ``with ctx:``.

    The unseal view reads slot state from the cache; _seal_slot_zero already set the
    cache to Sealed. The unseal view updates the cache to Unsealed on success.
    """
    view = smartcard_views.ToolsSatodimeUnsealSlotView(0)
    view.run_screen = ScreenRecorder(0, 0)  # confirm unseal warning -> ack Unsealed
    view.run()


def _populate_cache(slots):
    """Set the controller slot cache directly (avoids a card read in test helpers)."""
    from seedsigner.controller import Controller
    Controller.get_instance().satodime_slot_cache = {
        "card_id": "test",
        "max_keys": max(len(slots), 3),
        "slots": list(slots) + [(smartcard_views.SATODIME_SLOT_UNINITIALIZED, None, None)] * max(0, 3 - len(slots)),
    }


class ScreenRecorder:
    """Stand-in for ``View.run_screen`` that records every screen and scripts returns."""

    def __init__(self, *returns):
        self.calls = []
        self._returns = list(returns)

    def __call__(self, screen_cls, **kwargs):
        self.calls.append((screen_cls.__name__, kwargs))
        if not self._returns:
            raise AssertionError(
                f"unscripted screen: {screen_cls.__name__} title={kwargs.get('title')!r} "
                f"text={kwargs.get('text')!r}"
            )
        return self._returns.pop(0)

    @property
    def titles(self):
        return [kwargs.get("title") for _cls, kwargs in self.calls]

    @property
    def texts(self):
        return [kwargs.get("text") for _cls, kwargs in self.calls if kwargs.get("text")]

    def body_for(self, title):
        for _cls, kwargs in self.calls:
            if kwargs.get("title") == title:
                return kwargs.get("text")
        raise AssertionError(f"no screen titled {title!r}; saw {self.titles}")


def _fresh_connector():
    """A connector onto whatever card the active jcardsim fixture is serving."""
    from pysatochip.CardConnector import CardConnector

    return CardConnector(card_filter=["satodime"])


class _StubConnection:
    def __init__(self, reader):
        self._reader = reader

    def getReader(self):
        return self._reader


class _StubCardService:
    def __init__(self, reader):
        self.connection = _StubConnection(reader)


def _connector_reporting_reader(reader):
    class Stub:
        cardservice = _StubCardService(reader)

    return Stub()


class SatodimeSimulatedFlowTest(FlowTest):

    def setup_method(self):
        super().setup_method()
        for setting in (
            SettingsConstants.SETTING__SMARTCARD_SUPPORT,
            SettingsConstants.SETTING__SATOCHIP_SUPPORT,
        ):
            self.settings.set_value(setting, SettingsConstants.OPTION__ENABLED)


class TestSatodimeConnectorAgainstRealApplet(SatodimeSimulatedFlowTest):
    """The APDUs the Satodime views lean on must round-trip against real bytecode."""

    def test_status_and_card_type(self, monkeypatch):
        try:
            ctx = simulated_satodime(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            assert connector.card_type == "Satodime"
            # These are the first three calls every Satodime view makes.
            connector.satodime_set_unlock_secret()
            connector.satodime_set_unlock_counter()
            (_, sw1, sw2, status) = connector.satodime_get_status()
            assert (sw1, sw2) == (0x90, 0x00)
            assert "max_num_keys" in status

    def test_fresh_card_refuses_seal_until_setup_has_run(self, monkeypatch):
        """
        The applet gates every state-changing APDU behind ``setupDone``.

        A factory-fresh Satodime answers status queries happily but rejects seal with
        0x9C04, which is why "Seal Slot" failed on a real card while every simulated
        test passed. Pin both halves: refused before setup, accepted after.
        """
        try:
            ctx = simulated_satodime(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            (_, _, _, status) = connector.card_get_status()
            assert status["setup_done"] is False, "fresh applet should report setup not done"

            connector.satodime_set_unlock_secret()
            connector.satodime_set_unlock_counter()
            connector.satodime_get_status()

            (_, sw1, sw2, _, _) = connector.satodime_seal_key(0, bytes(32))
            assert (sw1, sw2) == SW_SETUP_NOT_DONE, "seal must be refused before setup"

            claim(connector)

            (_, _, _, status) = connector.card_get_status()
            assert status["setup_done"] is True

            connector.satodime_get_status()  # refresh the unlock counter
            (_, sw1, sw2, _, pub_comp) = connector.satodime_seal_key(0, bytes(range(32)))
            assert (sw1, sw2) == (0x90, 0x00), "seal must succeed once setup has run"
            assert len(bytes(pub_comp)) == 33, "compressed secp256k1 pubkey"

    def test_sealed_pubkey_parses_as_an_embit_key(self, monkeypatch):
        """
        The card hands back a 33-byte SEC pubkey.

        ``ec.PublicKey(...)`` wants secp256k1's internal 64-byte point, so passing the
        card's bytes to it raises "Pubkey should be 64 bytes long". Views must go through
        ``_satodime_pubkey`` (i.e. ``ec.PublicKey.parse``). Asserting on a real card
        pubkey is what makes that a test failure rather than a runtime one.
        """
        try:
            ctx = simulated_satodime(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            claim(connector)
            connector.satodime_set_unlock_secret()
            connector.satodime_set_unlock_counter()
            connector.satodime_get_status()
            (_, sw1, sw2, _, pub_comp) = connector.satodime_seal_key(0, bytes(range(32)))
            assert (sw1, sw2) == (0x90, 0x00)

            address = smartcard_views._satodime_address(pub_comp, BTC, is_testnet=False)
            assert BECH32_ADDRESS.match(address), address


class TestSatodimeSlotListAgainstRealApplet(SatodimeSimulatedFlowTest):
    """The slot-centric Satodime menu renders the real slot list.

    We open the list then press BACK, exercising satodime_get_status + get_keyslot_status
    end to end without depending on how many slots the applet reports.
    """

    def test_renders_the_slot_list(self, monkeypatch):
        try:
            ctx = simulated_satodime(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            # Skip (rather than fail) if this jcardsim build can't service the status APDU
            # or exposes no slots to render -- neither is a SeedSigner bug.
            try:
                connector.satodime_set_unlock_secret()
                connector.satodime_set_unlock_counter()
                (_, sw1, sw2, status) = connector.satodime_get_status()
            except Exception as exc:  # pragma: no cover - environment dependent
                pytest.skip(f"satodime status unsupported under jcardsim: {exc}")
            if (sw1, sw2) != (0x90, 0x00) or not status.get("max_num_keys"):
                pytest.skip("no satodime slots to render")

            session = UISession(script=(
                select(0)   # ToolsSatodimeView: "Key Slots"
                + [Back()]   # open the slot list, then leave it
            ))
            self.run_sequence(
                [
                    FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                    FlowStep(tools_views.ToolsMenuView,
                             button_data_selection=tools_views.ToolsMenuView.SMARTCARD),
                    FlowStep(smartcard_views.ToolsSmartcardMenuView,
                             button_data_selection=smartcard_views.ToolsSmartcardMenuView.SATODIME),
                    FlowStep(smartcard_views.ToolsSatodimeView, real_screens=True),
                    FlowStep(smartcard_views.ToolsSatodimeSlotsView, real_screens=True),
                    FlowStep(smartcard_views.ToolsSatodimeView),
                ],
                ui_session=session,
            )

    def test_empty_slot_labelled_uninitialized_not_a_parser_error(self, monkeypatch):
        """
        A fresh card's slots hold no key, so ``satodime_get_pubkey`` returns an empty
        body and pysatochip's parser raises. The slot-list build must skip the pubkey
        lookup for empty slots and label them Uninitialized -- not paint an exception.
        """
        try:
            ctx = simulated_satodime(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            claim(connector)

            view = smartcard_views.ToolsSatodimeSlotsView()
            recorder = ScreenRecorder(RET_CODE__BACK_BUTTON)
            view.run_screen = recorder
            view.run()

            list_cls, list_kwargs = recorder.calls[0]
            assert list_cls == "ButtonListScreen"
            labels = [opt.button_label for opt in list_kwargs["button_data"]]
            for label in labels[:3]:
                assert "Uninitialized" in label, label
            assert not any("error" in l.lower() for l in labels), labels
            assert not any("expected at least" in l for l in labels), labels

    def test_sealed_slot_within_a_real_slot_list(self, monkeypatch):
        """
        After sealing, the slot row carries the sealed coin and the address, and
        selecting the slot routes into its action menu where "View Address" renders
        that address as a QR code -- not an exception.
        """
        try:
            ctx = simulated_satodime(monkeypatch)
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx as connector:
            claim(connector)
            connector.satodime_set_unlock_secret()
            connector.satodime_set_unlock_counter()
            connector.satodime_get_status()
            (_, sw1, sw2, _, _) = connector.satodime_seal_key(0, bytes(range(32)))
            assert (sw1, sw2) == (0x90, 0x00)

            list_view = smartcard_views.ToolsSatodimeSlotsView()
            recorder = ScreenRecorder(0)  # pick "Slot 0" -> its action menu
            list_view.run_screen = recorder
            dest = list_view.run()

            labels = [opt.button_label for opt in recorder.calls[0][1]["button_data"]]
            assert dest.View_cls is smartcard_views.ToolsSatodimeSlotMenuView
            assert dest.view_args == {"slot": 0}
            assert "Sealed - BTC" in labels[0], labels[0]
            address = labels[0].rsplit(" - ", 1)[-1]
            assert BECH32_ADDRESS.match(address), address

            # "View Address" on that slot renders the address as a QR code.
            view = smartcard_views.ToolsSatodimeViewAddressView(0)
            qr_recorder = ScreenRecorder(RET_CODE__BACK_BUTTON)  # dismiss the QR
            view.run_screen = qr_recorder
            view.run()

            qr_call = next(c for c in qr_recorder.calls if c[0] == "QRDisplayScreen")
            address = qr_call[1]["qr_encoder"].data
            assert BECH32_ADDRESS.match(address), address


class TestSatodimeThroughRealInitSatochip(SatodimeSimulatedFlowTest):
    """
    The same views, but reaching the applet through the real ``init_satochip``.

    ``simulated_satodime`` replaces that function, so nothing above this class can see
    how SeedSigner reacts to a card whose setup has not been done. These tests patch
    only PC/SC, which is the level a real reader sits at.
    """

    def test_read_only_view_needs_no_claim_and_no_pin(self):
        """
        Satodime has no PIN. The shared 'card needs setup' branch used to prompt for one
        anyway, because it keys off ``setup_done`` alone -- so the user got a PIN keyboard
        on a card that has no PIN.

        Reads also must not force a claim: the slot list is reachable on an unclaimed
        card, so browsing it should just work.
        """
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            view = smartcard_views.ToolsSatodimeSlotsView()
            recorder = ScreenRecorder(RET_CODE__BACK_BUTTON)
            view.run_screen = recorder
            view.run()

            # The slot list is reachable, and nothing ever prompts for a PIN.
            assert recorder.titles[0] == "Satodime"
            for title in recorder.titles:
                assert "PIN" not in (title or ""), f"Satodime must never ask for a PIN: {title}"

    def test_genuine_check_on_satodime_neither_prompts_nor_clobbers_the_pin_cache(self):
        """
        Genuine Check calls init_satochip with the default require_pin=True. Satodime has
        no PIN, so that path must not prompt -- and it must still bind card_pin for the
        'cache the pin' step (an unbound read there raised UnboundLocalError on-device).
        A cached Satochip PIN from another card type must survive the Satodime connect.
        """
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            self.controller.Satochip_PIN = [0x31, 0x32, 0x33]

            view = smartcard_views.ToolsSmartcardGenuineCheckView(card_filter=["satodime"])
            recorder = ScreenRecorder(RET_CODE__BACK_BUTTON, RET_CODE__BACK_BUTTON)
            view.run_screen = recorder
            view.run()

            for title in recorder.titles:
                assert "PIN" not in (title or ""), f"Satodime must never ask for a PIN: {title}"
            assert self.controller.Satochip_PIN == [0x31, 0x32, 0x33]

    def test_state_change_on_an_unclaimed_card_routes_to_the_claim_view(self):
        """Seal needs setup, so it must send the user to claim rather than fail 0x9C04."""
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            view = smartcard_views.ToolsSatodimeSealSlotView(0)
            recorder = ScreenRecorder()  # no screen should be shown at all
            view.run_screen = recorder
            dest = view.run()

            assert dest.View_cls is smartcard_views.ToolsSatodimeClaimView
            assert recorder.titles == []

    def test_claim_over_contact_skips_the_backup_flow(self):
        """
        A contact reader ignores the unlock code entirely, so there is nothing to back
        up and the user should not be walked through a QR ceremony for nothing.
        """
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            assert not seedkeeper_utils.satodime_connection_is_contactless(
                _fresh_connector()
            ), "the jcardsim shim should look like a contact reader"

            view = smartcard_views.ToolsSatodimeClaimView()
            recorder = ScreenRecorder(0, 0)  # confirm claim, then acknowledge success
            view.run_screen = recorder
            view.run()

            assert recorder.titles == ["Card Unclaimed", "Card Claimed"]

            cached = self.controller.Satodime_unlock_secrets or {}
            (secret,) = list(cached.values())
            assert len(secret) == 20
            assert any(secret), "the card must hand back a real secret, not zeros"

    def test_claim_over_contactless_routes_to_the_backup_flow(self, monkeypatch):
        """Over NFC the secret is the only thing standing between the user and a
        stranded card, so claiming must hand straight off to the backup ceremony."""
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        monkeypatch.setattr(
            seedkeeper_utils, "satodime_connection_is_contactless", lambda connector: True
        )

        with ctx:
            view = smartcard_views.ToolsSatodimeClaimView()
            recorder = ScreenRecorder(0)
            view.run_screen = recorder
            dest = view.run()

            assert dest.View_cls is smartcard_views.ToolsSatodimeBackupUnlockView
            assert dest.view_args["card_id"]

    def test_declining_the_claim_leaves_the_card_untouched(self):
        """Choosing Cancel must abort and leave ``setup_done`` False."""
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            view = smartcard_views.ToolsSatodimeClaimView()
            recorder = ScreenRecorder(1)  # "Cancel"
            view.run_screen = recorder
            view.run()

            assert recorder.titles == ["Card Unclaimed"]
            (_, _, _, status) = _fresh_connector().card_get_status()
            assert status["setup_done"] is False, "cancelling must not claim the card"

    def test_seal_after_claiming_shows_an_address(self):
        """
        The whole reported failure, in one test: claim -> Seal Slot -> success.

        This is what would have caught 0x9C04 (no setup ever ran) *and* the bad embit
        constructor, because it drives the views and asserts on the address the success
        screen actually renders.

        Sealing must pass through the loud no-backup warning first.
        """
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            claim_view = smartcard_views.ToolsSatodimeClaimView()
            claim_view.run_screen = ScreenRecorder(0, 0)
            claim_view.run()

            # What ToolsSatodimeSlotsView would have cached for a fresh card.
            _populate_cache([(smartcard_views.SATODIME_SLOT_UNINITIALIZED, None, None)])

            view = smartcard_views.ToolsSatodimeSealSlotView(0)
            # coin picker (BTC is first) -> no-backup warning -> success
            recorder = ScreenRecorder(0, 0, 0)
            view.run_screen = recorder
            view.run()

            assert "Seal Failed" not in recorder.titles, recorder.calls
            assert recorder.titles == ["Seal As", "No Backup", "Success"]
            # The no-backup warning is the loud point of this screen.
            assert "no backup" in recorder.body_for("No Backup").lower(), recorder.calls
            headline, address = recorder.body_for("Success").split("\n")
            assert headline == "Slot 0 sealed BTC"
            assert BECH32_ADDRESS.match(address), address

    def test_reseal_of_a_sealed_slot_is_refused_with_the_warning(self):
        """
        The applet only ever seals an Uninitialized slot (it answers 0x9C52 otherwise),
        and re-sealing a slot that already holds -- or held -- a key would orphan the
        funds and there is no backup. The slot-centric SealSlotView must refuse with the
        same loud no-backup warning.
        """
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            _seal_slot_zero()

            view = smartcard_views.ToolsSatodimeSealSlotView(0)
            recorder = ScreenRecorder(0)  # ack the Cannot Re-Seal refusal
            view.run_screen = recorder
            view.run()

            assert recorder.titles == ["Cannot Re-Seal"]
            assert "no backup" in recorder.calls[0][1]["text"].lower()

    def test_slot_menu_shows_state_appropriate_actions(self):
        """The per-slot action menu only offers actions valid for the slot's state:
        [Seal] when uninitialized, [View Address, Unseal, Sign] when sealed, and
        [View Address, View Private Key, Sign, Load Key, Reset] when unsealed (BTC)."""
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            # Uninitialized: only Seal. (Cache as ToolsSatodimeSlotsView would build it.)
            _populate_cache([(smartcard_views.SATODIME_SLOT_UNINITIALIZED, None, None)])
            menu = smartcard_views.ToolsSatodimeSlotMenuView(0)
            recorder = ScreenRecorder(RET_CODE__BACK_BUTTON)
            menu.run_screen = recorder
            menu.run()
            assert [o.button_label for o in recorder.calls[0][1]["button_data"]] == [
                "Seal Slot (Initialise New Key)",
            ]

            # Sealed BTC: View Address, Unseal, Sign Transaction.
            _seal_slot_zero()
            menu = smartcard_views.ToolsSatodimeSlotMenuView(0)
            recorder = ScreenRecorder(RET_CODE__BACK_BUTTON)
            menu.run_screen = recorder
            menu.run()
            assert [o.button_label for o in recorder.calls[0][1]["button_data"]] == [
                "View Address (QR)", "Unseal Slot (View Private Key)", "Sign Transaction",
            ]

            # Unsealed BTC: View Address, View Private Key, Sign Transaction, Load Key, Reset Slot.
            _unseal_slot_zero()
            menu = smartcard_views.ToolsSatodimeSlotMenuView(0)
            recorder = ScreenRecorder(RET_CODE__BACK_BUTTON)
            menu.run_screen = recorder
            menu.run()
            assert [o.button_label for o in recorder.calls[0][1]["button_data"]] == [
                "View Address (QR)", "View Private Key (QR)", "Sign Transaction",
                "Load Key to SeedSigner", "Reset Slot",
            ]

    def test_unseal_warning_blocks_and_confirms(self):
        """
        Unsealing permanently exposes a slot's private key and the applet then refuses
        to seal it again. The flow must warn before the unseal APDU, and backing out of
        that warning must leave the slot sealed.
        """
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            _seal_slot_zero()

            # Backing out of the warning leaves the slot sealed.
            view = smartcard_views.ToolsSatodimeUnsealSlotView(0)
            recorder = ScreenRecorder(RET_CODE__BACK_BUTTON)  # back out of the warning
            view.run_screen = recorder
            view.run()

            (_, _, _, slot_status) = _fresh_connector().satodime_get_keyslot_status(0)
            assert slot_status["key_status_txt"] == "Sealed"

            # Confirming the warning unseals; the slot is then Unsealed.
            view = smartcard_views.ToolsSatodimeUnsealSlotView(0)
            recorder = ScreenRecorder(0, 0)  # confirm warning, ack Unsealed
            view.run_screen = recorder
            view.run()

            assert recorder.titles == ["Unseal Slot", "Unsealed"]
            (_, _, _, slot_status) = _fresh_connector().satodime_get_keyslot_status(0)
            assert slot_status["key_status_txt"] == "Unsealed"

    def test_view_private_key_shows_wif_qr(self):
        """An unsealed BTC slot's private key is shown as a QR (WIF)."""
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            _seal_slot_zero()
            _unseal_slot_zero()

            view = smartcard_views.ToolsSatodimeViewPrivateKeyView(0)
            recorder = ScreenRecorder(RET_CODE__BACK_BUTTON)  # dismiss the QR
            view.run_screen = recorder
            view.run()

            qr_call = next(c for c in recorder.calls if c[0] == "QRDisplayScreen")
            # A BTC WIF starts with K or L (mainnet) or c (testnet); never an exception.
            assert qr_call[1]["qr_encoder"].data[0] in "KLc"

    def test_load_key_loads_an_unsealed_bitcoin_slot(self):
        """
        Load Key to SeedSigner reads an already-unsealed BTC slot's WIF and stages it as
        psbt_seed, landing back on the slot's action menu.
        """
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            _seal_slot_zero()
            _unseal_slot_zero()

            view = smartcard_views.ToolsSatodimeLoadKeyView(0)
            recorder = ScreenRecorder(0)  # ack "Key Loaded"
            view.run_screen = recorder
            dest = view.run()

            from seedsigner.models.wif import WIFKey

            assert recorder.titles == ["Key Loaded"]
            assert dest.View_cls is smartcard_views.ToolsSatodimeSlotMenuView
            assert isinstance(self.controller.psbt_seed, WIFKey)
            _, address = recorder.body_for("Key Loaded").split("\n")
            assert BECH32_ADDRESS.match(address), address

    def test_reset_slot_clears_an_unsealed_slot(self):
        """Resetting an unsealed slot erases its key back to Uninitialized, after the
        loud no-backup warning."""
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            _seal_slot_zero()
            _unseal_slot_zero()

            view = smartcard_views.ToolsSatodimeResetSlotView(0)
            recorder = ScreenRecorder(0, 0)  # confirm Reset warning, ack Reset
            view.run_screen = recorder
            view.run()

            assert recorder.titles == ["Reset Slot", "Reset"]
            (_, _, _, slot_status) = _fresh_connector().satodime_get_keyslot_status(0)
            assert slot_status["key_status_txt"] == "Uninitialized"

    def test_seal_fails_closed_when_the_rng_health_monitor_has_failed(self, monkeypatch):
        """
        Sealing mints a new key from system-RNG entropy, so it must refuse -- not
        warn-and-continue -- when the background RNG health monitor has flagged the
        source, exactly like the password generator and image-entropy seed flows.
        """
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        monkeypatch.setattr(
            type(self.controller), "hardware_rng_is_healthy", property(lambda self: False)
        )
        monkeypatch.setattr(
            type(self.controller), "hardware_rng_failure_reason", property(lambda self: "test RNG failure")
        )

        with ctx:
            claim_view = smartcard_views.ToolsSatodimeClaimView()
            claim_view.run_screen = ScreenRecorder(0, 0)
            claim_view.run()

            # What ToolsSatodimeSlotsView would have cached for a fresh card.
            _populate_cache([(smartcard_views.SATODIME_SLOT_UNINITIALIZED, None, None)])

            view = smartcard_views.ToolsSatodimeSealSlotView(0)
            recorder = ScreenRecorder(0)  # ack the RNG error gate; nothing else should render
            view.run_screen = recorder
            view.run()

            assert recorder.titles == ["System RNG Error"]
            assert "Sealing" not in " ".join(recorder.titles)

    def test_seal_fails_closed_when_the_entropy_draw_is_low_quality(self, monkeypatch):
        """
        Belt-and-suspenders over the background monitor (which samples once a minute):
        the actual bytes folded into the card's key are sanity-checked, and a
        low-entropy draw aborts the seal.
        """
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            claim_view = smartcard_views.ToolsSatodimeClaimView()
            claim_view.run_screen = ScreenRecorder(0, 0)
            claim_view.run()

            # What ToolsSatodimeSlotsView would have cached for a fresh card.
            _populate_cache([(smartcard_views.SATODIME_SLOT_UNINITIALIZED, None, None)])

            # Stop the background monitor so its own reads don't consume the patch,
            # then make the seal's os.urandom(32) always return a constant block.
            if self.controller.rng_monitor_thread:
                self.controller.rng_monitor_thread.stop()
            monkeypatch.setattr(smartcard_views.os, "urandom", lambda n: b"\x00" * n)

            view = smartcard_views.ToolsSatodimeSealSlotView(0)
            # coin picker (BTC) -> no-backup warning -> RNG error gate
            recorder = ScreenRecorder(0, 0, 0)
            view.run_screen = recorder
            view.run()

            assert recorder.titles == ["Seal As", "No Backup", "System RNG Error"]

    def test_contactless_without_the_secret_routes_to_restore(self, monkeypatch):
        """
        Over NFC the applet checks HMAC(unlock_secret, ...), so a claimed card whose
        secret this session does not hold cannot seal. The user must be sent to restore
        it rather than shown a raw 0x9C51.
        """
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        with ctx:
            claim_view = smartcard_views.ToolsSatodimeClaimView()
            claim_view.run_screen = ScreenRecorder(0, 0)
            claim_view.run()

            # Simulate a later session: card still claimed, secret no longer in RAM.
            self.controller.Satodime_unlock_secrets = None
            monkeypatch.setattr(
                seedkeeper_utils, "satodime_connection_is_contactless", lambda connector: True
            )

            view = smartcard_views.ToolsSatodimeSealSlotView(0)
            recorder = ScreenRecorder(0)  # accept "Restore Key"
            view.run_screen = recorder
            dest = view.run()

            assert recorder.titles == ["Key Required"]
            assert dest.View_cls is smartcard_views.ToolsSatodimeRestoreUnlockView


class TestUnlockSecretPayload:
    """The backup payload is what a user's phone photo has to survive."""

    def test_round_trips(self):
        secret = list(range(20))
        payload = seedkeeper_utils.format_satodime_unlock_payload("deadbeef", secret)
        assert payload.startswith("satodime-unlock:")
        assert seedkeeper_utils.parse_satodime_unlock_payload(payload) == ("deadbeef", secret)

    def test_survives_surrounding_whitespace(self):
        payload = seedkeeper_utils.format_satodime_unlock_payload("abc", list(range(20)))
        assert seedkeeper_utils.parse_satodime_unlock_payload(f"  {payload}\n") is not None

    @pytest.mark.parametrize("text", [
        "",
        "not a backup",
        "satodime-unlock:abc",                    # no secret
        "satodime-unlock:abc:zz",                 # not hex
        "satodime-unlock:abc:" + "00" * 19,       # wrong length
        "satodime-unlock:abc:" + "00" * 21,
    ])
    def test_rejects_junk(self, text):
        assert seedkeeper_utils.parse_satodime_unlock_payload(text) is None


class TestContactlessDetection:
    """Which medium we are on decides whether the secret matters at all."""

    @pytest.mark.parametrize("reader,expected", [
        ("Identive SCR33xx v2.0 USB SC Reader 0", False),
        ("jcardsim simulator", False),
        ("SEC1210 Contact Reader", False),
        ("ACS ACR122U PICC Interface", True),
        ("PN532 via GPIO", True),
        ("Some NFC Reader", True),
    ])
    def test_reader_names(self, reader, expected):
        connector = _connector_reporting_reader(reader)
        assert seedkeeper_utils.satodime_connection_is_contactless(connector) is expected

    def test_unknown_reader_fails_safe_to_contactless(self):
        """Better to offer a backup that wasn't needed than to skip one that was."""
        class Exploding:
            @property
            def cardservice(self):
                raise RuntimeError("no reader")

        assert seedkeeper_utils.satodime_connection_is_contactless(Exploding()) is True
        assert seedkeeper_utils.satodime_connection_is_contactless(
            _connector_reporting_reader("")
        ) is True


class TestBackupAndRestoreViews(SatodimeSimulatedFlowTest):
    """The QR ceremony and its restore path, driven without a card."""

    CARD_ID = "0123456789abcdef"
    SECRET = list(range(20))

    def _seed_cache(self):
        seedkeeper_utils.cache_satodime_unlock_secret(self.controller, self.CARD_ID, self.SECRET)
        return seedkeeper_utils.format_satodime_unlock_payload(self.CARD_ID, self.SECRET)

    def test_scanning_the_code_back_verifies_the_backup(self, monkeypatch):
        payload = self._seed_cache()
        monkeypatch.setattr(smartcard_views, "_satodime_scan_text", lambda view: payload)

        view = smartcard_views.ToolsSatodimeBackupUnlockView(card_id=self.CARD_ID)
        # dire warning, theft caveat, QR, menu -> "Scan It Back", success
        recorder = ScreenRecorder(0, 0, None, 0, 0)
        view.run_screen = recorder
        view.run()

        assert recorder.titles == [
            "Ownership Key", "Not Theft Proof", None, "Verify Backup", "Backup Verified",
        ]

    def test_a_wrong_scan_does_not_count_as_verified(self, monkeypatch):
        self._seed_cache()
        monkeypatch.setattr(
            smartcard_views, "_satodime_scan_text", lambda view: "satodime-unlock:other:" + "11" * 20
        )

        view = smartcard_views.ToolsSatodimeBackupUnlockView(card_id=self.CARD_ID)
        # ... menu -> "Scan It Back", "No Match", QR again, menu -> "Skip", confirm skip
        recorder = ScreenRecorder(0, 0, None, 0, 0, None, 3, 0)
        view.run_screen = recorder
        view.run()

        assert "No Match" in recorder.titles
        assert "Backup Verified" not in recorder.titles

    def test_the_user_is_told_the_code_is_not_theft_protection(self):
        """A contact reader can unseal the card without this code; users must know."""
        self._seed_cache()
        view = smartcard_views.ToolsSatodimeBackupUnlockView(card_id=self.CARD_ID)
        recorder = ScreenRecorder(0, 0, None, 3, 0)  # straight to Skip
        view.run_screen = recorder
        view.run()

        caveat = recorder.body_for("Not Theft Proof")
        assert "contact reader" in caveat.lower()

    def test_backup_refuses_when_nothing_is_cached(self):
        view = smartcard_views.ToolsSatodimeBackupUnlockView(card_id=self.CARD_ID)
        recorder = ScreenRecorder(0)
        view.run_screen = recorder
        view.run()

        assert recorder.titles == ["No Ownership Key"]

    def test_restore_rejects_another_card_s_backup(self, monkeypatch):
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        # Simulate NFC — the restore flow is only available over contactless.
        monkeypatch.setattr(seedkeeper_utils, "satodime_connection_is_contactless", lambda c: True)
        other = seedkeeper_utils.format_satodime_unlock_payload("ffffffffffffffff", self.SECRET)
        monkeypatch.setattr(smartcard_views, "_satodime_scan_text", lambda view: other)

        with ctx:
            view = smartcard_views.ToolsSatodimeRestoreUnlockView()
            recorder = ScreenRecorder(0, 0)  # choose "Scan Backup QR", ack the warning
            view.run_screen = recorder
            view.run()

            assert recorder.titles == ["Ownership Key", "Wrong Card"]
            assert not (self.controller.Satodime_unlock_secrets or {})

    def test_restore_loads_this_card_s_backup(self, monkeypatch):
        try:
            ctx = simulated_satodime_raw()
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        # Simulate NFC — the restore flow is only available over contactless.
        monkeypatch.setattr(seedkeeper_utils, "satodime_connection_is_contactless", lambda c: True)
        with ctx:
            card_id = seedkeeper_utils.satodime_card_id(_fresh_connector())
            payload = seedkeeper_utils.format_satodime_unlock_payload(card_id, self.SECRET)
            monkeypatch.setattr(smartcard_views, "_satodime_scan_text", lambda view: payload)

            view = smartcard_views.ToolsSatodimeRestoreUnlockView()
            recorder = ScreenRecorder(0, 0)
            view.run_screen = recorder
            view.run()

            assert recorder.titles == ["Ownership Key", "Ownership Key Set"]
            assert self.controller.Satodime_unlock_secrets[card_id] == self.SECRET


class TestMatchesTheOfficialSatodimeApp:
    """
    Golden vector: a slot sealed by the official Satodime Android app.

    The pubkey below was read off a real Satodime whose first slot the Android app
    sealed, and the address is the one that app displayed for it. SeedSigner originally
    rendered P2PKH here (1NBbECsXng3GVCuU2PdWAAZAxyB2GfWi6B) -- spendable, but a
    different address for the same key, so anything deposited to it showed a zero
    balance in the official app.

    Javacryptotools' ``BaseCoin.pubToAddress()`` returns a segwit address whenever the
    coin supports it and ``Bitcoin`` sets ``segwit_supported = true``, so bech32 P2WPKH
    is the format to match.
    """

    SEALED_PUBKEY = "03de296020fbf9a119db36a513a572ea4936a5729f5a3deb21a9b8c0928c9db8f0"
    APP_ADDRESS = "bc1qapd47as9kw384u5pkd4jvvj5pn8ds3s876k048"

    def test_address_matches_what_the_android_app_shows(self):
        pub_comp = list(bytes.fromhex(self.SEALED_PUBKEY))
        address = smartcard_views._satodime_address(pub_comp, BTC, is_testnet=False)
        assert address == self.APP_ADDRESS

    def test_testnet_uses_the_same_key_with_the_testnet_hrp(self):
        """
        The keyslot records only the coin: Javacryptotools' MAP_SLIP44_BY_SYMBOL has a
        single BTC entry and the apps carry testnet as a separate display flag. So the
        network comes from SeedSigner's own setting, exactly as it comes from the app's.
        """
        from embit import networks

        pub_comp = list(bytes.fromhex(self.SEALED_PUBKEY))
        from embit import script

        address = smartcard_views._satodime_address(pub_comp, BTC, is_testnet=True)
        assert address.startswith("tb1q")
        # bech32 checksums cover the hrp, so the strings differ past the prefix; what
        # must match is the witness program they encode.
        assert (
            script.address_to_scriptpubkey(address).data
            == script.address_to_scriptpubkey(self.APP_ADDRESS).data
        )

    def test_slot_metadata_matches_the_apps_seal(self):
        """
        NFCCardService.seal() follows every seal with SET_KEYSLOT_STATUS carrying the
        coin's slip44 and a 34-byte contract/tokenid block whose second byte is 32.
        Without it the slot reads back as slip44 0x00000000 and the official apps show
        an unknown asset.
        """
        assert smartcard_views.SATODIME_SLIP44_BTC_BYTES == [0x80, 0x00, 0x00, 0x00]
        assert len(smartcard_views.SATODIME_EMPTY_CONTRACT) == 34
        assert smartcard_views.SATODIME_EMPTY_CONTRACT[1] == 32
        assert set(smartcard_views.SATODIME_EMPTY_CONTRACT) == {0, 32}


class TestSlotCoinHandling:
    """A slot sealed for another chain must not be shown a Bitcoin address."""

    def _slot(self, slip44_hex, txt="Sealed"):
        return {
            "key_status_txt": txt,
            "key_slip44": list(bytes.fromhex(slip44_hex)),
            "key_slip44_txt": "ETH" if slip44_hex == "8000003c" else "BTC",
        }

    def test_btc_slot_is_bitcoin(self):
        assert smartcard_views._satodime_slot_slip44(self._slot("80000000")) == \
            smartcard_views.SATODIME_SLIP44_BTC

    def test_untagged_slot_is_treated_as_bitcoin(self):
        """SeedSigner sealed slots before it wrote this metadata; they read back as 0."""
        assert smartcard_views._satodime_slot_slip44(self._slot("00000000")) == \
            smartcard_views.SATODIME_SLIP44_BTC
        assert smartcard_views._satodime_slot_slip44({"key_status_txt": "Sealed"}) == \
            smartcard_views.SATODIME_SLIP44_BTC

    def test_eth_slot_is_not_bitcoin(self):
        assert smartcard_views._satodime_slot_slip44(self._slot("8000003c")) != \
            smartcard_views.SATODIME_SLIP44_BTC
