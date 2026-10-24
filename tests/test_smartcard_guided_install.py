"""Guided applet install and PIN retry behaviour of the smartcard flows.

Covers the feedback that setup/save flows dead-ended: a card without the applet
now offers to install the bundled one, and a rejected or mistyped PIN re-prompts
instead of leaving the flow.
"""
import hashlib
import shutil
import sys
from types import SimpleNamespace

import pytest

from seedsigner.helpers import seedkeeper_utils
from seedsigner.views import smartcard_views


class DummyLoadingScreen:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        pass

    def stop(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def _no_loading_screen(monkeypatch):
    monkeypatch.setattr(seedkeeper_utils, "LoadingScreenThread", DummyLoadingScreen)
    monkeypatch.setattr(seedkeeper_utils, "restart_pn532", lambda *a, **k: None)


def make_view(responses=None, javacard_keys=None):
    """A stand-in View recording every screen it is asked to show."""
    screens = []
    replies = iter(responses or [])

    def run_screen(screen_cls, **kwargs):
        screens.append(SimpleNamespace(cls=screen_cls, **kwargs))
        return next(replies, 0)

    controller = SimpleNamespace(
        Satochip_Connector=None,
        smartcard_backend_preference=None,
        Satochip_PIN=None,
        Satochip_Last_UID_SHA1=None,
        javacard_keys=javacard_keys,
    )
    view = SimpleNamespace(
        controller=controller,
        settings=SimpleNamespace(get_value=lambda *a, **k: []),
        run_screen=run_screen,
        screens=screens,
    )
    return view


def titles(view):
    return [s.title for s in view.screens]


# ---------------------------------------------------------------------------
# Bundled cap verification
# ---------------------------------------------------------------------------
class TestVerifyBundledCap:
    @pytest.mark.parametrize("applet", sorted(seedkeeper_utils.BUNDLED_APPLET_CAPS))
    def test_shipped_caps_verify(self, applet):
        cap = seedkeeper_utils.get_internal_cap_dir() / seedkeeper_utils.BUNDLED_APPLET_CAPS[applet]
        assert seedkeeper_utils.verify_bundled_cap(cap)

    def test_tampered_cap_is_rejected(self, tmp_path):
        name = seedkeeper_utils.BUNDLED_APPLET_CAPS["seedkeeper"]
        src_dir = seedkeeper_utils.get_internal_cap_dir()
        shutil.copy(src_dir / seedkeeper_utils.CAP_CHECKSUM_FILENAME, tmp_path)
        (tmp_path / name).write_bytes((src_dir / name).read_bytes() + b"\x00")
        assert not seedkeeper_utils.verify_bundled_cap(tmp_path / name)

    def test_cap_without_checksum_entry_is_rejected(self, tmp_path):
        cap = tmp_path / "Other.cap"
        cap.write_bytes(b"cap")
        (tmp_path / seedkeeper_utils.CAP_CHECKSUM_FILENAME).write_text(
            f"{hashlib.sha256(b'cap').hexdigest()}  Different.cap\n"
        )
        assert not seedkeeper_utils.verify_bundled_cap(cap)

    def test_missing_checksum_file_is_rejected(self, tmp_path):
        cap = tmp_path / "SeedKeeper-0.2-official.cap"
        cap.write_bytes(b"cap")
        assert not seedkeeper_utils.verify_bundled_cap(cap)


# ---------------------------------------------------------------------------
# Applet probe
# ---------------------------------------------------------------------------
class FakeConnection:
    def __init__(self, present_aids, has_card=True):
        self.present_aids = present_aids
        self.has_card = has_card
        self.sent = []

    def connect(self):
        if not self.has_card:
            raise RuntimeError("no card")

    def transmit(self, apdu):
        self.sent.append(apdu)
        aid = bytes(apdu[5:]).hex().upper()
        return ([], 0x90, 0x00) if aid in self.present_aids else ([], 0x6A, 0x82)

    def disconnect(self):
        pass


class FakeReader:
    def __init__(self, name, connection):
        self.name = name
        self.connection = connection

    def __str__(self):
        return self.name

    def createConnection(self):
        return self.connection


def patch_readers(monkeypatch, reader_list):
    import smartcard.System
    monkeypatch.setattr(smartcard.System, "readers", lambda: reader_list)


class TestProbeCardApplets:
    def test_reports_each_applet(self, monkeypatch):
        conn = FakeConnection({seedkeeper_utils.APPLET_AIDS["satochip"]})
        patch_readers(monkeypatch, [FakeReader("Reader 0", conn)])

        reader, found = seedkeeper_utils.probe_card_applets()

        assert reader == "Reader 0"
        assert found == {"satochip": True, "seedkeeper": False, "satodime": False}
        # SELECT only: nothing that needs card-manager keys is ever sent.
        assert all(apdu[:4] == [0x00, 0xA4, 0x04, 0x00] for apdu in conn.sent)

    def test_skips_windows_hello_and_empty_readers(self, monkeypatch):
        hello = FakeConnection({seedkeeper_utils.APPLET_AIDS["seedkeeper"]})
        patch_readers(monkeypatch, [
            FakeReader("Windows Hello for Business 1", hello),
            FakeReader("Empty Reader", FakeConnection(set(), has_card=False)),
            FakeReader("Card Reader", FakeConnection(set())),
        ])

        reader, found = seedkeeper_utils.probe_card_applets()

        assert reader == "Card Reader"
        assert not any(found.values())
        assert hello.sent == []

    def test_no_card_returns_none(self, monkeypatch):
        patch_readers(monkeypatch, [FakeReader("Empty", FakeConnection(set(), has_card=False))])
        assert seedkeeper_utils.probe_card_applets() is None


# ---------------------------------------------------------------------------
# Offer to install
# ---------------------------------------------------------------------------
@pytest.fixture
def install_calls(monkeypatch):
    calls = []

    def fake_install(view, cap_path, **kwargs):
        calls.append(SimpleNamespace(cap_path=cap_path, **kwargs))
        return True

    monkeypatch.setattr(seedkeeper_utils, "install_applet_cap", fake_install)
    monkeypatch.setitem(sys.modules, "pygp", SimpleNamespace(close=lambda: None))
    return calls


def patch_probe(monkeypatch, result):
    monkeypatch.setattr(seedkeeper_utils, "probe_card_applets", lambda names=None: result)


BLANK_CARD = ("Reader 0", {"satochip": False, "seedkeeper": False, "satodime": False})


class TestOfferMissingAppletInstall:
    def test_not_offered_when_flow_accepts_several_applets(self, monkeypatch, install_calls):
        patch_probe(monkeypatch, BLANK_CARD)
        view = make_view()
        outcome = seedkeeper_utils.offer_missing_applet_install(view, ["satochip", "seedkeeper"])
        assert outcome == seedkeeper_utils.APPLET_OFFER__NOT_APPLICABLE
        assert view.screens == [] and install_calls == []

    def test_not_offered_without_card(self, monkeypatch, install_calls):
        patch_probe(monkeypatch, None)
        view = make_view()
        outcome = seedkeeper_utils.offer_missing_applet_install(view, ["seedkeeper"])
        assert outcome == seedkeeper_utils.APPLET_OFFER__NOT_APPLICABLE
        assert install_calls == []

    def test_not_offered_when_applet_is_present(self, monkeypatch, install_calls):
        patch_probe(monkeypatch, ("Reader 0", {"satochip": False, "seedkeeper": True, "satodime": False}))
        view = make_view()
        outcome = seedkeeper_utils.offer_missing_applet_install(view, ["seedkeeper"])
        assert outcome == seedkeeper_utils.APPLET_OFFER__NOT_APPLICABLE
        assert install_calls == []

    def test_other_applet_names_the_card_instead_of_installing(self, monkeypatch, install_calls):
        patch_probe(monkeypatch, ("Reader 0", {"satochip": True, "seedkeeper": False, "satodime": False}))
        view = make_view()
        outcome = seedkeeper_utils.offer_missing_applet_install(view, ["seedkeeper"])
        assert outcome == seedkeeper_utils.APPLET_OFFER__HANDLED
        assert titles(view) == ["Wrong Card"]
        assert "Satochip" in view.screens[0].text
        assert install_calls == []

    def test_cancel_does_not_install(self, monkeypatch, install_calls):
        patch_probe(monkeypatch, BLANK_CARD)
        view = make_view(responses=[1])  # "Cancel"
        outcome = seedkeeper_utils.offer_missing_applet_install(view, ["seedkeeper"])
        assert outcome == seedkeeper_utils.APPLET_OFFER__HANDLED
        assert titles(view) == ["Applet Not Found"]
        assert install_calls == []

    def test_accept_installs_verified_bundled_seedkeeper(self, monkeypatch, install_calls):
        patch_probe(monkeypatch, BLANK_CARD)
        view = make_view(responses=[0])  # "Install SeedKeeper"
        outcome = seedkeeper_utils.offer_missing_applet_install(view, ["seedkeeper"])

        assert outcome == seedkeeper_utils.APPLET_OFFER__INSTALLED
        assert len(install_calls) == 1
        call = install_calls[0]
        assert call.cap_path.name == "SeedKeeper-0.2-official.cap"
        assert call.storage_param == seedkeeper_utils.SEEDKEEPER_DEFAULT_STORAGE
        assert call.reader_name == "Reader 0"
        assert call.require_auth is True
        assert titles(view) == ["Applet Not Found", "Success"]

    def test_satochip_install_passes_no_storage(self, monkeypatch, install_calls):
        patch_probe(monkeypatch, BLANK_CARD)
        view = make_view(responses=[0])
        assert seedkeeper_utils.offer_missing_applet_install(view, "satochip") == seedkeeper_utils.APPLET_OFFER__INSTALLED
        assert install_calls[0].cap_path.name == "SatoChip-0.12-official.cap"
        assert install_calls[0].storage_param is None

    def test_checksum_failure_blocks_install(self, monkeypatch, install_calls):
        patch_probe(monkeypatch, BLANK_CARD)
        monkeypatch.setattr(seedkeeper_utils, "verify_bundled_cap", lambda path: False)
        view = make_view(responses=[0])
        outcome = seedkeeper_utils.offer_missing_applet_install(view, ["seedkeeper"])
        assert outcome == seedkeeper_utils.APPLET_OFFER__HANDLED
        assert titles(view) == ["Applet Not Found", "Applet Unavailable"]
        assert install_calls == []

    def test_failed_install_is_handled(self, monkeypatch):
        patch_probe(monkeypatch, BLANK_CARD)
        monkeypatch.setattr(seedkeeper_utils, "install_applet_cap", lambda *a, **k: False)
        monkeypatch.setitem(sys.modules, "pygp", SimpleNamespace(close=lambda: None))
        view = make_view(responses=[0])
        assert seedkeeper_utils.offer_missing_applet_install(view, ["seedkeeper"]) == seedkeeper_utils.APPLET_OFFER__HANDLED


# ---------------------------------------------------------------------------
# install_applet_cap
# ---------------------------------------------------------------------------
class FakePyGP:
    SECURITY_LEVEL_C_MAC = 1

    def __init__(self, auth_error=None):
        self.auth_error = auth_error
        self.terminal_args = None
        self.auth_kwargs = None
        self.installs = []

    def terminal(self, *args):
        self.terminal_args = args

    def card(self):
        pass

    def auth(self, **kwargs):
        self.auth_kwargs = kwargs
        if self.auth_error:
            raise self.auth_error

    def install_capfile(self, path, **kwargs):
        self.installs.append((path, kwargs))
        return {}


class TestInstallAppletCap:
    def test_uses_named_reader_and_default_key(self, monkeypatch):
        pygp = FakePyGP()
        monkeypatch.setitem(sys.modules, "pygp", pygp)
        view = make_view()

        assert seedkeeper_utils.install_applet_cap(view, "x.cap", storage_param="1FFF", reader_name="Reader 0")

        assert pygp.terminal_args == ("Reader 0",)
        assert pygp.auth_kwargs["enc_key"] == seedkeeper_utils.DEFAULT_GP_KEY
        assert pygp.installs == [("x.cap", {"application_specific_parameters": "1FFF"})]

    def test_uses_loaded_key_set(self, monkeypatch):
        pygp = FakePyGP()
        monkeypatch.setitem(sys.modules, "pygp", pygp)
        view = make_view(javacard_keys={"type": "set", "enc": "E" * 32, "mac": "A" * 32, "dek": "D" * 32})

        assert seedkeeper_utils.install_applet_cap(view, "x.cap")
        assert (pygp.auth_kwargs["enc_key"], pygp.auth_kwargs["mac_key"], pygp.auth_kwargs["dek_key"]) == ("E" * 32, "A" * 32, "D" * 32)

    def test_required_auth_failure_stops_install(self, monkeypatch):
        pygp = FakePyGP(auth_error=BaseException("Card cryptogram invalid"))
        monkeypatch.setitem(sys.modules, "pygp", pygp)
        view = make_view()

        assert not seedkeeper_utils.install_applet_cap(view, "x.cap", require_auth=True)
        assert pygp.installs == []
        assert titles(view) == ["Card Keys Locked"]

    def test_optional_auth_failure_still_attempts_install(self, monkeypatch):
        pygp = FakePyGP(auth_error=BaseException("Card cryptogram invalid"))
        monkeypatch.setitem(sys.modules, "pygp", pygp)
        view = make_view()

        assert seedkeeper_utils.install_applet_cap(view, "x.cap")
        assert len(pygp.installs) == 1

    def test_install_error_is_reported(self, monkeypatch):
        pygp = FakePyGP()

        def boom(path, **kwargs):
            raise BaseException("Not enough memory space")

        pygp.install_capfile = boom
        monkeypatch.setitem(sys.modules, "pygp", pygp)
        view = make_view()

        assert not seedkeeper_utils.install_applet_cap(view, "x.cap")
        assert titles(view) == ["Failed"]
        assert "space" in view.screens[0].text


# ---------------------------------------------------------------------------
# init_satochip: missing applet, PIN prompts and retries
# ---------------------------------------------------------------------------
class FakeCardConnector:
    is_keycard_backend = False
    needs_secure_channel = False

    def __init__(self, setup_done=True, verify_results=(), setup_results=()):
        self.UID_SHA1 = "ab" * 20
        self.setup_done = setup_done
        self.verify_results = list(verify_results)
        self.setup_results = list(setup_results)
        self.pins = []
        self.setup_pins = []

    def set_pin(self, nbr, pin):
        self.pins.append(pin)

    def card_verify_PIN(self):
        result = self.verify_results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    def card_setup(self, pin_tries0, ublk_tries0, pin0, *args, **kwargs):
        self.setup_pins.append(pin0)
        return self.setup_results.pop(0)

    def card_disconnect(self):
        pass


def connect_with(monkeypatch, connector):
    monkeypatch.setattr(seedkeeper_utils, "_init_card_connector", lambda *a, **k: connector)
    monkeypatch.setattr(
        seedkeeper_utils, "_connect_card",
        lambda view, conn: ([], 0x90, 0x00, {"setup_done": conn.setup_done}),
    )


def queue_pins(monkeypatch, name, pins):
    asked = []
    replies = iter(pins)

    def fake_prompt(view, title, **kwargs):
        asked.append(title)
        return next(replies)

    monkeypatch.setattr(seedkeeper_utils, name, fake_prompt)
    return asked


class TestInitSatochipMissingApplet:
    def test_install_then_reconnect_once(self, monkeypatch):
        attempts = []

        def failing_connector(*args, **kwargs):
            attempts.append(1)
            raise RuntimeError("no applet")

        offers = []

        def fake_offer(view, card_filter):
            offers.append(card_filter)
            return seedkeeper_utils.APPLET_OFFER__INSTALLED

        monkeypatch.setattr(seedkeeper_utils, "_init_card_connector", failing_connector)
        monkeypatch.setattr(seedkeeper_utils, "offer_missing_applet_install", fake_offer)
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is None
        # One offer, then one reconnect that does not offer again.
        assert offers == [["seedkeeper"]]
        assert len(attempts) == 2
        assert titles(view) == ["Failure"]

    def test_handled_offer_skips_generic_error(self, monkeypatch):
        monkeypatch.setattr(seedkeeper_utils, "_init_card_connector",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no applet")))
        monkeypatch.setattr(seedkeeper_utils, "offer_missing_applet_install",
                            lambda view, f: seedkeeper_utils.APPLET_OFFER__HANDLED)
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is None
        assert view.screens == []

    def test_not_applicable_keeps_generic_error(self, monkeypatch):
        monkeypatch.setattr(seedkeeper_utils, "_init_card_connector",
                            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no card")))
        monkeypatch.setattr(seedkeeper_utils, "offer_missing_applet_install",
                            lambda view, f: seedkeeper_utils.APPLET_OFFER__NOT_APPLICABLE)
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is None
        assert titles(view) == ["Failure"]

    def test_status_failure_also_offers(self, monkeypatch):
        monkeypatch.setattr(seedkeeper_utils, "_init_card_connector", lambda *a, **k: FakeCardConnector())
        monkeypatch.setattr(seedkeeper_utils, "_connect_card", lambda view, conn: None)
        offers = []
        monkeypatch.setattr(seedkeeper_utils, "offer_missing_applet_install",
                            lambda view, f: offers.append(f) or seedkeeper_utils.APPLET_OFFER__NOT_APPLICABLE)
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is None
        assert offers == [["seedkeeper"]]
        assert titles(view) == ["Unable to Connect"]

    def test_status_failure_without_filter_reports_cleanly(self, monkeypatch):
        """filter_str was unbound when no card filter was given."""
        monkeypatch.setattr(seedkeeper_utils, "_init_card_connector", lambda *a, **k: FakeCardConnector())
        monkeypatch.setattr(seedkeeper_utils, "_connect_card", lambda view, conn: None)
        view = make_view()

        assert seedkeeper_utils.init_satochip(view) is None
        assert titles(view) == ["Unable to Connect"]


class TestInitSatochipPin:
    def test_blank_card_is_not_asked_for_existing_pin(self, monkeypatch):
        connector = FakeCardConnector(setup_done=False, setup_results=[([], 0x90, 0x00)])
        connect_with(monkeypatch, connector)
        asked_existing = queue_pins(monkeypatch, "prompt_for_pin", [])
        queue_pins(monkeypatch, "prompt_for_new_pin", ["1234"])
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is connector
        assert asked_existing == []
        assert view.controller.Satochip_PIN == list(b"1234")

    def test_rejected_setup_pin_reprompts(self, monkeypatch):
        connector = FakeCardConnector(
            setup_done=False,
            setup_results=[([], 0x9C, 0x0F), ([], 0x90, 0x00)],
        )
        connect_with(monkeypatch, connector)
        asked = queue_pins(monkeypatch, "prompt_for_new_pin", ["12", "123456"])
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is connector
        assert asked == ["New Card PIN", "New Card PIN"]
        assert connector.setup_pins == [list(b"12"), list(b"123456")]
        assert "PIN Rejected" in titles(view)
        assert view.controller.Satochip_PIN == list(b"123456")

    def test_backing_out_of_setup_retry_returns_none(self, monkeypatch):
        connector = FakeCardConnector(setup_done=False, setup_results=[([], 0x9C, 0x0F)])
        connect_with(monkeypatch, connector)
        queue_pins(monkeypatch, "prompt_for_new_pin", ["12", None])
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is None

    def test_wrong_pin_sw_reprompts(self, monkeypatch):
        connector = FakeCardConnector(verify_results=[([], 0x63, 0xC4), ([], 0x90, 0x00)])
        connect_with(monkeypatch, connector)
        asked = queue_pins(monkeypatch, "prompt_for_pin", ["0000", "1234"])
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is connector
        assert asked == ["Card PIN", "Card PIN"]
        assert titles(view) == ["Incorrect PIN"]
        assert "4 attempts" in view.screens[0].text
        assert view.controller.Satochip_PIN == list(b"1234")

    def test_wrong_pin_exception_reprompts(self, monkeypatch):
        # conftest stubs pysatochip with a MagicMock, so mirror its WrongPinError
        # (matched by name in production, for exactly that reason).
        class WrongPinError(Exception):
            def __init__(self, message, pin_left):
                super().__init__(message)
                self.pin_left = pin_left

        connector = FakeCardConnector(verify_results=[WrongPinError("Wrong PIN!", 2), ([], 0x90, 0x00)])
        connect_with(monkeypatch, connector)
        queue_pins(monkeypatch, "prompt_for_pin", ["0000", "1234"])
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is connector
        assert titles(view) == ["Incorrect PIN"]
        assert "2 attempts" in view.screens[0].text

    def test_last_attempt_stops_retrying(self, monkeypatch):
        connector = FakeCardConnector(verify_results=[([], 0x63, 0xC0)])
        connect_with(monkeypatch, connector)
        asked = queue_pins(monkeypatch, "prompt_for_pin", ["0000"])
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is None
        assert asked == ["Card PIN"]

    def test_backing_out_of_pin_retry_returns_none(self, monkeypatch):
        connector = FakeCardConnector(verify_results=[([], 0x63, 0xC4)])
        connect_with(monkeypatch, connector)
        queue_pins(monkeypatch, "prompt_for_pin", ["0000", None])
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is None

    def test_other_errors_still_stop(self, monkeypatch):
        connector = FakeCardConnector(verify_results=[RuntimeError("card removed")])
        connect_with(monkeypatch, connector)
        queue_pins(monkeypatch, "prompt_for_pin", ["1234"])
        view = make_view()

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is None
        assert titles(view) == ["Failed"]

    def test_cached_pin_same_card_is_not_prompted(self, monkeypatch):
        connector = FakeCardConnector(verify_results=[([], 0x90, 0x00)])
        connect_with(monkeypatch, connector)
        asked = queue_pins(monkeypatch, "prompt_for_pin", [])
        view = make_view()
        view.controller.Satochip_PIN = list(b"1234")
        view.controller.Satochip_Last_UID_SHA1 = connector.UID_SHA1

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is connector
        assert asked == []
        assert connector.pins == [list(b"1234")]

    def test_cached_pin_swapped_card_prompts_once(self, monkeypatch):
        connector = FakeCardConnector(verify_results=[([], 0x90, 0x00)])
        connect_with(monkeypatch, connector)
        asked = queue_pins(monkeypatch, "prompt_for_pin", ["5678"])
        view = make_view()
        view.controller.Satochip_PIN = list(b"1234")
        view.controller.Satochip_Last_UID_SHA1 = "cd" * 20

        assert seedkeeper_utils.init_satochip(view, init_card_filter=["seedkeeper"]) is connector
        assert asked == ["Card PIN"]
        assert connector.pins == [list(b"5678")]


# ---------------------------------------------------------------------------
# Change PIN view
# ---------------------------------------------------------------------------
class TestChangePinRetry:
    def _view(self, monkeypatch, change_results, new_pins):
        connector = SimpleNamespace(pin=list(b"1234"), calls=[])
        results = list(change_results)

        def change(nbr, old, new):
            connector.calls.append(new)
            result = results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result

        connector.card_change_PIN = change
        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *a, **k: connector)
        queue_pins(monkeypatch, "prompt_for_new_pin", new_pins)

        view = object.__new__(smartcard_views.ToolsSatochipChangePinView)
        view.card_filter = None
        stub = make_view()
        view.controller = stub.controller
        view.run_screen = stub.run_screen
        return view, stub, connector

    def test_rejected_pin_reprompts_until_accepted(self, monkeypatch):
        view, stub, connector = self._view(
            monkeypatch, [([], 0x9C, 0x0F), ([], 0x90, 0x00)], ["99", "5678"]
        )
        view.run()
        assert connector.calls == [list(b"99"), list(b"5678")]
        assert titles(stub) == ["PIN Rejected", "Success"]
        assert stub.controller.Satochip_PIN == list(b"5678")

    def test_back_out_after_rejection(self, monkeypatch):
        view, stub, connector = self._view(monkeypatch, [([], 0x9C, 0x0F)], ["99", None])
        view.run()
        assert titles(stub) == ["PIN Rejected"]
        assert stub.controller.Satochip_PIN is None

    def test_exception_is_reported_not_raised(self, monkeypatch):
        view, stub, connector = self._view(monkeypatch, [RuntimeError("card removed")], ["5678"])
        view.run()
        assert titles(stub) == ["Failed"]


# ---------------------------------------------------------------------------
# Specter-DIY PIN prompt
# ---------------------------------------------------------------------------
def test_specter_empty_pin_reprompts(monkeypatch):
    replies = iter([{"passphrase": ""}, {"passphrase": "1234"}])

    class FakeKeyboard:
        KEYBOARD__DIGITS_BUTTON_TEXT = "123"

        def __init__(self, **kwargs):
            pass

        def display(self):
            return next(replies)

    monkeypatch.setattr(smartcard_views.seed_screens, "SeedAddPassphraseScreen", FakeKeyboard)
    view = make_view()

    assert smartcard_views._prompt_specter_pin_once(view, "PIN") == "1234"
    assert titles(view) == ["Invalid PIN"]
