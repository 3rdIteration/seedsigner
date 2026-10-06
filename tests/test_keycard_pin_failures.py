# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest

from seedsigner.helpers import keycard_connector


class CardError(Exception):
    def __init__(self, sw):
        super().__init__(f"SW={sw:04X}")
        self.status_word = sw


WRONG_PUK = 0x63C2   # verification failed, 2 attempts left
WRONG_PIN = 0x63C1


class RefusingCard:
    """A card that rejects every credential change, as a real one does."""

    def __init__(self, sw):
        self.sw = sw
        self.calls = []

    def unblock_pin(self, puk, new_pin):
        self.calls.append(("unblock_pin", puk, new_pin))
        raise CardError(self.sw)

    def change_pin(self, new_pin):
        self.calls.append(("change_pin", new_pin))
        raise CardError(self.sw)

    def change_puk(self, new_puk):
        self.calls.append(("change_puk", new_puk))
        raise CardError(self.sw)


def make_connector(card):
    conn = object.__new__(keycard_connector.KeycardSatochipConnector)
    conn._card = card
    conn._secure_open = True
    conn.pin = list(b"111111")
    conn._ensure_secure_channel = lambda: None
    conn._ensure_pin_verified = lambda: None
    conn._verify_pin_sw = lambda: (0x90, 0x00)
    return conn


class TestRejectedCredentialChange:
    """A refused change must come back as a status word, not an exception."""

    def test_unblock_pin_with_a_wrong_puk(self):
        conn = make_connector(RefusingCard(WRONG_PUK))

        _resp, sw1, sw2 = conn.card_unblock_PIN(0, "999999999999", "222222")

        assert (sw1, sw2) == (0x63, 0xC2)
        # The PIN was not changed, so the cached one must not be either
        assert conn.pin == list(b"111111")

    def test_change_pin_with_a_wrong_old_pin(self):
        conn = make_connector(RefusingCard(WRONG_PIN))

        _resp, sw1, sw2 = conn.card_change_PIN(0, "111111", "222222")

        assert (sw1, sw2) == (0x63, 0xC1)
        assert conn.pin == list(b"111111")

    def test_change_puk_that_the_card_refuses(self):
        conn = make_connector(RefusingCard(WRONG_PIN))

        _resp, sw1, sw2 = conn.card_change_PUK(0, "000000000000", "999999999999")

        assert (sw1, sw2) == (0x63, 0xC1)


class RejectingPinCard:
    """A card that refuses PIN verification itself."""

    def __init__(self):
        self.changed = []

    def change_pin(self, new_pin):
        self.changed.append(new_pin)


class TestCachedPinAfterAFailedVerify:
    """A wrong old PIN must not end up cached as if it were right."""

    def test_cached_pin_survives_a_failed_verification(self):
        conn = make_connector(RejectingPinCard())
        conn._verify_pin_sw = lambda: (0x63, 0xC2)

        _resp, sw1, sw2 = conn.card_change_PIN(0, "999999", "222222")

        assert (sw1, sw2) == (0x63, 0xC2)
        assert conn.pin == list(b"111111")
        assert conn._card.changed == []


class _PukScreen:
    KEYBOARD__DIGITS_BUTTON_TEXT = "123"

    def __init__(self, *args, **kwargs):
        pass

    def display(self):
        return {"passphrase": "999999999999"}


class TestAWrongPukIsReportedAsOne(BaseTest):
    """
    Unblock PIN is only reached with the PIN already blocked, so a 63CX here is
    the card refusing the PUK, and X counts the PUK tries left. Running out of
    those blocks the card for good, so the warning must name the right secret.
    """

    def test_a_wrong_puk_names_the_puk_and_its_tries(self, monkeypatch):
        from seedsigner.views import smartcard_views

        conn = make_connector(RefusingCard(WRONG_PUK))
        monkeypatch.setattr(
            smartcard_views.seedkeeper_utils, "init_satochip", lambda *a, **kw: conn
        )
        monkeypatch.setattr(smartcard_views.seed_screens, "SeedAddPassphraseScreen", _PukScreen)
        monkeypatch.setattr(smartcard_views, "_prompt_keycard_new_pin", lambda *a: "222222")
        shown = []
        view = smartcard_views.ToolsKeycardUnblockPinView()
        monkeypatch.setattr(
            view, "run_screen",
            lambda screen, **kw: shown.append((kw.get("title"), kw.get("text"))),
            raising=False,
        )

        view.run()

        assert shown == [("Incorrect PUK", "PUK is incorrect.\n2 attempts remaining.")]
        assert conn.pin == list(b"111111")
