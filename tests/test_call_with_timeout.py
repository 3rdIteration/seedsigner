# pylint: disable=missing-function-docstring
import random
import threading
import time
import types
from concurrent.futures import Future, TimeoutError as FuturesTimeoutError
from types import SimpleNamespace

import pytest

# Must import base before any seedsigner modules: seedkeeper_utils pulls in the
# GUI, and imported first it keeps the real hardware and renderer modules.
import base  # noqa: F401

from embit.ec import PrivateKey
from embit.psbt import DerivationPath, InputScope, PSBT

from seedsigner.helpers import satochip_signer, seedkeeper_utils
from seedsigner.helpers.satochip_signer import _call_with_timeout, sign_psbt_with_satochip
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


class TestATimeoutActuallyReturns:
    """A stalled card must not hold the caller past the timeout."""

    def test_a_stalled_call_raises_without_waiting_for_the_worker(self):
        release = threading.Event()

        def stalls():
            release.wait(30)
            return "too late"

        start = time.monotonic()
        try:
            with pytest.raises((TimeoutError, FuturesTimeoutError)):
                _call_with_timeout(stalls, 0.2)
            elapsed = time.monotonic() - start
        finally:
            release.set()

        # Waiting on the worker would make this ~30s
        assert elapsed < 3, f"took {elapsed:.1f}s: the worker was waited on"


class _Card:
    """A card whose next request can be made to hang until released."""

    def __init__(self):
        self.release = threading.Event()
        self.started = []

    def stall(self):
        self.started.append("stall")
        self.release.wait(30)
        return "late"

    def answer(self):
        self.started.append("answer")
        return "ok"


class TestNothingIsSentToACardStillBusy:
    """
    A timeout abandons its worker; it does not stop it. That worker is still in
    the middle of an exchange with the card, and "Retry (higher timeout)" is one
    button away. The retry builds a new connector, but it talks to the same
    card, so whichever connector asks, nothing may be sent until the abandoned
    request has ended.
    """

    def test_a_retry_on_a_new_connector_sends_nothing(self):
        stuck, retry = _Card(), _Card()
        try:
            with pytest.raises((TimeoutError, FuturesTimeoutError)):
                _call_with_timeout(stuck.stall, 0.2)

            start = time.monotonic()
            with pytest.raises((TimeoutError, FuturesTimeoutError)):
                _call_with_timeout(retry.answer, 0.3)
            elapsed = time.monotonic() - start

            assert retry.started == [], "a request went to a busy card"
            assert elapsed < 3, "the retry did not respect its own timeout"
        finally:
            stuck.release.set()

    def test_the_card_is_usable_again_once_the_request_ends(self):
        stuck, retry = _Card(), _Card()
        with pytest.raises((TimeoutError, FuturesTimeoutError)):
            _call_with_timeout(stuck.stall, 0.2)
        stuck.release.set()

        assert _call_with_timeout(retry.answer, 2) == "ok"
        assert retry.started == ["answer"]

    def test_a_request_cancelled_before_it_ran_does_not_wedge_the_card(self, monkeypatch):
        # A timeout that fires before the worker picks the request up leaves a
        # cancelled future behind. It never reached the card, so it must not
        # block the card for good.
        never_ran = Future()
        never_ran.cancel()
        monkeypatch.setattr(satochip_signer, "_abandoned_request", never_ran)
        card = _Card()

        assert _call_with_timeout(card.answer, 2) == "ok"


KEY = PrivateKey(bytes([5]) * 32)


class _CardPubkey:
    def __init__(self, key):
        self._sec = key.get_public_key().sec()

    def get_public_key_bytes(self, compressed=True):
        return self._sec


class _StallingSatochip:
    """A Satochip whose signatures never come back until released."""

    def __init__(self):
        self.release = threading.Event()
        self.requests = []

    def card_bip32_get_extendedkey(self, path):
        self.requests.append("derive")
        return _CardPubkey(KEY), b"\x00" * 32

    def card_sign_transaction_hash(self, keynbr, txhash, chalresponse=None):
        self.requests.append("sign")
        self.release.wait(30)
        return (b"", 0x6F, 0x00)


class _Settings:
    def __init__(self, pre_dummies=0):
        self.pre_dummies = pre_dummies

    def get_value(self, setting):
        if setting == SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT:
            return 0.2
        if setting == SettingsConstants.SETTING__SATOCHIP_MAX_PRE_DUMMIES:
            return self.pre_dummies
        return 0


def _psbt(inputs):
    psbt = PSBT()
    psbt.inputs = [InputScope() for _ in range(inputs)]
    for inp in psbt.inputs:
        inp.bip32_derivations[KEY.get_public_key()] = DerivationPath(b"\x00" * 4, [0])
    psbt.sighash = types.MethodType(lambda self, idx, sighash=None: bytes([idx + 1]) * 32, psbt)
    return psbt


class TestTheSignerSendsNothingToABusyCard:
    """
    The signer talks to the card directly to derive each input's key, so the
    guard in _call_with_timeout alone let a derivation reach a card that was
    still working on a signature that had timed out.
    """

    def _sign(self, monkeypatch, psbt, settings):
        monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: settings))
        monkeypatch.setattr(random, "randint", lambda low, high: high)
        monkeypatch.setattr(random, "random", lambda: 1.0)
        card = _StallingSatochip()
        try:
            return card, sign_psbt_with_satochip(psbt, card)
        finally:
            card.release.set()

    def test_no_derivation_follows_a_stalled_signature(self, monkeypatch):
        card, result = self._sign(monkeypatch, _psbt(2), _Settings())

        assert card.requests == ["derive", "sign"], "a request went to a busy card"
        assert result.signed_count == 0
        assert result.timed_out

    def test_no_derivation_follows_a_stalled_dummy(self, monkeypatch):
        card, result = self._sign(monkeypatch, _psbt(1), _Settings(pre_dummies=1))

        assert card.requests == ["sign"], "a request went to a busy card"
        # Nothing was signed because of the stall: the user is offered a retry
        assert result.timed_out


class _NoLoadingScreen:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        pass

    def stop(self):
        pass


class _Connector:
    """A connector as init_satochip sees one, logging what reaches the card."""

    card_type = "Satochip"
    is_keycard_backend = False
    needs_secure_channel = False
    UID_SHA1 = "0123456789abcdef0123456789abcdef01234567"

    def __init__(self, requests):
        self.requests = requests
        self.release = threading.Event()

    def card_sign_transaction_hash(self, keynbr, txhash, chalresponse=None):
        self.release.wait(30)
        return (b"", 0x6F, 0x00)

    def card_disconnect(self):
        self.requests.append("disconnect")

    def card_get_status(self):
        self.requests.append("status")
        return ([], 0x90, 0x00, {"setup_done": True})

    def set_pin(self, pin_nbr, pin):
        pass

    def card_verify_PIN(self):
        self.requests.append("verify_pin")
        return ([], 0x90, 0x00)


class TestTheRetryWaitsForTheBusyCard:
    """
    "Retry (higher timeout)" goes back through init_satochip, which disconnects
    the old connector and builds a new one before signing. Every step of that
    talks to the card the abandoned request is still running on.
    """

    def _retry(self, monkeypatch, old, requests):
        monkeypatch.setattr(
            seedkeeper_utils, "_init_card_connector", lambda *a, **kw: _Connector(requests)
        )
        monkeypatch.setattr(seedkeeper_utils, "LoadingScreenThread", _NoLoadingScreen)
        monkeypatch.setattr(satochip_signer, "CARD_BUSY_WAIT_SECONDS", 0.2)
        screens = []
        parent = SimpleNamespace(
            controller=SimpleNamespace(
                Satochip_Connector=old,
                smartcard_backend_preference=None,
                Satochip_PIN=list(b"1234"),
                Satochip_Last_UID_SHA1=_Connector.UID_SHA1,
            ),
            run_screen=lambda screen, **kwargs: screens.append(kwargs.get("title")),
        )
        return seedkeeper_utils.init_satochip(parent, init_card_filter=["satochip"]), screens

    def test_nothing_reaches_a_card_still_busy(self, monkeypatch):
        requests = []
        old = _Connector(requests)
        try:
            with pytest.raises((TimeoutError, FuturesTimeoutError)):
                _call_with_timeout(old.card_sign_transaction_hash, 0.2, 0xFF, [0] * 32, None)

            connector, screens = self._retry(monkeypatch, old, requests)

            assert requests == [], "a request went to a busy card"
            assert connector is None
            assert screens == ["Card Busy"]
        finally:
            old.release.set()

    def test_the_retry_goes_ahead_once_the_card_is_free(self, monkeypatch):
        requests = []
        old = _Connector(requests)
        with pytest.raises((TimeoutError, FuturesTimeoutError)):
            _call_with_timeout(old.card_sign_transaction_hash, 0.2, 0xFF, [0] * 32, None)
        old.release.set()

        connector, screens = self._retry(monkeypatch, old, requests)

        assert connector is not None and connector is not old
        assert requests == ["disconnect", "status", "verify_pin"]
        assert screens == []
