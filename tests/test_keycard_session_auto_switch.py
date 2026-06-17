"""Auto-switch behaviour for ``open_unlocked_session``.

Verifies the multi-card session contract:

* SELECT runs first; the controller's ``last_keycard_uid`` is updated.
* The pairing for the inserted card is looked up via
  ``Controller.get_pairing_for(uid)``.
* When no pairing exists for the inserted card, ``KeycardCardChangedError``
  is raised carrying the card's UID (so the caller can route to PairView).
* When a pairing exists, ``open_secure_channel`` and ``verify_pin`` are
  called with the correct values.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
        "periphery",
    ]:
        sys.modules.setdefault(mod, MagicMock())


_install_hw_mocks()


UID_A = b"\xAA" * 16
UID_B = b"\xBB" * 16


def _make_select_response(uid, app_version=0x0301):
    # app_version 0x0301 = v3.1 (no ephemeral pairing) by default; tests
    # exercising the persistent path get the legacy behaviour. Pass 0
    # to simulate a pre-init applet, or 0x0302+ for ephemeral.
    info = MagicMock(name="select_info")
    info.instance_uid = uid
    info.app_version = app_version
    return info


class _Controller:
    """Minimal Controller stand-in matching the real cache contract."""

    def __init__(self):
        self.keycard_pairings = {}
        self.keycard_ephemeral_secrets = {}
        self.keycard_pins = {}
        self.keycard_aid_to_uid = {}
        self.last_keycard_uid = None
        # Swap-detection reference set by open_unlocked_session (the real
        # Controller initialises it in get_instance).
        self.last_authenticated_keycard_uid = None

    def wipe_card_session_secrets(self):
        # Faithful to the real contract for the swap-detector: drop PINs and
        # card-specific maps, but KEEP pairings / ephemeral secrets (they are
        # per-UID and survive a card swap, so each card still finds its own).
        self.keycard_pins.clear()
        self.keycard_aid_to_uid.clear()
        self.last_keycard_uid = None
        self.last_authenticated_keycard_uid = None

    def remember_aid_for_uid(self, aid, uid):
        if aid is None or uid is None:
            return
        self.keycard_aid_to_uid[bytes(aid)] = bytes(uid)

    def get_uid_for_aid(self, aid):
        if aid is None:
            return None
        return self.keycard_aid_to_uid.get(bytes(aid))

    def get_pairing_for(self, uid):
        if uid is None:
            return None
        return self.keycard_pairings.get(bytes(uid))

    def set_pairing_for(self, uid, pairing):
        self.keycard_pairings[bytes(uid)] = pairing
        self.last_keycard_uid = bytes(uid)

    def get_ephemeral_secret_for(self, uid):
        if uid is None:
            return None
        return self.keycard_ephemeral_secrets.get(bytes(uid))

    def forget_ephemeral_secret_for(self, uid):
        self.keycard_ephemeral_secrets.pop(bytes(uid), None)

    def get_pin_for(self, uid):
        if uid is None:
            return None
        return self.keycard_pins.get(bytes(uid))

    def set_pin_for(self, uid, pin):
        if uid is None or pin is None:
            return
        self.keycard_pins[bytes(uid)] = bytearray(pin)

    def forget_pin_for(self, uid):
        self.keycard_pins.pop(bytes(uid), None)


def _patches(client):
    """Patch the lazy imports inside ``ui_helpers.open_unlocked_session``."""
    import seedsigner.helpers.keycard.client as kc_client
    import seedsigner.helpers.keycard.reader as kc_reader
    return [
        patch.object(kc_client, "KeycardClient", MagicMock(return_value=client)),
        patch.object(kc_reader, "wait_for_card", return_value="conn"),
    ]


class TestAutoSwitch(unittest.TestCase):
    def test_card_with_pairing_succeeds(self):
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        ctrl = _Controller()
        pairing_a = MagicMock(name="pairing_a")
        ctrl.set_pairing_for(UID_A, pairing_a)

        view = MagicMock()
        view.controller = ctrl

        client = MagicMock()
        client.select.return_value = _make_select_response(UID_A)

        for p in _patches(client):
            p.start()
        try:
            returned_client, returned_pairing = open_unlocked_session(
                view, bytearray(b"123456"),
            )
        finally:
            for p in _patches(client):
                # patches were stopped on context exit by the contextmanager;
                # explicit stopall just in case patch instances aren't reused.
                pass
            patch.stopall()

        self.assertIs(returned_pairing, pairing_a)
        self.assertEqual(ctrl.last_keycard_uid, UID_A)
        client.open_secure_channel.assert_called_once_with(pairing_a)
        client.verify_pin.assert_called_once_with(b"123456")

    def test_card_without_pairing_raises_card_changed(self):
        from seedsigner.helpers.keycard import KeycardCardChangedError
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        ctrl = _Controller()
        # Cache has UID_A, but UID_B is in the reader.
        ctrl.set_pairing_for(UID_A, MagicMock(name="pairing_a"))

        view = MagicMock()
        view.controller = ctrl

        client = MagicMock()
        client.select.return_value = _make_select_response(UID_B)

        for p in _patches(client):
            p.start()
        try:
            with self.assertRaises(KeycardCardChangedError) as ctx:
                open_unlocked_session(view, bytearray(b"123456"))
        finally:
            patch.stopall()

        self.assertEqual(ctx.exception.instance_uid, UID_B)
        # Reader is updated with the UID just observed.
        self.assertEqual(ctrl.last_keycard_uid, UID_B)
        # We must NOT open a secure channel with the wrong card's pairing.
        client.open_secure_channel.assert_not_called()
        client.verify_pin.assert_not_called()

    def test_back_to_back_card_swap_picks_each_pairing(self):
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        ctrl = _Controller()
        pairing_a = MagicMock(name="pairing_a")
        pairing_b = MagicMock(name="pairing_b")
        ctrl.set_pairing_for(UID_A, pairing_a)
        ctrl.set_pairing_for(UID_B, pairing_b)

        view = MagicMock()
        view.controller = ctrl

        # First call: card A in reader. Second call: card B in reader.
        client = MagicMock()
        client.select.side_effect = [
            _make_select_response(UID_A),
            _make_select_response(UID_B),
        ]

        for p in _patches(client):
            p.start()
        try:
            _, pa = open_unlocked_session(view, bytearray(b"123456"))
            _, pb = open_unlocked_session(view, bytearray(b"123456"))
        finally:
            patch.stopall()

        self.assertIs(pa, pairing_a)
        self.assertIs(pb, pairing_b)
        self.assertEqual(ctrl.last_keycard_uid, UID_B)
        # open_secure_channel called with the correct pairing each time.
        calls = client.open_secure_channel.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertIs(calls[0].args[0], pairing_a)
        self.assertIs(calls[1].args[0], pairing_b)

    def test_swap_wipes_previous_card_secrets(self):
        """A different inserted UID than the last authenticated one triggers a
        reader-independent wipe of the previous card's session secrets — the
        backstop for an unreliable PC/SC 'removed' event (esp. NFC/PN532)."""
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        ctrl = _Controller()
        ctrl.set_pairing_for(UID_A, MagicMock(name="pairing_a"))
        ctrl.set_pairing_for(UID_B, MagicMock(name="pairing_b"))
        ctrl.last_authenticated_keycard_uid = UID_A  # last session was card A
        ctrl.wipe_card_session_secrets = MagicMock(
            wraps=ctrl.wipe_card_session_secrets,
        )

        view = MagicMock()
        view.controller = ctrl
        client = MagicMock()
        client.select.return_value = _make_select_response(UID_B)

        for p in _patches(client):
            p.start()
        try:
            open_unlocked_session(view, bytearray(b"123456"))
        finally:
            patch.stopall()

        ctrl.wipe_card_session_secrets.assert_called_once()
        # Marker now points at the card actually in the reader.
        self.assertEqual(ctrl.last_authenticated_keycard_uid, UID_B)

    def test_same_card_reuse_does_not_wipe(self):
        """Repeated ops on the same card must NOT wipe — that is what lets the
        cached PIN be reused (the whole point of caching)."""
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        ctrl = _Controller()
        ctrl.set_pairing_for(UID_A, MagicMock(name="pairing_a"))
        ctrl.last_authenticated_keycard_uid = UID_A
        ctrl.wipe_card_session_secrets = MagicMock(
            wraps=ctrl.wipe_card_session_secrets,
        )

        view = MagicMock()
        view.controller = ctrl
        client = MagicMock()
        client.select.return_value = _make_select_response(UID_A)

        for p in _patches(client):
            p.start()
        try:
            open_unlocked_session(view, bytearray(b"123456"))
        finally:
            patch.stopall()

        ctrl.wipe_card_session_secrets.assert_not_called()
        self.assertEqual(ctrl.last_authenticated_keycard_uid, UID_A)


class TestKeycardCardChangedError(unittest.TestCase):
    def test_carries_instance_uid(self):
        from seedsigner.helpers.keycard import KeycardCardChangedError
        err = KeycardCardChangedError(b"\x12\x34")
        self.assertEqual(err.instance_uid, b"\x12\x34")
        self.assertIn("not paired", str(err))


if __name__ == "__main__":
    unittest.main()
