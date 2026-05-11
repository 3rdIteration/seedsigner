"""View-flow tests for ``ToolsKeycardChangePinView``.

The view sequence is:

1. Open a PIN-verified session with the current PIN (prompts on cache
   miss). Uses the shared
   ``open_unlocked_session_cached_or_prompt`` helper, which is patched
   here to avoid PC/SC and the secure-channel handshake.
2. Prompt for the new PIN, then a confirmation.
3. If the two new-PIN buffers match, call ``client.change_pin``; drop
   the cached PIN for the current UID so the next op re-prompts.
4. On mismatch, return an error destination without calling
   ``change_pin``.
5. The captured PIN ``bytearray``s are wiped in a ``finally`` block.
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


UID = b"\xAA" * 16


def _make_view():
    """Build a view stub that swallows screen-rendering calls."""
    view = MagicMock()
    view.controller = MagicMock()
    view.controller.last_keycard_uid = UID
    # The view's ``run_screen`` is called for the success / error screens;
    # the return value isn't used by ChangePinView, so MagicMock default
    # is fine.
    return view


def _make_client(instance_uid=UID):
    client = MagicMock()
    client.select_response = MagicMock()
    client.select_response.instance_uid = instance_uid
    return client


class TestToolsKeycardChangePinView(unittest.TestCase):
    def test_happy_path_sends_change_pin_and_forgets_cached_pin(self):
        from seedsigner.views import keycard_views

        client = _make_client()
        pairing = MagicMock(name="pairing")
        view = _make_view()

        new_pin = bytearray(b"234567")
        confirm_pin = bytearray(b"234567")
        # Two prompt_for_pin calls during change-pin: new, then confirm.
        prompt_returns = [new_pin, confirm_pin]

        with patch.object(
            keycard_views,
            "_open_unlocked_session_cached_or_prompt",
            return_value=(client, pairing),
        ), patch.object(
            keycard_views,
            "prompt_for_pin",
            side_effect=lambda *a, **kw: prompt_returns.pop(0),
        ):
            inst = keycard_views.ToolsKeycardChangePinView.__new__(
                keycard_views.ToolsKeycardChangePinView,
            )
            inst.controller = view.controller
            inst.run_screen = view.run_screen
            inst.run()

        client.change_pin.assert_called_once_with(b"234567")
        view.controller.forget_pin_for.assert_called_once_with(UID)
        # Both captured PIN buffers must be wiped in the finally block.
        self.assertEqual(new_pin, bytearray(b"\x00" * 6))
        self.assertEqual(confirm_pin, bytearray(b"\x00" * 6))

    def test_mismatched_confirmation_does_not_call_change_pin(self):
        from seedsigner.views import keycard_views

        client = _make_client()
        pairing = MagicMock(name="pairing")
        view = _make_view()

        new_pin = bytearray(b"234567")
        confirm_pin = bytearray(b"345678")
        prompt_returns = [new_pin, confirm_pin]

        with patch.object(
            keycard_views,
            "_open_unlocked_session_cached_or_prompt",
            return_value=(client, pairing),
        ), patch.object(
            keycard_views,
            "prompt_for_pin",
            side_effect=lambda *a, **kw: prompt_returns.pop(0),
        ):
            inst = keycard_views.ToolsKeycardChangePinView.__new__(
                keycard_views.ToolsKeycardChangePinView,
            )
            inst.controller = view.controller
            inst.run_screen = view.run_screen
            inst.run()

        client.change_pin.assert_not_called()
        view.controller.forget_pin_for.assert_not_called()
        # Even on the mismatch path, buffers are wiped.
        self.assertEqual(new_pin, bytearray(b"\x00" * 6))
        self.assertEqual(confirm_pin, bytearray(b"\x00" * 6))

    def test_user_cancels_new_pin_prompt(self):
        """Backing out of the new-PIN keyboard returns BackStackView and
        does NOT call change_pin."""
        from seedsigner.views import keycard_views

        client = _make_client()
        pairing = MagicMock(name="pairing")
        view = _make_view()

        with patch.object(
            keycard_views,
            "_open_unlocked_session_cached_or_prompt",
            return_value=(client, pairing),
        ), patch.object(
            keycard_views, "prompt_for_pin", return_value=None,
        ):
            inst = keycard_views.ToolsKeycardChangePinView.__new__(
                keycard_views.ToolsKeycardChangePinView,
            )
            inst.controller = view.controller
            inst.run_screen = view.run_screen
            inst.run()

        client.change_pin.assert_not_called()
        view.controller.forget_pin_for.assert_not_called()

    def test_session_open_raises_no_master_key(self):
        """If the card has no master key, the session helper raises
        KeycardNoMasterKeyError before we ever prompt for a new PIN."""
        from seedsigner.helpers.keycard import KeycardNoMasterKeyError
        from seedsigner.views import keycard_views

        view = _make_view()

        with patch.object(
            keycard_views,
            "_open_unlocked_session_cached_or_prompt",
            side_effect=KeycardNoMasterKeyError(UID),
        ), patch.object(
            keycard_views, "prompt_for_pin",
        ) as mock_prompt:
            inst = keycard_views.ToolsKeycardChangePinView.__new__(
                keycard_views.ToolsKeycardChangePinView,
            )
            inst.controller = view.controller
            inst.run_screen = view.run_screen
            inst.run()

        mock_prompt.assert_not_called()

    def test_change_pin_apdu_error_propagates_to_error_screen(self):
        """An APDUError from the card's CHANGE_PIN reply must route to
        the error view; the cached PIN must NOT be dropped (the change
        didn't happen)."""
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.views import keycard_views

        client = _make_client()
        # Simulate the card rejecting the new PIN format (unlikely on 6
        # digits, but the path is the same for any post-verify failure).
        client.change_pin.side_effect = APDUError(0x6A80, "Bad params")
        pairing = MagicMock(name="pairing")
        view = _make_view()

        new_pin = bytearray(b"234567")
        confirm_pin = bytearray(b"234567")
        prompt_returns = [new_pin, confirm_pin]

        with patch.object(
            keycard_views,
            "_open_unlocked_session_cached_or_prompt",
            return_value=(client, pairing),
        ), patch.object(
            keycard_views,
            "prompt_for_pin",
            side_effect=lambda *a, **kw: prompt_returns.pop(0),
        ):
            inst = keycard_views.ToolsKeycardChangePinView.__new__(
                keycard_views.ToolsKeycardChangePinView,
            )
            inst.controller = view.controller
            inst.run_screen = view.run_screen
            inst.run()

        client.change_pin.assert_called_once_with(b"234567")
        # The change failed — must not lie to the user by clearing the
        # cached PIN.
        view.controller.forget_pin_for.assert_not_called()
        # Buffers wiped regardless.
        self.assertEqual(new_pin, bytearray(b"\x00" * 6))
        self.assertEqual(confirm_pin, bytearray(b"\x00" * 6))


if __name__ == "__main__":
    unittest.main()
