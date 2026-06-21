"""View-flow tests for ``ToolsKeycardUnblockPinView`` (PIN recovery via PUK).

The view sequence is:

1. Open a secure-channel session WITHOUT PIN verification
   (``skip_pin_verify=True`` — the PIN is blocked, VERIFY_PIN cannot
   succeed).
2. GET STATUS: bail with a clear message if the PIN is not actually
   blocked, or if the PUK itself has no retries left.
3. Prompt for the 12-digit PUK, then the new PIN twice (entry + confirm).
4. Send UNBLOCK PIN; on success drop the cached PIN for this UID.
5. A wrong PUK (SW=0x63CX) surfaces the remaining PUK retries; 0x63C0
   reports the PUK as blocked (factory reset only).
6. All captured digit buffers are wiped in a ``finally`` block.
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
    view = MagicMock()
    view.controller = MagicMock()
    view.controller.last_keycard_uid = UID
    return view


def _make_client(pin_retries=0, puk_retries=5, instance_uid=UID):
    from seedsigner.helpers.keycard.responses import StatusResponse

    client = MagicMock()
    client.select_response = MagicMock()
    client.select_response.instance_uid = instance_uid
    client.get_status.return_value = StatusResponse(
        pin_retries=pin_retries, puk_retries=puk_retries, key_initialised=True,
    )
    return client


def _run_view(client, prompt_returns):
    from seedsigner.views import keycard_views

    view = _make_view()
    returns = list(prompt_returns)
    with patch.object(
        keycard_views, "_open_unlocked_session",
        return_value=(client, MagicMock(name="pairing")),
    ) as session_mock, patch.object(
        keycard_views, "prompt_for_pin",
        side_effect=lambda *a, **kw: returns.pop(0),
    ) as prompt_mock:
        inst = keycard_views.ToolsKeycardUnblockPinView.__new__(
            keycard_views.ToolsKeycardUnblockPinView,
        )
        inst.controller = view.controller
        inst.run_screen = view.run_screen
        inst.run()
    return view, session_mock, prompt_mock


class TestUnblockPinView(unittest.TestCase):
    def test_happy_path_unblocks_and_forgets_cached_pin(self):
        client = _make_client(pin_retries=0, puk_retries=5)
        puk = bytearray(b"123456789012")
        new_pin = bytearray(b"234567")
        confirm = bytearray(b"234567")

        view, session_mock, prompt_mock = _run_view(
            client, [puk, new_pin, confirm],
        )

        # Session must be opened WITHOUT PIN verification.
        self.assertTrue(session_mock.call_args.kwargs.get("skip_pin_verify"))
        client.unblock_pin.assert_called_once_with(b"123456789012", b"234567")
        view.controller.forget_pin_for.assert_called_once_with(UID)
        # The PUK prompt must request 12 digits.
        self.assertEqual(prompt_mock.call_args_list[0].kwargs.get("num_digits"), 12)
        # Every captured buffer is wiped in the finally block.
        self.assertEqual(puk, bytearray(b"\x00" * 12))
        self.assertEqual(new_pin, bytearray(b"\x00" * 6))
        self.assertEqual(confirm, bytearray(b"\x00" * 6))

    def test_pin_not_blocked_bails_before_any_prompt(self):
        client = _make_client(pin_retries=3, puk_retries=5)
        view, _unused, prompt_mock = _run_view(client, [])

        prompt_mock.assert_not_called()
        client.unblock_pin.assert_not_called()
        view.controller.forget_pin_for.assert_not_called()

    def test_puk_blocked_bails_before_any_prompt(self):
        client = _make_client(pin_retries=0, puk_retries=0)
        view, _unused, prompt_mock = _run_view(client, [])

        prompt_mock.assert_not_called()
        client.unblock_pin.assert_not_called()

    def test_wrong_puk_surfaces_retries_and_wipes_buffers(self):
        from seedsigner.helpers.keycard.commands import APDUError

        client = _make_client(pin_retries=0, puk_retries=5)
        client.unblock_pin.side_effect = APDUError(0x63C4, "wrong PUK")
        puk = bytearray(b"999999999999")
        new_pin = bytearray(b"234567")
        confirm = bytearray(b"234567")

        view, _unused, _unused2 = _run_view(client, [puk, new_pin, confirm])

        view.controller.forget_pin_for.assert_not_called()
        self.assertEqual(puk, bytearray(b"\x00" * 12))
        self.assertEqual(new_pin, bytearray(b"\x00" * 6))

    def test_mismatched_new_pin_does_not_call_unblock(self):
        client = _make_client(pin_retries=0, puk_retries=5)
        puk = bytearray(b"123456789012")
        new_pin = bytearray(b"234567")
        confirm = bytearray(b"345678")

        view, _unused, _unused2 = _run_view(client, [puk, new_pin, confirm])

        client.unblock_pin.assert_not_called()
        view.controller.forget_pin_for.assert_not_called()
        self.assertEqual(puk, bytearray(b"\x00" * 12))

    def test_cancel_at_puk_prompt_skips_unblock(self):
        client = _make_client(pin_retries=0, puk_retries=5)
        view, _unused, _unused2 = _run_view(client, [None])

        client.unblock_pin.assert_not_called()


class TestThisInstanceMenuRouting(unittest.TestCase):
    def test_unblock_entry_routes_to_unblock_view(self):
        from seedsigner.views import keycard_views

        menu = keycard_views.ToolsKeycardThisInstanceMenuView
        self.assertEqual(menu.UNBLOCK_PIN.button_label, "Unblock PIN (PUK)")

        inst = menu.__new__(menu)
        inst.controller = MagicMock()
        # Select index 1: CHANGE_PIN / UNBLOCK_PIN / LOCK / SETUP_RESET
        # (rename hidden via _instance_rename_available -> False; the
        # destructive ops moved under the Set up / reset submenu).
        inst.run_screen = MagicMock(return_value=1)
        with patch.object(
            keycard_views, "_instance_rename_available", return_value=False,
        ), patch.object(
            keycard_views, "_instance_display_name", return_value="Inst 1",
        ):
            dest = inst.run()
        self.assertIs(dest.View_cls, keycard_views.ToolsKeycardUnblockPinView)


if __name__ == "__main__":
    unittest.main()
