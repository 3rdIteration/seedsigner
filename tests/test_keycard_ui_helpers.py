"""Unit tests for ``helpers/keycard/ui_helpers.py``.

These cover the pure helpers (path formatting, pubkey extraction, byte
wiping) and exercise the session-opening helper with a mocked client so
the secure-channel flow does not need real PC/SC hardware.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


# Mock hardware-dependent modules before importing anything that pulls them in.
def _install_hw_mocks():
    for mod in [
        "RPi", "RPi.GPIO", "pyzbar", "pyzbar.pyzbar", "smbus2",
        "smartcard", "smartcard.System", "pygame",
        "pysatochip.JCconstants", "pysatochip.util", "pysatochip.CardConnector",
    ]:
        sys.modules.setdefault(mod, MagicMock())

_install_hw_mocks()


class TestFormatPath(unittest.TestCase):
    def test_default_eth(self):
        from seedsigner.helpers.keycard.ui_helpers import format_path
        components = (
            44 | 0x80000000,
            60 | 0x80000000,
            0 | 0x80000000,
            0,
            0,
        )
        self.assertEqual(format_path(components), "m/44'/60'/0'/0/0")

    def test_no_components(self):
        from seedsigner.helpers.keycard.ui_helpers import format_path
        self.assertEqual(format_path([]), "m/")

    def test_mixed_hardened_and_soft(self):
        from seedsigner.helpers.keycard.ui_helpers import format_path
        # m/0/1'/2 — hardened only on the middle component.
        components = [0, 1 | 0x80000000, 2]
        self.assertEqual(format_path(components), "m/0/1'/2")

    def test_high_index_value(self):
        from seedsigner.helpers.keycard.ui_helpers import format_path
        # Soft index just below the hardened bit: 0x7FFFFFFF.
        self.assertEqual(format_path([0x7FFFFFFF]), "m/2147483647")


class TestExtractPubkey(unittest.TestCase):
    def _make_pubkey(self) -> bytes:
        # 65-byte uncompressed pubkey (0x04 prefix + 64 zero bytes is fine
        # for parser-only tests).
        return b"\x04" + bytes(range(1, 65))

    def test_template_a1_then_tlv_80(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        pubkey = self._make_pubkey()
        # Outer template 0xA1 with one inner TLV: tag 0x80, len 65.
        body = b"\x80\x41" + pubkey
        response = b"\xA1" + bytes([len(body)]) + body
        self.assertEqual(extract_pubkey(response), pubkey)

    def test_flat_tlv_without_outer_template(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        pubkey = self._make_pubkey()
        response = b"\x80\x41" + pubkey
        self.assertEqual(extract_pubkey(response), pubkey)

    def test_returns_none_for_empty(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        self.assertIsNone(extract_pubkey(b""))

    def test_returns_none_for_no_matching_tag(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        # Tag 0x81 instead of 0x80 — should be skipped, no pubkey returned.
        response = b"\x81\x41\x04" + bytes(64)
        self.assertIsNone(extract_pubkey(response))

    def test_returns_none_when_tag_present_but_pubkey_malformed(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        # tag 0x80 length 65 but missing 0x04 leading byte.
        response = b"\x80\x41" + b"\x00" + bytes(64)
        self.assertIsNone(extract_pubkey(response))

    def test_bare_uncompressed_pubkey(self):
        """Some applet variants return the raw 65-byte pubkey with no TLV
        wrapping at all. Parser must accept that as a fallback."""
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        pubkey = self._make_pubkey()
        self.assertEqual(extract_pubkey(pubkey), pubkey)

    def test_template_a1_with_long_form_length(self):
        """Outer template length encoded as ``0x81 LL`` (BER long-form)."""
        from seedsigner.helpers.keycard.ui_helpers import extract_pubkey
        pubkey = self._make_pubkey()
        body = b"\x80\x41" + pubkey
        response = b"\xA1\x81" + bytes([len(body)]) + body
        self.assertEqual(extract_pubkey(response), pubkey)


class TestExtractExtendedPubkey(unittest.TestCase):
    def _make_pubkey(self) -> bytes:
        return b"\x04" + bytes(range(1, 65))

    def _make_chain_code(self) -> bytes:
        return bytes(range(100, 132))

    def test_template_a1_pubkey_then_chain_code(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_extended_pubkey
        pub, cc = self._make_pubkey(), self._make_chain_code()
        body = b"\x80\x41" + pub + b"\x82\x20" + cc
        response = b"\xA1" + bytes([len(body)]) + body
        self.assertEqual(extract_extended_pubkey(response), (pub, cc))

    def test_bare_pubkey_then_chain_code(self):
        """Some applets return ``04 || pubkey(64) || chain_code(32)`` raw."""
        from seedsigner.helpers.keycard.ui_helpers import extract_extended_pubkey
        pub, cc = self._make_pubkey(), self._make_chain_code()
        self.assertEqual(extract_extended_pubkey(pub + cc), (pub, cc))

    def test_returns_none_when_chain_code_missing(self):
        from seedsigner.helpers.keycard.ui_helpers import extract_extended_pubkey
        pub = self._make_pubkey()
        body = b"\x80\x41" + pub
        response = b"\xA1" + bytes([len(body)]) + body
        self.assertIsNone(extract_extended_pubkey(response))


class TestWipeBytearray(unittest.TestCase):
    def test_wipes_in_place(self):
        from seedsigner.helpers.keycard.ui_helpers import wipe_bytearray
        buf = bytearray(b"123456")
        wipe_bytearray(buf)
        self.assertEqual(buf, bytearray(6))

    def test_handles_none(self):
        from seedsigner.helpers.keycard.ui_helpers import wipe_bytearray
        # Should not raise.
        wipe_bytearray(None)

    def test_wipes_empty_bytearray(self):
        from seedsigner.helpers.keycard.ui_helpers import wipe_bytearray
        buf = bytearray()
        wipe_bytearray(buf)
        self.assertEqual(buf, bytearray())


class TestOpenUnlockedSession(unittest.TestCase):
    """``open_unlocked_session`` SELECTs first, then looks up the cached
    pairing for the inserted card's instance_uid."""

    UID = b"\xAA" * 16

    def _patch_hardware(self, client):
        import seedsigner.helpers.keycard.client as kc_client
        import seedsigner.helpers.keycard.reader as kc_reader
        return (
            patch.object(kc_client, "KeycardClient", MagicMock(return_value=client)),
            patch.object(kc_reader, "wait_for_card", return_value="conn"),
        )

    def _select_info(self, uid=None, app_version=0x0301, key_uid=None):
        select_info = MagicMock()
        select_info.instance_uid = uid if uid is not None else self.UID
        # v3.1 by default — exercise the persistent path. Tests that need
        # the v3.2 ephemeral path pass app_version=0x0302 explicitly.
        select_info.app_version = app_version
        # SelectResponse.key_uid is empty until GENERATE_KEY/LOAD_KEY.
        # Default to a truthy 32-byte UID so existing tests skip the
        # "no master key" early-bail. Tests that exercise that branch
        # pass ``key_uid=b""`` explicitly.
        select_info.key_uid = key_uid if key_uid is not None else b"\xCC" * 32
        return select_info

    def test_raises_when_card_not_paired(self):
        from seedsigner.helpers.keycard import KeycardCardChangedError
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        client = MagicMock()
        client.select.return_value = self._select_info()

        view = MagicMock()
        view.controller.get_ephemeral_secret_for.return_value = None
        view.controller.get_pairing_for.return_value = None

        p1, p2 = self._patch_hardware(client)
        with p1, p2, self.assertRaises(KeycardCardChangedError) as ctx:
            open_unlocked_session(view, bytearray(b"123456"))
        self.assertEqual(ctx.exception.instance_uid, self.UID)
        # Ensure the secure channel was NOT opened on a card-changed error.
        client.open_secure_channel.assert_not_called()
        view.controller.last_keycard_uid = self.UID  # set by the helper

    def test_happy_path_uses_cached_pairing_for_inserted_card(self):
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        pairing = MagicMock(name="pairing")
        client = MagicMock()
        client.select.return_value = self._select_info()

        view = MagicMock()
        view.controller.get_ephemeral_secret_for.return_value = None
        view.controller.get_pairing_for.return_value = pairing
        pin = bytearray(b"123456")

        p1, p2 = self._patch_hardware(client)
        with p1, p2:
            returned_client, returned_pairing = open_unlocked_session(view, pin)

        self.assertIs(returned_pairing, pairing)
        self.assertIs(returned_client, client)
        view.controller.get_pairing_for.assert_called_once_with(self.UID)
        client.select.assert_called_once()
        client.open_secure_channel.assert_called_once_with(pairing)
        client.verify_pin.assert_called_once_with(bytes(pin))

    def test_v32_ephemeral_secret_triggers_repair_each_session(self):
        """v3.2 path: cached secret → re-PAIR with P2_EPHEMERAL each call."""
        from seedsigner.helpers.keycard.commands import PAIR_P2_EPHEMERAL
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        pairing = MagicMock(name="pairing")
        client = MagicMock()
        client.select.return_value = self._select_info(app_version=0x0302)
        client.pair.return_value = pairing

        secret = b"\x11" * 32
        view = MagicMock()
        view.controller.get_ephemeral_secret_for.return_value = secret
        # Ensure the persistent fallback isn't consulted.
        view.controller.get_pairing_for.return_value = None
        pin = bytearray(b"123456")

        p1, p2 = self._patch_hardware(client)
        with p1, p2:
            returned_client, returned_pairing = open_unlocked_session(view, pin)

        self.assertIs(returned_pairing, pairing)
        client.pair.assert_called_once_with(secret, p2=PAIR_P2_EPHEMERAL)
        client.open_secure_channel.assert_called_once_with(pairing)
        client.verify_pin.assert_called_once_with(bytes(pin))

    def test_v31_card_with_stale_ephemeral_secret_drops_it(self):
        """If the cached entry says ephemeral but the card is v3.1, drop it
        rather than silently allocating a persistent slot."""
        from seedsigner.helpers.keycard import KeycardCardChangedError
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        client = MagicMock()
        client.select.return_value = self._select_info(app_version=0x0301)

        view = MagicMock()
        view.controller.get_ephemeral_secret_for.return_value = b"\x22" * 32
        pin = bytearray(b"123456")

        p1, p2 = self._patch_hardware(client)
        with p1, p2, self.assertRaises(KeycardCardChangedError):
            open_unlocked_session(view, pin)

        view.controller.forget_ephemeral_secret_for.assert_called_once_with(self.UID)
        client.pair.assert_not_called()
        client.open_secure_channel.assert_not_called()

    def test_raises_no_master_key_when_key_uid_empty(self):
        """Initialised applet but no master key yet (post-INIT, before
        GENERATE_KEY/LOAD_KEY): SELECT returns empty ``key_uid``. The
        session helper must bail before any pair/SC/PIN attempt so the
        view can show "Generate key or import seed first." instead of a
        cryptic SW=0x6985 parse failure."""
        from seedsigner.helpers.keycard import KeycardNoMasterKeyError
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        client = MagicMock()
        client.select.return_value = self._select_info(
            app_version=0x0302, key_uid=b"",
        )

        view = MagicMock()
        pin = bytearray(b"123456")

        p1, p2 = self._patch_hardware(client)
        with p1, p2, self.assertRaises(KeycardNoMasterKeyError) as ctx:
            open_unlocked_session(view, pin)

        self.assertEqual(ctx.exception.instance_uid, self.UID)
        # No subsequent operations on the card.
        view.controller.get_ephemeral_secret_for.assert_not_called()
        view.controller.get_pairing_for.assert_not_called()
        client.pair.assert_not_called()
        client.open_secure_channel.assert_not_called()
        client.verify_pin.assert_not_called()

    def test_skips_master_key_check_when_require_key_false(self):
        """Generate / Import / ChangePIN / Unpair flows pass
        ``require_key=False`` because they either create the master key
        or do not depend on it. The helper must proceed to PAIR / OPEN /
        VERIFY_PIN even when ``key_uid`` is empty, instead of bailing
        with ``KeycardNoMasterKeyError`` — which previously made
        Generate-key-on-card unreachable on a freshly initialised card."""
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        pairing = MagicMock(name="pairing")
        client = MagicMock()
        client.select.return_value = self._select_info(
            app_version=0x0301, key_uid=b"",
        )

        view = MagicMock()
        view.controller.get_ephemeral_secret_for.return_value = None
        view.controller.get_pairing_for.return_value = pairing
        pin = bytearray(b"123456")

        p1, p2 = self._patch_hardware(client)
        with p1, p2:
            out_client, out_pairing = open_unlocked_session(
                view, pin, require_key=False,
            )

        self.assertIs(out_client, client)
        self.assertIs(out_pairing, pairing)
        client.open_secure_channel.assert_called_once_with(pairing)
        client.verify_pin.assert_called_once_with(bytes(pin))


class TestPinCacheBehaviour(unittest.TestCase):
    """``open_unlocked_session`` resolves the PIN from
    ``Controller.keycard_pins`` when the caller passes ``pin=None``,
    raising :class:`KeycardPinRequiredError` on miss. A successful
    VERIFY_PIN with a caller-provided value caches a copy. Bad PIN
    (SW=0x63CX) drops the cache before propagating."""

    UID = b"\xAA" * 16

    def _patch_hardware(self, client):
        import seedsigner.helpers.keycard.client as kc_client
        import seedsigner.helpers.keycard.reader as kc_reader
        return (
            patch.object(kc_client, "KeycardClient", MagicMock(return_value=client)),
            patch.object(kc_reader, "wait_for_card", return_value="conn"),
        )

    def _select_info(self):
        info = MagicMock()
        info.instance_uid = self.UID
        info.app_version = 0x0301
        return info

    def _mock_view(self, cached_pin=None):
        view = MagicMock()
        view.controller.get_ephemeral_secret_for.return_value = None
        view.controller.get_pairing_for.return_value = MagicMock(name="pairing")
        view.controller.get_pin_for.return_value = cached_pin
        return view

    def test_pin_none_with_no_cache_raises_required_error(self):
        from seedsigner.helpers.keycard import KeycardPinRequiredError
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        client = MagicMock()
        client.select.return_value = self._select_info()
        view = self._mock_view(cached_pin=None)

        p1, p2 = self._patch_hardware(client)
        with p1, p2, self.assertRaises(KeycardPinRequiredError) as ctx:
            open_unlocked_session(view, pin=None)
        self.assertEqual(ctx.exception.instance_uid, self.UID)
        client.verify_pin.assert_not_called()

    def test_pin_none_with_cached_pin_uses_it(self):
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        client = MagicMock()
        client.select.return_value = self._select_info()
        cached = bytearray(b"123456")
        view = self._mock_view(cached_pin=cached)

        p1, p2 = self._patch_hardware(client)
        with p1, p2:
            open_unlocked_session(view, pin=None)
        client.verify_pin.assert_called_once_with(bytes(cached))
        # Cached path should NOT re-cache (no extra set_pin_for call).
        view.controller.set_pin_for.assert_not_called()

    def test_provided_pin_is_cached_on_success(self):
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        client = MagicMock()
        client.select.return_value = self._select_info()
        view = self._mock_view(cached_pin=None)
        pin = bytearray(b"246810")

        p1, p2 = self._patch_hardware(client)
        with p1, p2:
            open_unlocked_session(view, pin=pin)
        view.controller.set_pin_for.assert_called_once_with(self.UID, pin)

    def test_bad_pin_sw_63cx_wipes_cache(self):
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        client = MagicMock()
        client.select.return_value = self._select_info()
        client.verify_pin.side_effect = APDUError(0x63C2, "PIN wrong")
        view = self._mock_view(cached_pin=bytearray(b"000000"))

        p1, p2 = self._patch_hardware(client)
        with p1, p2, self.assertRaises(APDUError):
            open_unlocked_session(view, pin=None)
        view.controller.forget_pin_for.assert_called_once_with(self.UID)
        view.controller.set_pin_for.assert_not_called()

    def test_other_apdu_error_does_not_wipe_cache(self):
        """A non-bad-PIN error (e.g. SW=0x6A82 applet-not-found) must
        leave the cache intact — it isn't evidence the PIN is wrong."""
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import open_unlocked_session

        client = MagicMock()
        client.select.return_value = self._select_info()
        client.verify_pin.side_effect = APDUError(0x6A82, "Applet not found")
        view = self._mock_view(cached_pin=bytearray(b"123456"))

        p1, p2 = self._patch_hardware(client)
        with p1, p2, self.assertRaises(APDUError):
            open_unlocked_session(view, pin=None)
        view.controller.forget_pin_for.assert_not_called()


class TestOpenUnlockedSessionCachedOrPrompt(unittest.TestCase):
    """``open_unlocked_session_cached_or_prompt`` tries the cache first,
    falls back to prompting the user, and translates a back-out into
    :class:`KeycardPinPromptCancelled`."""

    UID = b"\xAA" * 16

    def test_uses_cache_without_prompting(self):
        from seedsigner.helpers.keycard.ui_helpers import (
            open_unlocked_session_cached_or_prompt,
        )

        view = MagicMock()
        pairing = MagicMock(name="pairing")
        client = MagicMock()

        with patch(
            "seedsigner.helpers.keycard.ui_helpers.open_unlocked_session",
            return_value=(client, pairing),
        ) as mock_open, patch(
            "seedsigner.helpers.keycard.ui_helpers.prompt_for_pin"
        ) as mock_prompt:
            ret_client, ret_pairing = open_unlocked_session_cached_or_prompt(view)

        self.assertIs(ret_client, client)
        self.assertIs(ret_pairing, pairing)
        mock_open.assert_called_once_with(view, pin=None, require_key=True)
        mock_prompt.assert_not_called()

    def test_prompts_on_pin_required_then_succeeds(self):
        from seedsigner.helpers.keycard import KeycardPinRequiredError
        from seedsigner.helpers.keycard.ui_helpers import (
            open_unlocked_session_cached_or_prompt,
        )

        view = MagicMock()
        pairing = MagicMock(name="pairing")
        client = MagicMock()
        captured_pin = bytearray(b"123456")

        def open_side_effect(view, pin=None, *, require_key=True):
            if pin is None:
                raise KeycardPinRequiredError(self.UID)
            return client, pairing

        with patch(
            "seedsigner.helpers.keycard.ui_helpers.open_unlocked_session",
            side_effect=open_side_effect,
        ), patch(
            "seedsigner.helpers.keycard.ui_helpers.prompt_for_pin",
            return_value=captured_pin,
        ):
            ret_client, _ = open_unlocked_session_cached_or_prompt(view)

        self.assertIs(ret_client, client)
        # Wrapper must wipe its captured PIN before returning.
        self.assertEqual(captured_pin, bytearray(b"\x00" * 6))

    def test_user_cancel_raises_prompt_cancelled(self):
        from seedsigner.helpers.keycard import (
            KeycardPinPromptCancelled, KeycardPinRequiredError,
        )
        from seedsigner.helpers.keycard.ui_helpers import (
            open_unlocked_session_cached_or_prompt,
        )

        view = MagicMock()
        with patch(
            "seedsigner.helpers.keycard.ui_helpers.open_unlocked_session",
            side_effect=KeycardPinRequiredError(self.UID),
        ), patch(
            "seedsigner.helpers.keycard.ui_helpers.prompt_for_pin",
            return_value=None,
        ):
            with self.assertRaises(KeycardPinPromptCancelled):
                open_unlocked_session_cached_or_prompt(view)


class TestIdentifyInsertedCard(unittest.TestCase):
    def test_returns_uid_and_updates_controller(self):
        from seedsigner.helpers.keycard.ui_helpers import identify_inserted_card

        client = MagicMock()
        info = MagicMock()
        info.instance_uid = b"\xBB" * 16
        client.select.return_value = info

        view = MagicMock()

        import seedsigner.helpers.keycard.client as kc_client
        import seedsigner.helpers.keycard.reader as kc_reader
        with patch.object(kc_client, "KeycardClient", MagicMock(return_value=client)), \
             patch.object(kc_reader, "wait_for_card", return_value="conn"):
            returned_client, uid = identify_inserted_card(view)

        self.assertIs(returned_client, client)
        self.assertEqual(uid, b"\xBB" * 16)
        self.assertEqual(view.controller.last_keycard_uid, b"\xBB" * 16)


class TestClassifyCardError(unittest.TestCase):
    """``classify_card_error`` maps raw exceptions from a Keycard flow
    onto user-friendly ``(title, body)`` pairs so the UI doesn't show
    misleading "Card not reachable" titles for, e.g., a successful
    SELECT that returned SW=0x6A82 (applet not at active AID)."""

    def test_no_reader(self):
        from seedsigner.helpers.keycard.reader import NoReaderError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(NoReaderError("none"))
        self.assertEqual(title, "No reader")
        self.assertIn("Connect", body)

    def test_no_card(self):
        from seedsigner.helpers.keycard.reader import NoCardError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(NoCardError("timeout"))
        self.assertEqual(title, "No card")
        self.assertIn("Insert", body)

    def test_card_changed(self):
        from seedsigner.helpers.keycard import KeycardCardChangedError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(KeycardCardChangedError(b"\xAA" * 16))
        self.assertEqual(title, "Card changed")
        self.assertIn("Pair", body)

    def test_no_master_key(self):
        from seedsigner.helpers.keycard import KeycardNoMasterKeyError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(KeycardNoMasterKeyError(b"\xAA" * 16))
        self.assertEqual(title, "No key on card")
        self.assertIn("Generate", body)
        self.assertIn("import seed", body)

    def test_secure_channel_error(self):
        from seedsigner.helpers.keycard.secure_channel import SecureChannelError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(SecureChannelError("mac mismatch"))
        self.assertEqual(title, "Secure channel")
        # Body should surface the underlying reason so the user/dev
        # can distinguish e.g. MAC mismatch from a length error.
        self.assertIn("SC open failed", body)
        self.assertIn("mac mismatch", body)

    def test_pairing_storage_error(self):
        from seedsigner.helpers.keycard.pairing_storage import PairingStorageError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(PairingStorageError("corrupt blob"))
        self.assertEqual(title, "Storage error")
        self.assertEqual(body, "corrupt blob")

    def test_apdu_applet_not_found(self):
        """SW=0x6A82 is the headline bug: card *is* reachable, applet
        is not at the active AID. Should NOT say 'Card not reachable'."""
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(APDUError(0x6A82, "File not found"))
        self.assertEqual(title, "Applet not found")
        # The body should point the user at the new menu path
        # (Manage › Instances) so they can switch active AID.
        self.assertIn("Manage", body)
        self.assertIn("Instances", body)

    def test_apdu_security_status(self):
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(APDUError(0x6982, "Security status"))
        self.assertEqual(title, "Card refused")
        self.assertIn("6982", body)

    def test_apdu_conditions_of_use(self):
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, _ = classify_card_error(APDUError(0x6985, "Conditions of use"))
        self.assertEqual(title, "Card refused")

    def test_apdu_wrong_pin_with_tries_left(self):
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(APDUError(0x63C2, "Wrong PIN"))
        self.assertEqual(title, "Wrong PIN")
        self.assertIn("2 tries left", body)

    def test_apdu_not_supported(self):
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(APDUError(0x6D00, "INS not supported"))
        self.assertEqual(title, "Not supported")
        self.assertIn("not implement", body)

    def test_apdu_other_uses_default_title(self):
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(
            APDUError(0x6A80, "Bad params"),
            default_title="Generate failed",
        )
        self.assertEqual(title, "Generate failed")
        self.assertIn("6A80", body)

    def test_unknown_exception_uses_default_title(self):
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, body = classify_card_error(
            RuntimeError("kaboom"),
            default_title="Signing failed",
        )
        self.assertEqual(title, "Signing failed")
        self.assertEqual(body, "kaboom")

    def test_default_title_default_value(self):
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, _ = classify_card_error(RuntimeError("x"))
        self.assertEqual(title, "Card error")

    def test_body_truncated_to_100_chars(self):
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        long_msg = "x" * 250
        _, body = classify_card_error(RuntimeError(long_msg))
        self.assertEqual(len(body), 100)

    def test_apdu_success_falls_through_to_default(self):
        """0x9000 should never reach this helper, but if it does we
        must not crash and must fall back to the default title."""
        from seedsigner.helpers.keycard.commands import APDUError
        from seedsigner.helpers.keycard.ui_helpers import classify_card_error
        title, _ = classify_card_error(
            APDUError(0x9000, "Success"),
            default_title="Generate failed",
        )
        self.assertEqual(title, "Generate failed")


class TestPromptForPinKeyboard(unittest.TestCase):
    """``prompt_for_pin`` should open the digits keyboard, not abc."""

    def test_passes_digits_initial_keyboard(self):
        from seedsigner.gui.screens import seed_screens
        from seedsigner.helpers.keycard import ui_helpers

        expected_digits_const = seed_screens.SeedAddPassphraseScreen.KEYBOARD__DIGITS_BUTTON_TEXT
        captured = {}

        class FakeScreen:
            # Mirror the keyboard-mode constants so the class-attribute
            # lookup in prompt_for_pin still resolves after we patch the
            # class binding on seed_screens.
            KEYBOARD__DIGITS_BUTTON_TEXT = expected_digits_const

            def __init__(self, *args, **kwargs):
                captured["kwargs"] = kwargs

            def display(self):
                # Simulate user backing out so prompt_for_pin returns None.
                return {"is_back_button": True}

        with patch.object(seed_screens, "SeedAddPassphraseScreen", FakeScreen):
            result = ui_helpers.prompt_for_pin(MagicMock(), "Card PIN")

        self.assertIsNone(result)
        self.assertEqual(captured["kwargs"].get("initial_keyboard"), expected_digits_const)
        self.assertEqual(captured["kwargs"].get("title"), "Card PIN")


if __name__ == "__main__":
    unittest.main()
