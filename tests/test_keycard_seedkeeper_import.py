"""B3 — Import a seed from a SeedKeeper applet into a Keycard.

Covers the parts that are unit-testable without two physical cards:
the shared secret-decode helper, the chooser routing into the import
chain, and the security invariants (independent word copies + wipe leaves
the global BIP-39 wordlist intact, pending seed wiped on user-exit).

The full swap → LOAD_KEY round trip needs hardware (two cards) — see
CLAUDE.md "Hardware verification".
"""
import unittest
from unittest.mock import MagicMock, patch


class TestDecodeSeedkeeperSeedSecret(unittest.TestCase):
    """``seedkeeper_utils.decode_seedkeeper_seed_secret`` turns an exported
    Seedkeeper secret into ``(mnemonic, passphrase)`` or ``None``."""

    MNEMONIC12 = (
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about"
    )

    # conftest mocks pysatochip.JCconstants, so the real code maps the
    # numeric type/wordlist codes from there. Inject the real maps for the
    # decode under test.
    REAL_TYPES = {
        16: "Masterseed", 48: "BIP39 mnemonic", 49: "BIP39 mnemonic v2",
        144: "Password",
    }
    REAL_WORDLISTS = {0: "english"}

    def _decode(self, secret_dict, subtype=0):
        import sys
        from seedsigner.helpers import seedkeeper_utils as su
        # conftest mocks pysatochip.JCconstants. SEEDKEEPER_DIC_TYPE is bound
        # in seedkeeper_utils' namespace; BIP39_WORDLIST_DIC is imported lazily
        # from the module the conftest put in sys.modules. Inject the real maps
        # and restore by *re-setting* (never delattr — mock.patch would delete
        # the auto-attribute on teardown and break later from-imports).
        jc = sys.modules["pysatochip.JCconstants"]
        saved_wl = jc.BIP39_WORDLIST_DIC
        saved_ty = su.SEEDKEEPER_DIC_TYPE
        jc.BIP39_WORDLIST_DIC = self.REAL_WORDLISTS
        su.SEEDKEEPER_DIC_TYPE = self.REAL_TYPES
        try:
            return su.decode_seedkeeper_seed_secret(secret_dict, subtype)
        finally:
            jc.BIP39_WORDLIST_DIC = saved_wl
            su.SEEDKEEPER_DIC_TYPE = saved_ty

    def test_bip39_v1(self):
        passphrase = "trezor"
        raw = self.MNEMONIC12 + "\x00" + passphrase  # sep at raw[len(mnemonic)]
        secret = b"\x01" + raw.encode("utf-8")  # leading byte skipped by [1:]
        secret_dict = {
            "type": 48,  # "BIP39 mnemonic"
            "secret": secret.hex(),
            "secret_list": [len(self.MNEMONIC12)],
        }
        mnemonic, pp = self._decode(secret_dict)
        self.assertEqual(mnemonic, self.MNEMONIC12)
        self.assertEqual(pp, passphrase)

    def test_bip39_v1_empty_passphrase(self):
        raw = self.MNEMONIC12 + "\x00"  # trailing null stripped → empty pp
        secret = b"\x01" + raw.encode("utf-8")
        secret_dict = {
            "type": 48,
            "secret": secret.hex(),
            "secret_list": [len(self.MNEMONIC12)],
        }
        mnemonic, pp = self._decode(secret_dict)
        self.assertEqual(mnemonic, self.MNEMONIC12)
        self.assertEqual(pp, "")

    def test_masterseed_v2(self):
        # The entropy->mnemonic step is delegated to the external ``mnemonic``
        # lib (its wordlist files aren't available in CI), so mock it and
        # assert OUR parsing extracts the right entropy / wordlist / passphrase.
        import mnemonic as mnemonic_mod
        entropy = b"\x11" * 16
        masterseed = b"\xAA" * 4  # skipped by the decoder
        passphrase = b"pass"
        raw = (
            bytes([len(masterseed)]) + masterseed
            + bytes([0])               # wordlist id 0 = english
            + bytes([len(entropy)]) + entropy
            + bytes([len(passphrase)]) + passphrase
        )
        secret_dict = {"type": 16, "secret": raw.hex(), "secret_list": []}

        fake = MagicMock()
        fake.to_mnemonic.return_value = self.MNEMONIC12
        fake_ctor = MagicMock(return_value=fake)
        with patch.object(mnemonic_mod, "Mnemonic", fake_ctor):
            mnemonic, pp = self._decode(secret_dict, subtype=0x01)

        self.assertEqual(mnemonic, self.MNEMONIC12)
        self.assertEqual(pp, "pass")
        fake_ctor.assert_called_once_with("english")
        fake.to_mnemonic.assert_called_once_with(entropy)

    def test_unsupported_type_returns_none(self):
        secret_dict = {"type": 144, "secret": "00", "secret_list": [0]}  # Password
        self.assertIsNone(self._decode(secret_dict))

    def test_masterseed_without_subtype_returns_none(self):
        # A raw Masterseed (no appended BIP39 record) can't be re-imported.
        secret_dict = {"type": 16, "secret": "00", "secret_list": []}
        self.assertIsNone(self._decode(secret_dict, subtype=0x00))

    # --- malformed / hostile card payloads must yield None, never raise -----

    def test_masterseed_v2_truncated_returns_none(self):
        # A 1-byte secret can't carry a full masterseed-v2 record.
        secret_dict = {"type": 16, "secret": "00", "secret_list": []}
        self.assertIsNone(self._decode(secret_dict, subtype=0x01))

    def test_masterseed_v2_invalid_entropy_length_returns_none(self):
        # ent_size = 7 is not a legal BIP-39 entropy length → rejected before
        # ever reaching the mnemonic library (so no mock needed, no raise).
        masterseed = b"\xAA" * 4
        raw = (
            bytes([len(masterseed)]) + masterseed
            + bytes([0])                 # english
            + bytes([7]) + b"\x00" * 7   # bogus 7-byte entropy
            + bytes([0])                 # empty passphrase
        )
        secret_dict = {"type": 16, "secret": raw.hex(), "secret_list": []}
        self.assertIsNone(self._decode(secret_dict, subtype=0x01))

    def test_masterseed_v2_entropy_overruns_buffer_returns_none(self):
        # ent_size claims 32 bytes but the buffer holds only 4.
        masterseed = b"\xAA" * 4
        raw = (
            bytes([len(masterseed)]) + masterseed
            + bytes([0])
            + bytes([32]) + b"\x11" * 4   # truncated entropy
        )
        secret_dict = {"type": 16, "secret": raw.hex(), "secret_list": []}
        self.assertIsNone(self._decode(secret_dict, subtype=0x01))

    def test_masterseed_v2_passphrase_overruns_buffer_returns_none(self):
        import mnemonic as mnemonic_mod
        entropy = b"\x11" * 16
        masterseed = b"\xAA" * 4
        raw = (
            bytes([len(masterseed)]) + masterseed
            + bytes([0])
            + bytes([len(entropy)]) + entropy
            + bytes([40]) + b"short"      # pp_size lies (40 > 5 remaining)
        )
        secret_dict = {"type": 16, "secret": raw.hex(), "secret_list": []}
        fake = MagicMock()
        fake.to_mnemonic.return_value = self.MNEMONIC12
        with patch.object(mnemonic_mod, "Mnemonic", MagicMock(return_value=fake)):
            self.assertIsNone(self._decode(secret_dict, subtype=0x01))

    def test_masterseed_v2_missing_passphrase_byte_ok(self):
        # No trailing passphrase length byte at all means "no passphrase",
        # which is a valid seed, not a corrupt secret.
        import mnemonic as mnemonic_mod
        entropy = b"\x11" * 16
        masterseed = b"\xAA" * 4
        raw = (
            bytes([len(masterseed)]) + masterseed
            + bytes([0])
            + bytes([len(entropy)]) + entropy
            # deliberately no passphrase length byte
        )
        secret_dict = {"type": 16, "secret": raw.hex(), "secret_list": []}
        fake = MagicMock()
        fake.to_mnemonic.return_value = self.MNEMONIC12
        with patch.object(mnemonic_mod, "Mnemonic", MagicMock(return_value=fake)):
            mnemonic, pp = self._decode(secret_dict, subtype=0x01)
        self.assertEqual(mnemonic, self.MNEMONIC12)
        self.assertEqual(pp, "")

    def test_masterseed_v2_to_mnemonic_raises_returns_none(self):
        import mnemonic as mnemonic_mod
        entropy = b"\x11" * 16
        masterseed = b"\xAA" * 4
        raw = (
            bytes([len(masterseed)]) + masterseed
            + bytes([0])
            + bytes([len(entropy)]) + entropy
            + bytes([0])
        )
        secret_dict = {"type": 16, "secret": raw.hex(), "secret_list": []}
        fake = MagicMock()
        fake.to_mnemonic.side_effect = ValueError("bad entropy")
        with patch.object(mnemonic_mod, "Mnemonic", MagicMock(return_value=fake)):
            self.assertIsNone(self._decode(secret_dict, subtype=0x01))

    def test_masterseed_v2_bad_hex_returns_none(self):
        secret_dict = {"type": 16, "secret": "zzzz", "secret_list": []}
        self.assertIsNone(self._decode(secret_dict, subtype=0x01))

    def test_masterseed_v2_missing_secret_key_returns_none(self):
        secret_dict = {"type": 16, "secret_list": []}
        self.assertIsNone(self._decode(secret_dict, subtype=0x01))

    def test_bip39_v1_empty_secret_list_returns_none(self):
        secret = b"\x01" + self.MNEMONIC12.encode("utf-8")
        secret_dict = {"type": 48, "secret": secret.hex(), "secret_list": []}
        self.assertIsNone(self._decode(secret_dict))

    def test_bip39_v1_oversized_size_returns_none(self):
        secret = b"\x01" + b"abc"
        secret_dict = {"type": 48, "secret": secret.hex(), "secret_list": [999]}
        self.assertIsNone(self._decode(secret_dict))


class TestImportChooserRouting(unittest.TestCase):
    """The "From SeedKeeper" source routes into the dedicated swap chain."""

    def test_from_seedkeeper_routes_to_insert(self):
        from seedsigner.views.keycard_views import (
            ToolsKeycardImportSeedView,
            ToolsKeycardImportSeedkeeperInsertView,
        )
        view = ToolsKeycardImportSeedView.__new__(ToolsKeycardImportSeedView)
        view.controller = MagicMock()
        # 1st screen = DireWarning (Continue=0), 2nd = Source chooser; index 2
        # is "From SeedKeeper" (TYPE_WORDS, HEX, FROM_SEEDKEEPER, SCAN).
        view.run_screen = MagicMock(side_effect=[0, 2])
        dest = view.run()
        self.assertIs(dest.View_cls, ToolsKeycardImportSeedkeeperInsertView)


class TestImportWordlistIntegrityAndWipe(unittest.TestCase):
    """Words stashed for the swap must be independent copies, and wiping the
    pending state must leave the global BIP-39 wordlist intact (CLAUDE.md
    shared-wordlist rule)."""

    def test_stash_then_wipe_keeps_wordlist_intact(self):
        from embit import bip39
        from seedsigner.helpers.secure_delete import wipe_list

        original_first = bip39.WORDLIST[0]
        # Mnemonic that uses real wordlist words; decode-style split + copy.
        mnemonic_str = TestDecodeSeedkeeperSeedSecret.MNEMONIC12
        words = ["".join(w) for w in mnemonic_str.split()]
        # The stored words must not BE the wordlist objects.
        for w in words:
            if w in bip39.WORDLIST:
                self.assertIsNot(w, bip39.WORDLIST[bip39.WORDLIST.index(w)])
        wipe_list(words)
        # Global wordlist survives the wipe.
        self.assertEqual(bip39.WORDLIST[0], original_first)
        self.assertEqual(bip39.WORDLIST[0], "abandon")

    def test_reinsert_cancel_wipes_pending(self):
        """Backing out of the Keycard re-insert step wipes the stashed seed."""
        from seedsigner.views.keycard_views import (
            ToolsKeycardImportSeedkeeperReinsertView,
        )
        from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
        from seedsigner.views import keycard_views

        view = ToolsKeycardImportSeedkeeperReinsertView.__new__(
            ToolsKeycardImportSeedkeeperReinsertView,
        )
        view.controller = MagicMock()
        view.controller.pending_keycard_mnemonic = ["abandon", "about"]
        view.controller.pending_keycard_passphrase = bytearray(b"x")
        view.run_screen = MagicMock(return_value=RET_CODE__BACK_BUTTON)

        with patch.object(keycard_views, "_wipe_pending_setup_state") as wipe:
            dest = view.run()
        wipe.assert_called_once_with(view.controller)
        # Routes back to the Keycard menu (user-driven cancel).
        from seedsigner.views.keycard_views import ToolsKeycardMenuView
        self.assertIs(dest.View_cls, ToolsKeycardMenuView)


class TestTeardownSatochipConnector(unittest.TestCase):
    """``seedkeeper_utils.teardown_satochip_connector`` must drop the card
    connection AND unregister the connector's RemovalObserver from pyscard's
    singleton CardMonitor — pysatochip's ``card_disconnect`` only does the
    former, leaving a live observer that re-grabs the next inserted card and
    starves a fresh connector across a swap (the "Unable to find seedkeeper"
    failure on the 2nd card of a "Both" backup)."""

    def test_disconnects_and_removes_observer(self):
        from seedsigner.helpers import seedkeeper_utils as su

        conn = MagicMock()
        su.teardown_satochip_connector(conn)
        conn.card_disconnect.assert_called_once_with()
        conn.cardmonitor.deleteObserver.assert_called_once_with(conn.cardobserver)

    def test_none_is_a_noop(self):
        from seedsigner.helpers import seedkeeper_utils as su

        su.teardown_satochip_connector(None)  # must not raise

    def test_swallows_value_error_from_delete_observer(self):
        """``deleteObserver`` raises ``ValueError`` if the observer was already
        removed (double teardown). The helper must swallow it."""
        from seedsigner.helpers import seedkeeper_utils as su

        conn = MagicMock()
        conn.cardmonitor.deleteObserver.side_effect = ValueError
        su.teardown_satochip_connector(conn)  # must not raise
        conn.card_disconnect.assert_called_once_with()

    def test_disconnect_smartcard_connections_routes_through_teardown(self):
        from seedsigner.helpers import seedkeeper_utils as su

        controller = MagicMock()
        conn = MagicMock()
        controller.Satochip_Connector = conn
        with patch("subprocess.run"):
            su.disconnect_smartcard_connections(controller)
        conn.card_disconnect.assert_called_once_with()
        conn.cardmonitor.deleteObserver.assert_called_once_with(conn.cardobserver)
        self.assertIsNone(controller.Satochip_Connector)


if __name__ == "__main__":
    unittest.main()
