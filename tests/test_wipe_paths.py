# pylint: disable=missing-function-docstring
# Must import base before any seedsigner modules
from base import BaseTest

from seedsigner.models.seed import Slip39Seed, XprvSeed
from seedsigner.models.seed_storage import SeedStorage


XPRV = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)

# One SLIP-39 share, threshold 1 of 1 (same fixture style as tests/test_seed.py)
SLIP39_SHARE = (
    "testify swimming academic academic column loyalty smear include exotic "
    "bedroom exotic wrist lobe cover grief golden smart junior estimate learn"
)

# A mainnet WIF private key (test vector; never funded)
WIF = "L1aW4aubDFB7yfras2S1mN3bqg9nwySY8nkoLmJebSLD5BWv3ENZ"

# A 12-word BIP-39 mnemonic, entered one word at a time below
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()


def fresh(text: str) -> str:
    """Return a private copy of a fixture string.

    wipe() zeroes a str's buffer in place, so handing a module-level constant
    straight to a Seed destroys the fixture for every later test in the run.
    """
    return "".join(list(text))


def run_inactivity_wipe(controller, monkeypatch):
    """Fire the inactivity wipe with the toast stubbed out."""
    import seedsigner.gui.toast as gui_toast

    monkeypatch.setattr(controller, "activate_toast", lambda toast: None)
    monkeypatch.setattr(gui_toast, "InfoToast", lambda label_text=None: label_text)
    controller.handle_wipe_timeout()


class DummyLoadingScreenThread:
    def __init__(self, *args, **kwargs):
        pass

    def start(self):
        pass

    def stop(self):
        pass


class TestFixtureCopiesAreIndependent(BaseTest):
    """A wiped copy must not take the shared fixture down with it."""

    def test_fresh_returns_a_separate_object(self):
        copy = fresh(XPRV)

        assert copy == XPRV
        assert copy is not XPRV

    def test_wiping_a_copy_leaves_the_fixture_intact(self):
        seed = XprvSeed(fresh(XPRV))

        seed.wipe()

        assert XPRV.startswith("xprv")
        assert SLIP39_SHARE.startswith("testify")


class TestSeedSubclassWipe(BaseTest):
    """Seed.wipe() must work for every Seed subclass, not just BIP-39 seeds."""

    def test_xprv_seed_wipe_does_not_raise(self):
        seed = XprvSeed(fresh(XPRV))

        seed.wipe()

        assert seed._xprv == ""
        assert seed._root is None

    def test_xprv_seed_wipe_zeroes_the_root_key(self):
        # The HDKey parsed from the xprv holds the key in bytes of its own:
        # clearing the string and dropping _root leaves those in freed memory.
        seed = XprvSeed(fresh(XPRV))
        secret = seed._root.key._secret
        chain_code = seed._root.chain_code

        seed.wipe()

        assert secret == bytes(len(secret))
        assert chain_code == bytes(len(chain_code))

    def test_slip39_seed_wipe_does_not_raise(self, monkeypatch):
        monkeypatch.setattr(
            "seedsigner.gui.screens.screen.LoadingScreenThread", DummyLoadingScreenThread
        )
        seed = Slip39Seed(mnemonics=[fresh(SLIP39_SHARE)])

        seed.wipe()

        assert seed._shares == []
        assert seed.seed_bytes is None
        assert seed.master_secret is None


class TestClearPendingSeed(BaseTest):
    """A pending seed must be dropped even when wiping it fails."""

    def test_pending_seed_is_dropped_when_wipe_raises(self):
        class ExplodingSeed:
            def wipe(self):
                raise AttributeError("no _mnemonic")

        storage = SeedStorage()
        storage.set_pending_seed(ExplodingSeed())

        # Best-effort, like Controller.discard_seed(): the caller is dropping a
        # secret and must not be left holding it because the wipe failed.
        storage.clear_pending_seed()

        assert storage.pending_seed is None


class TestWipeTimeoutCompletes(BaseTest):
    """One failing wipe must not skip the rest of the inactivity cleanup."""

    def test_remaining_data_is_cleared_when_a_seed_wipe_raises(self, monkeypatch):
        from types import SimpleNamespace
        from seedsigner.controller import Controller

        controller = Controller.get_instance()

        class ExplodingSeed:
            def wipe(self):
                raise AttributeError("no _mnemonic")

        def exploding_clear_pending_seed():
            raise AttributeError("no _mnemonic")

        controller._storage = SimpleNamespace(
            seeds=[ExplodingSeed()], clear_pending_seed=exploding_clear_pending_seed
        )
        controller._storage2 = None
        controller.password_generator_entropy_cache = {"entropy_bytes": bytearray(b"\x00\x01")}
        controller.psbt_seed = "not None"

        run_inactivity_wipe(controller, monkeypatch)

        assert controller.password_generator_entropy_cache is None
        assert controller.psbt_seed is None
        assert controller.auto_wiped is True

    def test_a_failing_step_does_not_skip_the_later_ones(self, monkeypatch):
        from seedsigner.controller import Controller

        class ExplodingDict(dict):
            def __getattribute__(self, name):
                if name in ("get", "values", "items", "clear"):
                    raise RuntimeError("boom")
                return super().__getattribute__(name)

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        controller.javacard_keys = ExplodingDict(type="single", key=fresh("00" * 16))
        entropy_bytes = bytearray(b"\x11\x22\x33\x44")
        controller.password_generator_entropy_cache = {"entropy_bytes": entropy_bytes}
        admin_pin = fresh("12345678")
        controller.GPG_Admin_PIN = admin_pin

        run_inactivity_wipe(controller, monkeypatch)

        assert controller.javacard_keys is None
        assert entropy_bytes == bytearray(len(entropy_bytes))
        assert admin_pin == "\x00" * len(admin_pin)
        assert controller.auto_wiped is True


class TestWipeTimeoutClearsPartialEntry(BaseTest):
    """Half-entered secrets live in SeedStorage, not in a Seed; wipe those too."""

    def test_partially_entered_mnemonic_and_slip39_shares_are_cleared(self, monkeypatch):
        from seedsigner.controller import Controller

        controller = Controller.get_instance()
        storage = SeedStorage()

        storage.init_pending_mnemonic(num_words=12)
        for index, word in enumerate(MNEMONIC):
            storage.update_pending_mnemonic(word, index)

        storage.add_slip39_share_mnemonic(fresh(SLIP39_SHARE))

        controller._storage = storage
        controller._storage2 = None

        run_inactivity_wipe(controller, monkeypatch)

        assert storage.pending_mnemonic == []
        assert storage._pending_slip39_share == []
        assert storage._pending_slip39_shares == []
        assert storage._slip39_first_share is None


class TestWipeTimeoutClearsCardAndKeyMaterial(BaseTest):
    """Secrets that never live in a Seed are missed unless named explicitly."""

    def test_javacard_keys_are_wiped(self, monkeypatch):
        from seedsigner.controller import Controller

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        enc = fresh("404142434445464748494a4b4c4d4e4f")
        controller.javacard_keys = {"type": fresh("set"), "enc": enc, "mac": enc, "dek": enc}

        run_inactivity_wipe(controller, monkeypatch)

        assert controller.javacard_keys is None
        assert enc == "\x00" * len(enc)

    def test_javacard_key_type_is_left_intact(self, monkeypatch):
        # The type tag is a code constant in production. Only the keys are
        # secret; zeroing the tag in place corrupts it for the whole process.
        from seedsigner.controller import Controller

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        key_type = fresh("single")
        key = fresh("00112233445566778899AABBCCDDEEFF")
        controller.javacard_keys = {"type": key_type, "key": key}

        run_inactivity_wipe(controller, monkeypatch)

        assert key == "\x00" * len(key)
        assert key_type == "single"

    def test_wif_psbt_seed_is_wiped(self, monkeypatch):
        from seedsigner.controller import Controller
        from seedsigner.models.wif import WIFKey

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        key = WIFKey(fresh(WIF))
        secret = key.privkey._secret
        controller.psbt_seed = key

        run_inactivity_wipe(controller, monkeypatch)

        assert controller.psbt_seed is None
        assert key.wif == ""
        assert secret == bytes(len(secret))

    def test_password_generator_entropy_is_zeroed_not_just_dropped(self, monkeypatch):
        from seedsigner.controller import Controller

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        entropy_bytes = bytearray(b"\x11\x22\x33\x44")
        roll_data = fresh("123456123456")
        controller.password_generator_entropy_cache = {
            "roll_data": roll_data,
            "entropy_bytes": entropy_bytes,
        }

        run_inactivity_wipe(controller, monkeypatch)

        assert controller.password_generator_entropy_cache is None
        assert entropy_bytes == bytearray(len(entropy_bytes))
        assert roll_data == "\x00" * len(roll_data)

    def test_password_entropy_labels_are_left_intact(self, monkeypatch):
        # password_type and entropy_source are module constants in
        # production; only the rolls and the entropy bytes are secret.
        from seedsigner.controller import Controller

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        password_type = fresh("dice_rolls")
        entropy_source = fresh("dice")
        roll_data = fresh("123456123456")
        controller.password_generator_entropy_cache = {
            "password_type": password_type,
            "strength_bits": 128,
            "entropy_source": entropy_source,
            "word_count": None,
            "roll_data": roll_data,
            "entropy_bytes": None,
        }

        run_inactivity_wipe(controller, monkeypatch)

        assert roll_data == "\x00" * len(roll_data)
        assert password_type == "dice_rolls"
        assert entropy_source == "dice"

    def test_code_constants_in_the_dicts_survive(self, monkeypatch):
        # The same check through the code that builds the dicts. On CPython
        # < 3.12 a code constant is not immortal and has fewer references than
        # the shared-string limit, so wiping it in place would break the key
        # file parser and every comparison with the constant until reboot.
        # 3.12+ refuses to wipe the constants anyway: only the 3.10 lane, the
        # Python the device runs, can fail here.
        from seedsigner.controller import Controller
        from seedsigner.views import tools_views
        from seedsigner.views.smartcard_views import _parse_javacard_keys

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        key_file = "single: 00112233445566778899AABBCCDDEEFF"
        controller.javacard_keys = _parse_javacard_keys(key_file)
        tools_views._cache_password_entropy(
            controller,
            password_type=tools_views.PASSWORD_TYPE_DICE_ROLLS,
            strength_bits=128,
            entropy_source=tools_views.PASSWORD_ENTROPY_DICE,
            word_count=None,
            roll_data=fresh("123456123456"),
        )

        run_inactivity_wipe(controller, monkeypatch)

        assert _parse_javacard_keys(key_file)["type"] == fresh("single")
        assert tools_views.PASSWORD_TYPE_DICE_ROLLS == fresh("dice_rolls")
        assert tools_views.PASSWORD_ENTROPY_DICE == fresh("dice")

    def test_encryptedqr_key_is_zeroed(self, monkeypatch):
        from seedsigner.controller import Controller
        from seedsigner.models.encryptedqr import EncryptedQR, EncryptedQRStorage

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        storage2 = EncryptedQRStorage()
        encryptedqr = EncryptedQR()
        encryption_key = fresh("correct horse battery staple")
        encryptedqr.set_encryption_key(encryption_key)
        storage2.set_encryptedqr(encryptedqr)
        controller._storage2 = storage2

        run_inactivity_wipe(controller, monkeypatch)

        assert storage2.encryptedqr is None
        assert encryption_key == "\x00" * len(encryption_key)


class TestWipeTimeoutClearsPsbtParserKeys(BaseTest):
    """The psbt parser keeps a root key of its own, apart from psbt_seed."""

    def test_parser_root_derived_from_the_seed_is_zeroed(self, monkeypatch):
        # A BIP-39 seed hands the parser a new HDKey, so wiping the seed does
        # not reach the parser's copy of the master key.
        from seedsigner.controller import Controller
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.models.seed import Seed

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        seed = Seed([fresh(word) for word in MNEMONIC])
        parser = PSBTParser(None, seed=seed)
        parser._set_root()
        secret = parser.root.key._secret
        chain_code = parser.root.chain_code
        controller.psbt_seed = seed
        controller.psbt_parser = parser

        run_inactivity_wipe(controller, monkeypatch)

        assert controller.psbt_parser is None
        assert secret == bytes(len(secret))
        assert chain_code == bytes(len(chain_code))

    def test_wif_key_held_only_by_the_parser_is_zeroed(self, monkeypatch):
        # Back from the psbt overview, and a signature that did not verify,
        # both set psbt_seed = None while the parser still holds the key.
        from seedsigner.controller import Controller
        from seedsigner.models.psbt_parser import PSBTParser
        from seedsigner.models.wif import WIFKey

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        key = WIFKey(fresh(WIF))
        secret = key.privkey._secret
        parser = PSBTParser(None, seed=key)
        parser._set_root()
        controller.psbt_seed = None
        controller.psbt_parser = parser

        run_inactivity_wipe(controller, monkeypatch)

        assert key.wif == ""
        assert secret == bytes(len(secret))

    def test_public_parser_root_is_left_intact(self, monkeypatch):
        # The card flow builds the parser from the card's xpub. It is not
        # secret, so there is nothing to zero.
        from embit import bip32
        from seedsigner.controller import Controller
        from seedsigner.models.psbt_parser import PSBTParser

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        xpub = bip32.HDKey.from_string(fresh(XPRV)).to_public().to_string()
        root = bip32.HDKey.from_string(xpub)
        controller.psbt_parser = PSBTParser(None, root=root)

        run_inactivity_wipe(controller, monkeypatch)

        assert root.to_string() == xpub


class TestWipeTimeoutClearsSmartcardSecrets(BaseTest):
    """Card PINs and unlock secrets are lists of ints; zero them, not just drop them."""

    def test_card_pins_and_unlock_secrets_are_zeroed(self, monkeypatch):
        from types import SimpleNamespace
        from seedsigner.controller import Controller
        from seedsigner.helpers import seedkeeper_utils

        controller = Controller.get_instance()
        controller._storage = SeedStorage()
        controller._storage2 = None
        card_pin = list(b"123456")
        connector_pin = list(b"123456")
        controller.Satochip_PIN = card_pin
        controller.Satochip_Connector = SimpleNamespace(pin=connector_pin)
        seedkeeper_utils.cache_satodime_unlock_secret(
            controller, "card", bytes(range(1, 21)), nickname="name"
        )
        unlock_secret = controller.Satodime_unlock_secrets["card"]
        named_unlock_secret = controller.Satodime_unlock_nicknames["name"][1]
        admin_pin = fresh("12345678")
        controller.GPG_Admin_PIN = admin_pin

        run_inactivity_wipe(controller, monkeypatch)

        assert card_pin == []
        assert connector_pin == []
        assert unlock_secret == []
        assert named_unlock_secret == []
        assert admin_pin == "\x00" * len(admin_pin)
        assert controller.Satochip_PIN is None
        assert controller.Satochip_Connector is None
        assert controller.Satodime_unlock_secrets is None
        assert controller.Satodime_unlock_nicknames is None
        assert controller.GPG_Admin_PIN is None


class TestWifKeyWipe(BaseTest):
    """WIFKey holds a private key, so it needs the same wipe() as a Seed."""

    def test_wipe_clears_the_wif_and_the_secret(self):
        from seedsigner.models.wif import WIFKey

        key = WIFKey(fresh(WIF))
        secret = key.privkey._secret

        key.wipe()

        assert key.wif == ""
        assert key.privkey is None
        assert secret == bytes(len(secret))
