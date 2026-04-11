import os
import json
import pytest
from unittest.mock import patch
from seedsigner.models.seed import InvalidSeedException, Seed, AezeedSeed, ElectrumSeed, Slip39Seed, SeedWordsUnavailableException, XprvSeed
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
import shamir_mnemonic

from base import BaseTest
from seedsigner.models.settings import SettingsConstants
from seedsigner.views import seed_views


def test_seed():
    seed = Seed(mnemonic="obscure bone gas open exotic abuse virus bunker shuffle nasty ship dash".split())
    
    assert seed.seed_bytes == b'q\xb3\xd1i\x0c\x9b\x9b\xdf\xa7\xd9\xd97H\xa8,\xa7\xd9>\xeck\xc2\xf5ND?, \x88-\x07\x9aa\xc5\xee\xb7\xbf\xc4x\xd6\x07 X\xb6}?M\xaa\x05\xa6\xa7(>\xbf\x03\xb0\x9d\xef\xed":\xdf\x88w7'
    
    assert seed.mnemonic_str == "obscure bone gas open exotic abuse virus bunker shuffle nasty ship dash"
    
    assert seed.passphrase == ""
    
    # TODO: Not yet supported in new implementation
    # seed.set_wordlist_language_code("es")
    
    # assert seed.mnemonic_str == "natural ayuda futuro nivel espejo abuelo vago bien repetir moreno relevo conga"
    
    # seed.set_wordlist_language_code(SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
    
    # seed.mnemonic_str = "height demise useless trap grow lion found off key clown transfer enroll"
    
    # assert seed.mnemonic_str == "height demise useless trap grow lion found off key clown transfer enroll"
    
    # # TODO: Not yet supported in new implementation
    # seed.set_wordlist_language_code("es")
    
    # assert seed.mnemonic_str == "hebilla cría truco tigre gris llenar folio negocio laico casa tieso eludir"
    
    # seed.set_passphrase("test")
    
    # assert seed.seed_bytes == b'\xdd\r\xcb\x0b V\xb4@\xee+\x01`\xabem\xc1B\xfd\x8fba0\xab;[\xab\xc9\xf9\xba[F\x0c5,\x7fd8\xebI\x90"\xb8\x86C\x821\x01\xdb\xbe\xf3\xbc\x1cBH"%\x18\xc2{\x04\x08a]\xa5'
    
    # assert seed.passphrase == "test"




def test_seed_case_insensitive():
    """Mnemonic words should be accepted regardless of case."""
    expected_bytes = Seed(mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()).seed_bytes

    # Capitalized words
    seed = Seed(mnemonic="Abandon Abandon Abandon Abandon Abandon Abandon Abandon Abandon Abandon Abandon Abandon About".split())
    assert seed.seed_bytes == expected_bytes
    assert seed.mnemonic_str == "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    # Uppercase words
    seed = Seed(mnemonic="ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABANDON ABOUT".split())
    assert seed.seed_bytes == expected_bytes

    # Mixed case words
    seed = Seed(mnemonic="aBaNdOn ABANDON abandon Abandon ABANDON abandon ABANDON Abandon abandon ABANDON abandon About".split())
    assert seed.seed_bytes == expected_bytes


def test_discard_pending_mnemonic_does_not_corrupt_wordlist():
    """Regression test: wipe_list in discard_pending_mnemonic must not corrupt
    the global bip39.WORDLIST via wipe_string/ctypes.memset."""
    from embit import bip39
    from seedsigner.models.seed_storage import SeedStorage

    original_first_word = bip39.WORDLIST[0]  # "abandon"
    assert original_first_word == "abandon"

    storage = SeedStorage()
    storage.init_pending_mnemonic(num_words=12)
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()
    for i, word in enumerate(mnemonic):
        storage.update_pending_mnemonic(word, i)

    storage.convert_pending_mnemonic_to_pending_seed()

    # The global wordlist must still be intact
    assert bip39.WORDLIST[0] == "abandon"
    assert bip39.WORDLIST[0].startswith("a")
    assert repr(bip39.WORDLIST[0]) == "'abandon'"
    # Word matching (as used in keyboard entry) must still work
    assert "abandon" in [w for w in bip39.WORDLIST if w.startswith("a")]



def test_wipe_list_does_not_corrupt_shared_wordlists():
    from embit import bip39
    from shamir_mnemonic import wordlist as slip39_wordlist
    from seedsigner.helpers.secure_delete import wipe_list, wipe_string

    original_bip39_first = bip39.WORDLIST[0]
    original_slip39_first = slip39_wordlist.WORDLIST[0]

    refs = [bip39.WORDLIST[0], slip39_wordlist.WORDLIST[0]]
    wipe_list(refs)

    assert bip39.WORDLIST[0] == original_bip39_first == "abandon"
    assert slip39_wordlist.WORDLIST[0] == original_slip39_first

    safe_copies = ["".join(bip39.WORDLIST[0]), "".join(slip39_wordlist.WORDLIST[0])]
    wipe_list(safe_copies)
    assert safe_copies == []
    assert bip39.WORDLIST[0] == "abandon"
    assert slip39_wordlist.WORDLIST[0] == original_slip39_first

    single_copy = "".join(bip39.WORDLIST[0])
    wipe_string(single_copy)
    assert single_copy != "abandon"
    assert bip39.WORDLIST[0] == "abandon"


def test_aezeed_seed_default_passphrase_vector():
    mnemonic = (
        "absorb original enlist once climb erode kid thrive kitchen giant define tube "
        "orange leader harbor comfort olive fatal success suggest drink penalty chimney ritual"
    ).split()
    seed = AezeedSeed(mnemonic=mnemonic)

    assert seed.seed_bytes == bytes.fromhex("81b637d86359e6960de795e41e0b4cfd")




def test_aezeed_seed_requires_passphrase_does_not_fail_word_validation():
    mnemonic = (
        "above gap bronze point damp name group actress idea festival cream during "
        "bid blanket dumb wage foster merit success suggest drink protect autumn box"
    ).split()
    seed = AezeedSeed(mnemonic=mnemonic)

    assert seed.seed_bytes is None



def test_aezeed_seed_user_reported_passphrase_vector():
    mnemonic = (
        "absent beef crazy include regret city blanket plug thought spatial boy receive "
        "bag jazz fade emerge quit beach crucial giant mutual reward captain excite"
    ).split()
    seed = AezeedSeed(mnemonic=mnemonic, passphrase="test")

    assert seed.seed_bytes == bytes.fromhex("81b637d86359e6960de795e41e0b4cfd")

def test_aezeed_seed_custom_passphrase_vector():
    mnemonic = (
        "above gap bronze point damp name group actress idea festival cream during "
        "bid blanket dumb wage foster merit success suggest drink protect autumn box"
    ).split()
    seed = AezeedSeed(mnemonic=mnemonic, passphrase="!very_safe_55345_password*")

    assert seed.seed_bytes == bytes.fromhex("81b637d86359e6960de795e41e0b4cfd")


def test_aezeed_seed_blank_passphrase_retry_does_not_raise():
    mnemonic = (
        "absent beef crazy include regret city blanket plug thought spatial boy receive "
        "bag jazz fade emerge quit beach crucial giant mutual reward captain excite"
    ).split()
    seed = AezeedSeed(mnemonic=mnemonic)

    assert seed.seed_bytes is None

    # Blank retry must remain in passphrase-required state, not raise.
    seed.set_passphrase("")
    assert seed.seed_bytes is None



def test_in_memory_seed_type_label_for_aezeed():
    mnemonic = (
        "absorb original enlist once climb erode kid thrive kitchen giant define tube "
        "orange leader harbor comfort olive fatal success suggest drink penalty chimney ritual"
    ).split()
    seed = AezeedSeed(mnemonic=mnemonic)

    assert seed_views.SeedsMenuView.get_seed_type_label(seed) == "Aezeed"

def test_xprv_seed_has_no_seed_words():
    xprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
    seed = XprvSeed(xprv)

    with pytest.raises(SeedWordsUnavailableException, match="does not have seed words"):
        _ = seed.mnemonic_display_list


def test_xprv_seed_supports_bip85_child_mnemonic_vectors():
    """BIP85 vectors from BIP-0085 for application 39' (BIP39 mnemonics)."""
    xprv = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
    seed = XprvSeed(xprv)

    assert seed.bip85_supported
    assert seed.get_bip85_child_mnemonic(0, 12) == "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
    assert seed.get_bip85_child_mnemonic(0, 18) == "near account window bike charge season chef number sketch tomorrow excuse sniff circle vital hockey outdoor supply token"
    assert seed.get_bip85_child_mnemonic(0, 24) == "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"


def test_electrum_seed_supports_bip85_child_mnemonic():
    seed = ElectrumSeed(mnemonic="regular reject rare profit once math fringe chase until ketchup century escape".split())

    assert seed.bip85_supported
    assert seed.get_bip85_child_mnemonic(0, 12) == "slender grass raw hundred skirt obey street sound swear fuel drastic dish"


def test_slip39_seed_supports_bip85_child_mnemonic(monkeypatch):
    class DummyLoadingScreenThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr("seedsigner.gui.screens.screen.LoadingScreenThread", DummyLoadingScreenThread)

    share = "testify swimming academic academic column loyalty smear include exotic bedroom exotic wrist lobe cover grief golden smart junior estimate learn"
    seed = Slip39Seed(mnemonics=[share])

    assert seed.bip85_supported
    assert seed.get_bip85_child_mnemonic(0, 12) == "unable jealous real gain balance armed wide sting alley float fiction engine"

def test_electrum_seed():
    """
    ElectrumSeed should correctly parse a modern Electrum mnemonic.
    """
    seed = ElectrumSeed(mnemonic="regular reject rare profit once math fringe chase until ketchup century escape".split())

    intended_seed = b'\xcan|\xf8\x8a\x8d\xf78=Pq\xc4_\xe6\x02\x91\xfcs\xb2[\xed*\xdc\xc7%\xb6[_-(~D\xe5\x1e\x85%N\x9c\x03\x9dh\xafX}\x16\xb1\x99,\xbe\xc4\x11\xfaW\x0f\xb0\x89yD\xf4\x0f\xd5?\x8eA'

    assert seed.seed_bytes == intended_seed


def test_electrum_mnemonic_format():
    """
    ElectrumSeed should reject mnemonics that are not 12 words long.
    """
    with pytest.raises(InvalidSeedException):
        ElectrumSeed(mnemonic=["regular"] * 11)

    with pytest.raises(InvalidSeedException):
        ElectrumSeed(mnemonic=["regular"] * 13)

    with pytest.raises(InvalidSeedException):
        ElectrumSeed(mnemonic=["regular"] * 24)


def test_electrum_seed_rejects_most_bip39_mnemonics():
    """
    ElectrumSeed should throw an exception for most BIP-39 mnemonics.

    There are 1/16 odds that a seed will be valid for both formats.
    """
    # Most BIP-39 seeds should fail; test seeds generated by bitcoiner.guide
    with pytest.raises(InvalidSeedException):
        ElectrumSeed(mnemonic="pioneer divide volcano art victory family grow novel mandate bicycle senior adjust".split())

    with pytest.raises(InvalidSeedException):
        ElectrumSeed(mnemonic="gentle combine cool hamster ghost harvest gossip lend dismiss slam any toast".split())

    with pytest.raises(InvalidSeedException):
        ElectrumSeed(mnemonic="enough board blossom stamp fire buffalo digital solution sadness random number stone".split())

    # This one is valid for both formats
    mnemonic = "only gain spot output unknown craft simple cram absorb suggest ridge famous".split()
    Seed(mnemonic)
    ElectrumSeed(mnemonic)

def test_slip39_seed():
        secret = bytes.fromhex("11" * 32)
        shares = shamir_mnemonic.generate_mnemonics(1, [(2, 3)], secret)[0]
        seed = Slip39Seed(mnemonics=[shares[0], shares[1]])
        assert seed.seed_bytes == secret

def test_slip39_seed_20_word_share():
        secret = bytes.fromhex("33" * 16)
        shares = shamir_mnemonic.generate_mnemonics(1, [(2, 3)], secret)[0]
        seed = Slip39Seed(mnemonics=[shares[0], shares[1]])
        assert seed.seed_bytes == secret


def test_slip39_qr_with_capitalization():
        secret = bytes.fromhex("11" * 32)
        share = shamir_mnemonic.generate_mnemonics(1, [(1, 1)], secret)[0][0]
        share_caps = share.upper()
        decoder = DecodeQR()
        status = decoder.add_data(share_caps)
        assert status == DecodeQRStatus.COMPLETE
        assert decoder.is_slip39_share
        assert decoder.get_slip39_share() == share

def test_slip39_storage_reconstruction():
       secret = bytes.fromhex("22" * 32)
       shares = shamir_mnemonic.generate_mnemonics(1, [(2, 3)], secret)[0]
       from seedsigner.models.seed_storage import SeedStorage
       storage = SeedStorage()
       storage.init_pending_slip39_share(num_words=len(shares[0].split()))
       for i, w in enumerate(shares[0].split()):
               storage.update_pending_slip39_share(w, i)
       storage.finalize_current_slip39_share()
       storage.init_pending_slip39_share()
       for i, w in enumerate(shares[1].split()):
               storage.update_pending_slip39_share(w, i)
       storage.finalize_current_slip39_share()
       storage.convert_pending_slip39_shares_to_pending_seed()
       assert storage.pending_seed.seed_bytes == secret

def test_slip39_storage_reconstruction_20_word():
       secret = bytes.fromhex("44" * 16)
       shares = shamir_mnemonic.generate_mnemonics(1, [(2, 3)], secret)[0]
       from seedsigner.models.seed_storage import SeedStorage
       storage = SeedStorage()
       storage.init_pending_slip39_share(num_words=len(shares[0].split()))
       for i, w in enumerate(shares[0].split()):
               storage.update_pending_slip39_share(w, i)
       storage.finalize_current_slip39_share()
       storage.init_pending_slip39_share()
       for i, w in enumerate(shares[1].split()):
               storage.update_pending_slip39_share(w, i)
       storage.finalize_current_slip39_share()
       storage.convert_pending_slip39_shares_to_pending_seed()
       assert storage.pending_seed.seed_bytes == secret

def test_slip39_invalid_share_rejected():
        secret = bytes.fromhex("55" * 16)
        shares = shamir_mnemonic.generate_mnemonics(1, [(2, 3)], secret)[0]
        bad_share = shares[0].split()
        bad_share[-1] = "abandon"
        from seedsigner.models.seed_storage import SeedStorage, InvalidSeedException
        storage = SeedStorage()
        storage.init_pending_slip39_share(num_words=len(bad_share))
        for i, w in enumerate(bad_share):
                storage.update_pending_slip39_share(w, i)
        with pytest.raises(InvalidSeedException):
                storage.finalize_current_slip39_share()


def test_seed_passphrase_effect():
        mnemonic = "abandon " * 11 + "about"
        seed = Seed(mnemonic=mnemonic.split())
        orig = seed.seed_bytes
        seed.set_passphrase("trezor")
        from embit import bip39
        expected = bip39.mnemonic_to_seed(mnemonic, password="trezor")
        assert seed.seed_bytes == expected
        assert seed.seed_bytes != orig

def test_slip39_regenerate_shares():
        secret = bytes.fromhex("aa" * 16)
        shares = shamir_mnemonic.generate_mnemonics(1, [(2, 3)], secret, extendable=True)[0]
        seed = Slip39Seed(mnemonics=[shares[0], shares[1]])
        assert seed.extendable
        new_shares = seed.regenerate_shares(2, 4)
        assert len(new_shares) == 4
        combined = shamir_mnemonic.combine_mnemonics(new_shares[:2])
        assert combined == secret
        assert seed.seed_bytes == secret


def test_slip39_regenerate_shares_nonextendable():
        secret = bytes.fromhex("aa" * 16)
        shares = shamir_mnemonic.generate_mnemonics(1, [(2, 3)], secret, extendable=False)[0]
        seed = Slip39Seed(mnemonics=[shares[0], shares[1]])
        assert not seed.extendable
        with pytest.raises(InvalidSeedException):
                seed.regenerate_shares(2, 4)


def test_slip39_passphrase_update():
    secret = bytes.fromhex("dd" * 16)
    shares = shamir_mnemonic.generate_mnemonics(
        1, [(2, 3)], secret, passphrase=b"pw", extendable=True
    )[0]
    seed1 = Slip39Seed(mnemonics=[shares[0], shares[1]], slip39_passphrase="pw")
    seed2 = Slip39Seed(mnemonics=[shares[0], shares[1]])
    seed2.set_slip39_passphrase("pw")
    assert seed2.seed_bytes == seed1.seed_bytes
    assert seed2.master_secret == seed1.master_secret

def test_slip39_passphrase_fingerprint():
    share = "testify swimming academic academic column loyalty smear include exotic bedroom exotic wrist lobe cover grief golden smart junior estimate learn"
    seed = Slip39Seed(mnemonics=[share])
    assert seed.get_fingerprint() == "37bb5fa5"
    seed.set_slip39_passphrase("test")
    assert seed.get_fingerprint() == "d9fda401"


def test_slip39_regenerate_consistency():
    """Old and regenerated shares should yield the same master secret."""
    share = (
        "testify swimming academic academic column loyalty smear include exotic "
        "bedroom exotic wrist lobe cover grief golden smart junior estimate learn"
    )
    expected_secret = bytes.fromhex("1679b4516e0ee5954351d288a838f45e")

    seed = Slip39Seed(mnemonics=[share])
    seed.set_slip39_passphrase("TREZOR")
    assert seed.master_secret == expected_secret

    old_shares = seed.mnemonic_list.copy()
    new_shares = seed.regenerate_shares(seed._member_threshold, len(old_shares))

    secret_old = shamir_mnemonic.combine_mnemonics(old_shares, b"TREZOR")
    secret_new = shamir_mnemonic.combine_mnemonics(
        new_shares[: seed._member_threshold], b"TREZOR"
    )

    assert secret_old == secret_new == expected_secret

    # Random passphrase should also yield the same result for old and new shares
    rand_pw = os.urandom(5)
    assert (
        shamir_mnemonic.combine_mnemonics(old_shares, rand_pw)
        == shamir_mnemonic.combine_mnemonics(new_shares[: seed._member_threshold], rand_pw)
    )


def test_slip39_regenerate_consistency_no_passphrase():
    """Vector 42 should regenerate shares without changing the master secret when no passphrase is used."""
    share = (
        "testify swimming academic academic column loyalty smear include exotic"
        " bedroom exotic wrist lobe cover grief golden smart junior estimate learn"
    )
    expected_secret = bytes.fromhex("642a850f4ee8508a3ef44db68ccf0d62")

    seed = Slip39Seed(mnemonics=[share])
    assert seed.master_secret == expected_secret

    old_shares = seed.mnemonic_list.copy()
    new_shares = seed.regenerate_shares(seed._member_threshold, len(old_shares))

    secret_old = shamir_mnemonic.combine_mnemonics(old_shares)
    secret_new = shamir_mnemonic.combine_mnemonics(
        new_shares[: seed._member_threshold]
    )

    assert secret_old == secret_new == expected_secret


def test_slip39_regenerate_random_passphrase():
    """Regeneration should keep the master secret with any passphrase."""
    import random, string
    slip_pass = ''.join(random.choice(string.ascii_letters) for _ in range(8))
    secret = os.urandom(16)
    shares = shamir_mnemonic.generate_mnemonics(
        1, [(2, 3)], secret, passphrase=slip_pass.encode(), extendable=True
    )[0]

    seed = Slip39Seed(mnemonics=[shares[0], shares[1]], slip39_passphrase=slip_pass)
    old_shares = seed.mnemonic_list.copy()
    new_shares = seed.regenerate_shares(2, 4)

    secret_old = shamir_mnemonic.combine_mnemonics(old_shares, slip_pass.encode())
    secret_new = shamir_mnemonic.combine_mnemonics(new_shares[:2], slip_pass.encode())

    assert secret_old == secret_new == secret

    alt_pass = os.urandom(5)
    assert (
        shamir_mnemonic.combine_mnemonics(old_shares, alt_pass)
        == shamir_mnemonic.combine_mnemonics(new_shares[:2], alt_pass)
    )


VECTORS_PATH = os.path.join(os.path.dirname(__file__), "data", "shamir_vectors.json")


@pytest.mark.parametrize('desc,mnemonics,secret_hex,xprv', json.load(open(VECTORS_PATH)))
def test_slip39_vectors_end_to_end(desc, mnemonics, secret_hex, xprv):
        if not secret_hex:
                with pytest.raises(Exception):
                        Slip39Seed(mnemonics=mnemonics, slip39_passphrase="TREZOR")
        else:
                seed = Slip39Seed(mnemonics=mnemonics, slip39_passphrase="TREZOR")
                from embit import bip32
                from embit.networks import NETWORKS
                assert seed.seed_bytes.hex() == secret_hex
                root = bip32.HDKey.from_seed(seed.seed_bytes, version=NETWORKS["main"]["xprv"])
                assert root.to_base58() == xprv




class TestAezeedPassphraseMode(BaseTest):
    def test_back_from_aezeed_passphrase_entry_returns_mode(self, monkeypatch):
        mnemonic = (
            "absent beef crazy include regret city blanket plug thought spatial boy receive "
            "bag jazz fade emerge quit beach crucial giant mutual reward captain excite"
        ).split()
        self.controller.storage.set_pending_seed(AezeedSeed(mnemonic=mnemonic))

        view = seed_views.SeedAddPassphraseView()
        monkeypatch.setattr(
            view,
            "run_screen",
            lambda *args, **kwargs: {"passphrase": "", "is_back_button": True},
        )

        destination = view.run()
        assert destination.View_cls == seed_views.SeedAezeedPassphraseModeView

    def test_back_from_aezeed_passphrase_mode_returns_home(self, monkeypatch):
        mnemonic = (
            "absent beef crazy include regret city blanket plug thought spatial boy receive "
            "bag jazz fade emerge quit beach crucial giant mutual reward captain excite"
        ).split()
        self.controller.storage.set_pending_seed(AezeedSeed(mnemonic=mnemonic))

        view = seed_views.SeedAezeedPassphraseModeView()
        monkeypatch.setattr(view, "run_screen", lambda *args, **kwargs: seed_views.RET_CODE__BACK_BUTTON)

        destination = view.run()
        assert destination.View_cls == seed_views.MainMenuView
        assert destination.clear_history is True

    def test_scan_wrong_aezeed_passphrase_returns_mode(self, monkeypatch):
        mnemonic = (
            "absent beef crazy include regret city blanket plug thought spatial boy receive "
            "bag jazz fade emerge quit beach crucial giant mutual reward captain excite"
        ).split()
        self.controller.storage.set_pending_seed(AezeedSeed(mnemonic=mnemonic))

        class DummyDecodeQR:
            def __init__(self, is_passphrase=False):
                self.is_complete = True
                self.is_nonUTF8 = False

            def get_passphrase(self):
                return "wrong"

        monkeypatch.setattr("seedsigner.models.decode_qr.DecodeQR", DummyDecodeQR)

        view = seed_views.SeedScanPassphraseView()
        monkeypatch.setattr(view, "run_screen", lambda *args, **kwargs: None)

        destination = view.run()
        assert destination.View_cls == seed_views.SeedAezeedPassphraseModeView

    def test_seedkeeper_wrong_aezeed_passphrase_returns_mode(self, monkeypatch):
        mnemonic = (
            "absent beef crazy include regret city blanket plug thought spatial boy receive "
            "bag jazz fade emerge quit beach crucial giant mutual reward captain excite"
        ).split()
        self.controller.storage.set_pending_seed(AezeedSeed(mnemonic=mnemonic))

        class DummyLoadingScreenThread:
            def __init__(self, *args, **kwargs):
                pass

            def start(self):
                pass

            def stop(self):
                pass

        class DummyConnector:
            def seedkeeper_list_secret_headers(self):
                return [{"id": 1, "label": "pw", "type": 0x90, "origin": 0, "export_rights": 0x01, "export_nbplain": 0, "export_nbsecure": 0, "export_counter": 0, "fingerprint": ""}]

            def seedkeeper_export_secret(self, sid, _):
                assert sid == 1
                pwd = "wrong".encode()
                return {"secret_list": [len(pwd)], "secret": (bytes([len(pwd)]) + pwd).hex()}

        monkeypatch.setattr("seedsigner.views.seed_views.seedkeeper_utils.init_satochip", lambda *args, **kwargs: DummyConnector())
        monkeypatch.setattr("seedsigner.gui.screens.screen.LoadingScreenThread", DummyLoadingScreenThread)

        view = seed_views.SeedLoadSeedKeeperPassphraseView()
        monkeypatch.setattr(view, "run_screen", lambda *args, **kwargs: 0)

        destination = view.run()
        assert destination.View_cls == seed_views.SeedAezeedPassphraseModeView





class TestAezeedBackupOptions(BaseTest):
    def _load_aezeed_seed(self, passphrase=""):
        mnemonic = (
            "absent beef crazy include regret city blanket plug thought spatial boy receive "
            "bag jazz fade emerge quit beach crucial giant mutual reward captain excite"
        ).split()
        seed = AezeedSeed(mnemonic=mnemonic)
        if passphrase:
            seed.set_passphrase(passphrase)
        self.controller.storage.seeds = [seed]
        return seed

    def test_backup_view_keeps_view_words_and_hides_plaintext_qr_for_aezeed(self, monkeypatch):
        self._load_aezeed_seed(passphrase="test")
        self.settings.set_value(SettingsConstants.SETTING__PLAINTEXTQR, SettingsConstants.OPTION__ENABLED)

        captured = {}
        def fake_run_screen(*args, **kwargs):
            captured['button_data'] = kwargs['button_data']
            return seed_views.RET_CODE__BACK_BUTTON

        view = seed_views.SeedBackupView(seed_num=0)
        monkeypatch.setattr(view, "run_screen", fake_run_screen)
        view.run()

        assert seed_views.SeedBackupView.VIEW_WORDS in captured['button_data']
        assert seed_views.SeedBackupView.EXPORT_PLAINTEXTQR not in captured['button_data']

    def test_aezeed_seed_words_warning_mentions_passphrase(self, monkeypatch):
        self._load_aezeed_seed(passphrase="test")

        captured = {}
        def fake_run_screen(*args, **kwargs):
            captured['text'] = kwargs.get('text')
            return seed_views.RET_CODE__BACK_BUTTON

        view = seed_views.SeedWordsWarningView(seed_num=0)
        monkeypatch.setattr(view, "run_screen", fake_run_screen)
        destination = view.run()

        assert "passphrase" in captured['text'].lower()
        assert destination.View_cls == seed_views.BackStackView

class TestSlip39ExtendableSetting(BaseTest):
    def test_create_nonextendable_slip39_seed(self, monkeypatch):
        self.settings.set_value(
            SettingsConstants.SETTING__SLIP39_SEEDS, SettingsConstants.OPTION__ENABLED
        )
        self.settings.set_value(
            SettingsConstants.SETTING__SLIP39_EXTENDABLE, SettingsConstants.OPTION__DISABLED
        )

        responses = iter(["2", "2"])

        class DummyScreen:
            def __init__(self, *args, **kwargs):
                pass

            def display(self):
                return next(responses)

        monkeypatch.setattr(
            seed_views.seed_screens, "SeedBIP85SelectChildIndexScreen", DummyScreen
        )

        secret = bytes.fromhex("11" * 16)
        view = seed_views.SeedSlip39CreateFromBytesView(secret=secret)
        view.run()

        seed = self.controller.storage.get_pending_seed()
        assert isinstance(seed, Slip39Seed)
        assert not seed.extendable


def test_seed_storage_convert_pending_mnemonic_passes_wordlist_language(monkeypatch):
    from seedsigner.models.seed_storage import SeedStorage
    from seedsigner.models.settings_definition import SettingsConstants

    captured = {}

    class DummySeed:
        def __init__(self, mnemonic, passphrase="", wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH):
            captured["mnemonic"] = list(mnemonic)
            captured["wordlist_language_code"] = wordlist_language_code

    monkeypatch.setattr("seedsigner.models.seed_storage.Seed", DummySeed)
    monkeypatch.setattr("seedsigner.models.seed_storage.wipe_list", lambda values: None)

    storage = SeedStorage()
    storage.init_pending_mnemonic(num_words=12)
    for i in range(12):
        storage.update_pending_mnemonic("abandon", i)

    storage.convert_pending_mnemonic_to_pending_seed(wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)

    assert captured["mnemonic"] == ["abandon"] * 12
    assert captured["wordlist_language_code"] == SettingsConstants.WORDLIST_LANGUAGE__ENGLISH


def test_seed_storage_pending_mnemonic_fingerprint_passes_wordlist_language(monkeypatch):
    from seedsigner.models.seed_storage import SeedStorage
    from seedsigner.models.settings_definition import SettingsConstants

    captured = {}

    class DummySeed:
        def __init__(self, mnemonic, passphrase="", wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH):
            captured["mnemonic"] = list(mnemonic)
            captured["wordlist_language_code"] = wordlist_language_code

        def get_fingerprint(self, network):
            captured["network"] = network
            return "deadbeef"

    monkeypatch.setattr("seedsigner.models.seed_storage.Seed", DummySeed)
    monkeypatch.setattr("seedsigner.models.seed_storage.wipe_list", lambda values: None)

    storage = SeedStorage()
    storage.init_pending_mnemonic(num_words=12)
    for i in range(12):
        storage.update_pending_mnemonic("abandon", i)

    fingerprint = storage.get_pending_mnemonic_fingerprint(
        network=SettingsConstants.TESTNET,
        wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH,
    )

    assert fingerprint == "deadbeef"
    assert captured["mnemonic"] == ["abandon"] * 12
    assert captured["wordlist_language_code"] == SettingsConstants.WORDLIST_LANGUAGE__ENGLISH
    assert captured["network"] == SettingsConstants.TESTNET

def test_seed_storage_allows_multiple_xprvs():
    from seedsigner.models.seed_storage import SeedStorage

    storage = SeedStorage()

    xprv_a = XprvSeed("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
    xprv_b = XprvSeed("xprv9s21ZrQH143K4QViKpwKCpS2zVbz8GrZgpEchMDg6KME9HZtjfL7iThE9w5muQA4YPHKN1u5VM1w8D4pvnjxa2BmpGMfXr7hnRrRHZ93awZ")

    storage.set_pending_seed(xprv_a)
    first_index = storage.finalize_pending_seed()

    storage.set_pending_seed(xprv_b)
    second_index = storage.finalize_pending_seed()

    assert first_index == 0
    assert second_index == 1
    assert storage.num_seeds() == 2
    assert storage.seeds[0] == xprv_a
    assert storage.seeds[1] == xprv_b


def test_seed_storage_import_multiple_seed_types_mix_and_match():
    from seedsigner.models.seed_storage import SeedStorage

    with patch("seedsigner.gui.screens.screen.LoadingScreenThread"):
        storage = SeedStorage()

        bip39_a = Seed(mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split())
        bip39_b = Seed(mnemonic="obscure bone gas open exotic abuse virus bunker shuffle nasty ship dash".split())

        electrum_a = ElectrumSeed(mnemonic="regular reject rare profit once math fringe chase until ketchup century escape".split())
        electrum_b = ElectrumSeed(mnemonic="basket print toy noodle betray weird filter ticket insect copy force machine".split())

        secret1 = bytes.fromhex("11" * 16)
        shares1 = shamir_mnemonic.generate_mnemonics(1, [(2, 3)], secret1)[0]
        slip39_a = Slip39Seed(mnemonics=[shares1[0], shares1[1]])

        secret2 = bytes.fromhex("22" * 16)
        shares2 = shamir_mnemonic.generate_mnemonics(1, [(2, 3)], secret2)[0]
        slip39_b = Slip39Seed(mnemonics=[shares2[0], shares2[1]])

        xprv_a = XprvSeed("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
        xprv_b = XprvSeed("xprv9s21ZrQH143K4QViKpwKCpS2zVbz8GrZgpEchMDg6KME9HZtjfL7iThE9w5muQA4YPHKN1u5VM1w8D4pvnjxa2BmpGMfXr7hnRrRHZ93awZ")

        seeds_in_order = [
            bip39_a,
            xprv_a,
            electrum_a,
            slip39_a,
            bip39_b,
            xprv_b,
            electrum_b,
            slip39_b,
        ]

        for expected_index, seed in enumerate(seeds_in_order):
            storage.set_pending_seed(seed)
            assert storage.finalize_pending_seed() == expected_index

        assert storage.num_seeds() == len(seeds_in_order)
        assert storage.seeds == seeds_in_order
