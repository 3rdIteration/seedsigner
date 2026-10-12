"""
libwally cross-checks of seeds, descriptors and addresses, and the
availability policy (seedsigner.crosscheck). PSBT checks: test_crosscheck_psbt.py.
"""
import pytest
from embit.descriptor import Descriptor

from seedsigner import crosscheck
from seedsigner.crosscheck import CrossCheckCode, CrossCheckError
from seedsigner.crosscheck.descriptor import check_descriptor
from seedsigner.crosscheck.secrets import SecretScratch
from seedsigner.crosscheck.seed import check_seed
from seedsigner.models import crosscheck_claims
from seedsigner.models.seed import ElectrumSeed, Seed, Slip39Seed, XprvSeed
from seedsigner.models.seed_storage import SeedStorage
from seedsigner.models.settings import SettingsConstants


MAINNET = SettingsConstants.MAINNET
TESTNET = SettingsConstants.TESTNET
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()

MULTISIG_DESCRIPTOR = (
    "wsh(sortedmulti(2,"
    "[0fb882ff/48h/1h/0h/2h]tpubDF3QYaRazZ44jHz3jaSPRGCLVYj7D8j4mVVUTCr3CHsfuvoV2Z73eTcvHc8sP3Dj58yEfkG57iBpKTuHv3dNAUcFufCxx26SAbrWque5gts/<0;1>/*,"
    "[03cd0a2b/48h/1h/0h/2h]tpubDEPEYgTj1ddmZqDdpiq5Gjttx3CnNSFppSaUa5eHAUVNMD2FE1ihGA2EMP92mzmSUGJsTAgMhBTACd9xsRDB5K4GKJH8RzbRuFUrmVVLR15/<0;1>/*,"
    "[0f889044/48h/1h/0h/2h]tpubDFQDKbH2mDqNDPNaUVxM6R5mHhzC4u5F6mNnUkCf6gBMbcENMQ1ZGFLZc3QwgdEv2f34wkTvLMG5kD8AZEZRhat1HQDj42eVxQSxbcqxn31/<0;1>/*"
    "))#jsc5nnpk"
)


def _expect(code, fn, *args, **kwargs):
    with pytest.raises(CrossCheckError) as excinfo:
        fn(*args, **kwargs)
    assert excinfo.value.code == code, excinfo.value
    return excinfo.value



class TestAvailability:

    def test_missing_wally_is_refused_when_required(self, monkeypatch):
        monkeypatch.setattr(crosscheck, "_wally", None)
        monkeypatch.setenv(crosscheck.REQUIRE_ENV_VAR, "1")
        _expect(CrossCheckCode.UNAVAILABLE, crosscheck_claims.crosscheck_seed, Seed(MNEMONIC), MAINNET)

    def test_missing_wally_is_skipped_on_desktop(self, monkeypatch):
        monkeypatch.setattr(crosscheck, "_wally", None)
        monkeypatch.setenv(crosscheck.REQUIRE_ENV_VAR, "0")
        crosscheck_claims.crosscheck_seed(Seed(MNEMONIC), MAINNET)

    def test_required_on_any_device_profile(self, monkeypatch):
        from seedsigner.models.settings import Settings
        monkeypatch.delenv(crosscheck.REQUIRE_ENV_VAR, raising=False)
        monkeypatch.setattr(Settings, "RUNTIME_PROFILE", "rpi_26", raising=False)
        assert crosscheck.crosscheck_required()
        monkeypatch.setattr(Settings, "RUNTIME_PROFILE", "desktop", raising=False)
        assert not crosscheck.crosscheck_required()

    def test_wally_is_installed_for_the_test_suite(self):
        assert crosscheck.wally_available()



class TestSeed:

    @pytest.mark.parametrize("network", [MAINNET, TESTNET])
    @pytest.mark.parametrize("make_seed", [
        lambda: Seed(MNEMONIC),
        lambda: Seed(MNEMONIC, passphrase="TREZOR é"),
        lambda: ElectrumSeed("wild father tree among universe such mobile favorite target dynamic credit identify".split()),
        lambda: XprvSeed(Seed(MNEMONIC).get_root(MAINNET).to_base58()),
        # SLIP-132 account-level key: version bytes swapped, depth 3
        lambda: XprvSeed(Seed(MNEMONIC).get_root(MAINNET).derive("m/84h/0h/0h").to_base58(version=bytes.fromhex("04b2430c"))),
    ], ids=["bip39", "bip39-passphrase", "electrum", "xprv", "zprv-account"])
    def test_seed_types_agree(self, make_seed, network):
        crosscheck_claims.crosscheck_seed(make_seed(), network)

    def test_slip39_agrees(self):
        import shamir_mnemonic
        groups = shamir_mnemonic.generate_mnemonics(1, [(2, 3)], bytes(range(16)))
        crosscheck_claims.crosscheck_seed(Slip39Seed(groups[0][:2]), MAINNET)

    def test_wrong_seed_bytes_are_refused(self):
        seed = Seed(MNEMONIC)
        seed.seed_bytes = bytes(64)
        _expect(CrossCheckCode.SEED, crosscheck_claims.crosscheck_seed, seed, MAINNET)

    def test_wrong_fingerprint_is_refused(self):
        claims = crosscheck_claims.seed_claims(Seed(MNEMONIC), MAINNET)
        claims.fingerprint = "00000000"
        _expect(CrossCheckCode.SEED, check_seed, claims)

    def test_wrong_account_key_is_refused(self):
        claims = crosscheck_claims.seed_claims(Seed(MNEMONIC), MAINNET)
        path = next(iter(claims.account_keys))
        pubkey, chain_code = claims.account_keys[path]
        claims.account_keys[path] = (pubkey, bytes(32))
        _expect(CrossCheckCode.SEED, check_seed, claims)

    def test_finalize_refuses_and_wipes_a_disagreeing_seed(self, monkeypatch):
        storage = SeedStorage()
        seed = Seed(MNEMONIC)
        storage.set_pending_seed(seed)
        monkeypatch.setattr(Seed, "get_fingerprint", lambda self, network=MAINNET: "deadbeef")
        with pytest.raises(CrossCheckError):
            storage.finalize_pending_seed()
        assert storage.seeds == []
        assert storage.pending_seed is None
        assert seed.seed_bytes is None

    def test_finalize_admits_an_agreeing_seed(self):
        storage = SeedStorage()
        storage.set_pending_seed(Seed(MNEMONIC))
        assert storage.finalize_pending_seed() in storage.seeds



class TestDescriptor:

    @pytest.mark.parametrize("descriptor_str", [
        MULTISIG_DESCRIPTOR,
        "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/{0,1}/*)",
        "tr(xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/{0,1}/*)",
        "sh(wpkh(xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/0/*))",
    ], ids=["wsh-sortedmulti", "wpkh-embit-multipath", "tr", "sh-wpkh-single-branch"])
    def test_descriptors_agree(self, descriptor_str):
        crosscheck_claims.crosscheck_descriptor(Descriptor.from_string(descriptor_str), descriptor_str, MAINNET)

    @pytest.mark.parametrize("mutate, detail", [
        (lambda c: c.keys.pop(), "key count"),
        (lambda c: setattr(c.keys[0], "fingerprint", "00000000"), "fingerprint"),
        (lambda c: setattr(c.keys[1], "origin_path", c.keys[1].origin_path[:-1]), "origin path"),
        (lambda c: setattr(c.keys[2], "xpub", c.keys[0].xpub), "xpub"),
        (lambda c: setattr(c, "num_branches", 1), "branch count"),
        (lambda c: c.addresses.__setitem__((1, 3), c.addresses[(0, 3)]), "address 1/3"),
    ])
    def test_disagreement_is_refused(self, mutate, detail):
        claims = crosscheck_claims.descriptor_claims(
            Descriptor.from_string(MULTISIG_DESCRIPTOR), MULTISIG_DESCRIPTOR, TESTNET)
        mutate(claims)
        error = _expect(CrossCheckCode.DESCRIPTOR, check_descriptor, claims)
        assert detail in error.detail

    def test_unparseable_descriptor_is_refused(self):
        claims = crosscheck_claims.descriptor_claims(
            Descriptor.from_string(MULTISIG_DESCRIPTOR), MULTISIG_DESCRIPTOR, TESTNET)
        claims.descriptor = claims.descriptor.replace("sortedmulti", "sortedmultii")
        _expect(CrossCheckCode.DESCRIPTOR, check_descriptor, claims)



class TestAddress:

    @pytest.mark.parametrize("script_type", [
        SettingsConstants.NATIVE_SEGWIT, SettingsConstants.NESTED_SEGWIT,
        SettingsConstants.LEGACY_P2PKH, SettingsConstants.TAPROOT,
    ])
    def test_seed_addresses_agree(self, script_type):
        from seedsigner.helpers import embit_utils
        seed = Seed(MNEMONIC)
        path = embit_utils.get_standard_derivation_path(MAINNET, SettingsConstants.SINGLE_SIG, script_type)
        xpub = seed.get_xpub(path, MAINNET)
        for is_change in (False, True):
            address = embit_utils.get_single_sig_address(xpub, script_type, 4, is_change, "main")
            crosscheck_claims.crosscheck_seed_address(seed, address, MAINNET, script_type, path, 4, is_change)
            crosscheck_claims.crosscheck_xpub_address(xpub, address, MAINNET, script_type, 4, is_change)
            _expect(CrossCheckCode.ADDRESS, crosscheck_claims.crosscheck_seed_address,
                    seed, address, MAINNET, script_type, path, 5, is_change)

    def test_descriptor_addresses_agree(self):
        from seedsigner.helpers import embit_utils
        descriptor = Descriptor.from_string(MULTISIG_DESCRIPTOR)
        address = embit_utils.get_multisig_address(descriptor, 7, True, "test")
        crosscheck_claims.crosscheck_descriptor_address(descriptor, address, TESTNET, 7, True)
        _expect(CrossCheckCode.ADDRESS, crosscheck_claims.crosscheck_descriptor_address,
                descriptor, address, TESTNET, 7, False)



class TestSecrets:

    def test_scratch_wipes_what_it_keeps(self):
        import wallycore as w
        with SecretScratch() as scratch:
            seed = scratch.keep(w.bip39_mnemonic_to_seed512(" ".join(MNEMONIC), ""))
            assert any(seed)
        assert not any(seed)

    def test_seed_check_leaves_no_wally_seed_buffer(self, monkeypatch):
        import wallycore as w
        produced = []
        real = w.bip39_mnemonic_to_seed512

        def spy(*args):
            buf = real(*args)
            produced.append(buf)
            return buf

        monkeypatch.setattr(w, "bip39_mnemonic_to_seed512", spy)
        crosscheck_claims.crosscheck_seed(Seed(MNEMONIC), MAINNET)
        assert produced and all(not any(buf) for buf in produced)
