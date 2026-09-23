"""
    Keycard v3.2 as real applet bytecode in jcardsim, driven by SeedSigner's real
    keycard-py client stack (the same one used against a physical card).

    The spec is pinned to the 3.2 release tag: it installs and selects cleanly under
    jcardsim, and every BIP32 derivation below matches embit byte-for-byte -- seed
    import, hardened and non-hardened child keys, xpubs, and ECDSA signatures are all
    exercised for real rather than stubbed.

    One trap worth knowing: Keycard has a duress-PIN feature. When init carries no
    explicit duress PIN the applet sets the alt (duress) PIN to the first six digits of
    the PUK, and verifying with it makes every derivation use a decoy chain code
    (SHA-256 of the real one). The test PUK below therefore must not start with the
    test PIN -- see TestKeycardDuressPin.

    SmartPGP has its own file: tests/test_jcardsim_smartpgp.py.
"""

import sys
from unittest.mock import MagicMock

import pytest

# Must import test base before the Controller (sets up the hardware mocks)
import base  # noqa: F401

# base.py stubs pysatochip so the ordinary suite runs cardless; these tests need it real.
for _name in [m for m in sys.modules if m == "pysatochip" or m.startswith("pysatochip.")]:
    if isinstance(sys.modules[_name], MagicMock):
        del sys.modules[_name]

from jcardsim import (
    JCardSimUnavailable,
    SimulatedCard,
    resolve_applet,
    why_keycard_unavailable,
    why_unavailable,
)
from jcardsim.pcsc_shim import patched_pcsc


pytestmark = pytest.mark.skipif(
    why_unavailable() is not None, reason=f"jcardsim unavailable: {why_unavailable()}"
)

# The PUK must not start with the PIN (duress-PIN trap; see module docstring).
PIN = "123456"
PUK = "987654321012"

# A fixed 64-byte BIP32 seed, so the derived keys below are reproducible.
TEST_SEED = bytes.fromhex("00" * 32 + "11" * 32)


@pytest.fixture
def keycard():
    try:
        spec, classes = resolve_applet("keycard")
    except JCardSimUnavailable as exc:
        pytest.skip(str(exc))
    with SimulatedCard(spec, classes) as card:
        card.select()
        yield card


@pytest.fixture
def connector(keycard):
    reason = why_keycard_unavailable()
    if reason:
        pytest.skip(reason)
    with patched_pcsc(keycard):
        from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

        yield KeycardSatochipConnector.create(card_filter=["satochip"])


def setup_and_login(cc, pin=PIN, puk=PUK) -> None:
    cc.card_setup(3, 5, pin, puk, 3, 5, pin, puk, 32, 32, 0x01, 0x01, 0x01)
    assert cc.card_verify_PIN()[1:] == (0x90, 0x00)


class TestKeycardBasics:

    def test_applet_compiles(self):
        """The v3.2 sources build against the vendored JavaCard SDK."""
        try:
            spec, classes = resolve_applet("keycard")
        except JCardSimUnavailable as exc:
            pytest.skip(str(exc))

        assert (classes / "im/status/keycard/KeycardApplet.class").is_file()

    def test_card_is_recognised(self, connector):
        assert connector.card_type == "Keycard"

    def test_setup_then_pin(self, connector):
        _, sw1, sw2, status = connector.card_get_status()
        assert (sw1, sw2) == (0x90, 0x00)
        assert status["setup_done"] is False, "a fresh applet should not be set up"

        setup_and_login(connector)
        assert connector.card_get_status()[3]["setup_done"] is True


class TestKeycardSeedAndDerivation:
    """
    The crypto path: importing a seed and deriving from it on-card.

    Every result is compared byte-for-byte against embit, so a pass means the applet's
    secp256k1, BIP32 CKD (hardened and non-hardened), and chain-code handling really ran
    -- this is not a stub returning canned bytes.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "m/84'/0'/0'",      # native segwit, all hardened
            "m/49'/1'/0'",      # nested segwit, testnet coin type
            "m/45'",            # single hardened element
            "m/0/1",            # non-hardened children
            "m/84'/0'/0'/2/1",  # mixed depth
        ],
    )
    def test_derivation_matches_embit(self, connector, path):
        from embit import bip32

        setup_and_login(connector)
        assert connector.card_bip32_import_seed(list(TEST_SEED))[1:] == (0x90, 0x00)

        master = bip32.HDKey.from_seed(TEST_SEED)
        expected = master.derive(path)

        pub, chain_code = connector.card_bip32_get_extendedkey(path)
        assert bytes(pub.get_public_key_bytes(compressed=True)) == \
            expected.key.get_public_key().serialize()
        assert bytes(chain_code) == expected.chain_code

    def test_xpub_base58_matches_embit(self, connector):
        """The full base58 xpub (version bytes, depth, fingerprint, child number)."""
        from embit import bip32
        from embit.networks import NETWORKS

        setup_and_login(connector)
        assert connector.card_bip32_import_seed(list(TEST_SEED))[1:] == (0x90, 0x00)

        # from_seed needs a private version; the xpub below is rebuilt with the public one.
        master = bip32.HDKey.from_seed(TEST_SEED, version=NETWORKS["main"]["xprv"])
        path = "m/84'/0'/0'"
        expected_key = master.derive(path)
        parent = master.derive("m/84'/0'")

        expected_xpub = bip32.HDKey(
            key=expected_key.get_public_key(),
            chain_code=expected_key.chain_code,
            version=NETWORKS["main"]["xpub"],
            depth=3,
            fingerprint=parent.my_fingerprint,
            child_number=0x80000000,
        ).to_base58()

        assert connector.card_bip32_get_xpub(path, "standard", True) == expected_xpub


class TestKeycardSigning:

    def test_sign_digest_and_verify(self, connector):
        """Sign a 32-byte digest on-card at a derived path; verify with embit's key."""
        from ecdsa import VerifyingKey
        from ecdsa.curves import SECP256k1
        from ecdsa.util import sigdecode_der
        from embit import bip32

        setup_and_login(connector)
        assert connector.card_bip32_import_seed(list(TEST_SEED))[1:] == (0x90, 0x00)

        path = "m/84'/0'/0'"
        master = bip32.HDKey.from_seed(TEST_SEED)
        expected_key = master.derive(path)
        pub_bytes = expected_key.key.get_public_key().serialize()

        connector.card_bip32_get_extendedkey(path)  # sets _last_path
        digest = bytes(range(32))
        sig_list, sw1, sw2 = connector.card_sign_transaction_hash(0xFF, list(digest), None)
        assert (sw1, sw2) == (0x90, 0x00)

        vk = VerifyingKey.from_string(pub_bytes, curve=SECP256k1)
        assert vk.verify_digest(bytes(sig_list), digest, sigdecode=sigdecode_der)


class TestKeycardDuressPin:

    def test_puk_starting_with_pin_switches_to_decoy_chain(self, keycard):
        """
        Documents the duress-PIN trap: with no explicit duress PIN, the applet's alt PIN
        is the first six digits of the PUK. If those equal the main PIN, verifying with
        it silently switches every derivation to a decoy chain code (SHA-256 of the real
        one). The exported xpub then differs from embit -- exactly what would happen on a
        physical card configured this way.
        """
        from embit import bip32

        reason = why_keycard_unavailable()
        if reason:
            pytest.skip(reason)

        with patched_pcsc(keycard):
            from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

            conn = KeycardSatochipConnector.create(card_filter=["satochip"])
            # PUK starts with the PIN -> alt (duress) PIN == main PIN.
            setup_and_login(conn, pin=PIN, puk=PIN + "789012")
            assert conn.card_bip32_import_seed(list(TEST_SEED))[1:] == (0x90, 0x00)

            master = bip32.HDKey.from_seed(TEST_SEED)
            expected = master.derive("m/0'")

            pub, chain_code = conn.card_bip32_get_extendedkey("m/0'")
            # The decoy is deterministic: SHA-256 of the real master chain code.
            assert bytes(chain_code) != expected.chain_code
            assert bytes(pub.get_public_key_bytes(compressed=True)) != \
                expected.key.get_public_key().serialize()


class TestKeycardMultisigPSBT:
    """
    The branch fix, end to end on a real simulated card: a multisig PSBT input carries a
    derivation per cosigner; sign_psbt_with_keycard must export each candidate path's
    public key, match it against the claimed pubkeys, and sign only the one the card
    actually reproduces.
    """

    def test_multisig_signs_only_the_card_cosigner(self, connector, monkeypatch):
        from ecdsa import VerifyingKey
        from ecdsa.curves import SECP256k1
        from ecdsa.util import sigdecode_der
        from embit import bip32, script
        from embit.psbt import DerivationPath, InputScope, OutputScope, PSBT
        from embit.transaction import TransactionOutput

        from seedsigner.helpers.keycard_signer import sign_psbt_with_keycard
        from seedsigner.models.settings import Settings
        from seedsigner.models.settings_definition import SettingsConstants

        class SlowSettings:
            """No dummy signatures (speed/determinism); generous per-sign timeout."""
            def get_value(self, setting):
                if setting == SettingsConstants.SETTING__KEYCARD_SIGN_TIMEOUT:
                    return 30
                return 0

        monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: SlowSettings()))

        setup_and_login(connector)
        assert connector.card_bip32_import_seed(list(TEST_SEED))[1:] == (0x90, 0x00)

        path = "m/48'/0'/0'/2'/0/0"
        derivation = [0x80000030, 0x80000000, 0x80000000, 0x80000002, 0, 0]

        card_master = bip32.HDKey.from_seed(TEST_SEED)
        card_key = card_master.derive(path)
        card_pub = card_key.get_public_key()

        # Two foreign cosigners claiming the same path with their own seeds.
        seed_a, seed_b = bytes([0xAA]) * 64, bytes([0xBB]) * 64
        foreign_a = bip32.HDKey.from_seed(seed_a).derive(path).get_public_key()
        foreign_b = bip32.HDKey.from_seed(seed_b).derive(path).get_public_key()

        pubs_sorted = sorted(
            [card_pub, foreign_a, foreign_b], key=lambda p: p.sec())
        witness_script = script.multisig(2, pubs_sorted)
        spk = script.p2wsh(witness_script)

        psbt = PSBT()
        inp = InputScope()
        inp.txid = bytes(range(32))
        inp.vout = 0
        inp.witness_script = witness_script
        inp.witness_utxo = TransactionOutput(1_000_000, spk)
        for pub, seed in ((foreign_a, seed_a), (card_pub, TEST_SEED), (foreign_b, seed_b)):
            root = bip32.HDKey.from_seed(seed)
            inp.bip32_derivations[pub] = DerivationPath(root.my_fingerprint, derivation)
        psbt.inputs.append(inp)

        out = OutputScope()
        out.value = 900_000
        out.script_pubkey = script.p2wpkh(foreign_a)
        psbt.outputs.append(out)

        result = sign_psbt_with_keycard(psbt, connector)

        assert result.signed_count == 1
        assert not result.timed_out
        # The signature must be attached to the card's own pubkey only.
        assert card_pub in inp.partial_sigs
        assert foreign_a not in inp.partial_sigs
        assert foreign_b not in inp.partial_sigs

        sig_der = bytes(inp.partial_sigs[card_pub])[:-1]  # strip the SIGHASH.ALL byte
        digest = psbt.sighash(0)
        vk = VerifyingKey.from_string(card_pub.sec(), curve=SECP256k1)
        assert vk.verify_digest(sig_der, digest, sigdecode=sigdecode_der)
