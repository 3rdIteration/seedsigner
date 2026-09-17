import os

import pytest
from embit import ec, script, psbt
from embit.finalizer import finalize_psbt
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from seedsigner.models.wif import WIFKey
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.models.decode_qr import DecodeQR
from base import BaseTest

def test_wif_signs_psbt():
    priv = ec.PrivateKey(os.urandom(32))
    wif = priv.wif()
    key = WIFKey(wif)
    pub = priv.get_public_key()
    spk = script.p2wpkh(pub)
    tx = Transaction(1, [TransactionInput(b"\x00" * 32, 0)], [TransactionOutput(900, spk)], 0)
    p = psbt.PSBT(tx)
    p.inputs[0].witness_utxo = TransactionOutput(1000, spk)
    parser = PSBTParser(p, seed=key, network=SettingsConstants.MAINNET)
    assert isinstance(parser.root, ec.PrivateKey)
    p.sign_with(parser.root)
    assert PSBTParser.sig_count(p) == 1


def test_decode_qr_wif():
    priv = ec.PrivateKey(os.urandom(32))
    wif = priv.wif()
    decoder = DecodeQR()
    decoder.add_data(wif)
    assert decoder.is_complete
    assert decoder.is_wif
    assert decoder.get_wif() == wif


class TestWIF(BaseTest):
    def test_wif_signed_tx_qr_is_raw_hex(self):
        from seedsigner.views.psbt_views import PSBTFinalizeView, PSBTSignedQRDisplayView
        from seedsigner.models.encode_qr import GenericStringEncoder
        from embit.finalizer import finalize_psbt
        from seedsigner.controller import Controller

        priv = ec.PrivateKey(os.urandom(32))
        wif = priv.wif()
        key = WIFKey(wif)
        pub = priv.get_public_key()
        spk = script.p2wpkh(pub)
        tx = Transaction(1, [TransactionInput(b"\x00" * 32, 0)], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].witness_utxo = TransactionOutput(1000, spk)

        # compute expected finalized tx
        p_expected = psbt.PSBT.parse(p.serialize())
        p_expected.sign_with(priv)
        expected_hex = finalize_psbt(p_expected).serialize().hex()

        # setup controller state
        ctrl = Controller.get_instance()
        ctrl.psbt = p
        ctrl.psbt_seed = key
        ctrl.psbt_parser = PSBTParser(p, seed=key, network=SettingsConstants.MAINNET)

        finalize_view = PSBTFinalizeView()
        finalize_view.run_screen = lambda *a, **k: 0
        finalize_view.run()

        captured = {}
        display_view = PSBTSignedQRDisplayView()

        def fake_run_screen(screen_cls, **kwargs):
            captured["encoder"] = kwargs["qr_encoder"]
            return 0

        display_view.run_screen = fake_run_screen
        display_view.run()

        encoder = captured["encoder"]
        assert isinstance(encoder, GenericStringEncoder)
        assert encoder.next_part() == expected_hex

    def test_wif_setting_disables_options(self):
        from seedsigner.views import psbt_views
        from embit import ec, script, psbt
        from embit.transaction import Transaction, TransactionInput, TransactionOutput
        import os

        self.settings.set_value(SettingsConstants.SETTING__WIF_KEYS, SettingsConstants.OPTION__DISABLED)

        priv = ec.PrivateKey(os.urandom(32))
        pub = priv.get_public_key()
        spk = script.p2wpkh(pub)
        tx = Transaction(1, [TransactionInput(b"\x00" * 32, 0)], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].witness_utxo = TransactionOutput(1000, spk)
        self.controller.psbt = p
        self.controller._storage = type("s", (), {})()
        self.controller._storage.seeds = []

        # Build button list as PSBTSelectSeedView would
        buttons = [
            psbt_views.PSBTSelectSeedView.SATOCHIP,
            psbt_views.PSBTSelectSeedView.SCAN_SEED,
        ]
        if self.settings.get_value(SettingsConstants.SETTING__WIF_KEYS) == SettingsConstants.OPTION__ENABLED:
            buttons.append(psbt_views.PSBTSelectSeedView.SCAN_WIF)
        if self.settings.get_value(SettingsConstants.SETTING__BIP38_KEYS) == SettingsConstants.OPTION__ENABLED:
            buttons.append(psbt_views.PSBTSelectSeedView.SCAN_BIP38)

        seed_lengths = self.settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS)
        options = {
            12: psbt_views.PSBTSelectSeedView.TYPE_12WORD,
            15: psbt_views.PSBTSelectSeedView.TYPE_15WORD,
            18: psbt_views.PSBTSelectSeedView.TYPE_18WORD,
            21: psbt_views.PSBTSelectSeedView.TYPE_21WORD,
            24: psbt_views.PSBTSelectSeedView.TYPE_24WORD,
        }
        for l in seed_lengths:
            buttons.append(options[l])
        if self.settings.get_value(SettingsConstants.SETTING__ELECTRUM_SEEDS) == SettingsConstants.OPTION__ENABLED:
            buttons.append(psbt_views.PSBTSelectSeedView.TYPE_ELECTRUM)
        if self.settings.get_value(SettingsConstants.SETTING__WIF_KEYS) == SettingsConstants.OPTION__ENABLED:
            buttons.append(psbt_views.PSBTSelectSeedView.TYPE_WIF)
        if self.settings.get_value(SettingsConstants.SETTING__BIP38_KEYS) == SettingsConstants.OPTION__ENABLED:
            buttons.append(psbt_views.PSBTSelectSeedView.TYPE_BIP38)

        assert psbt_views.PSBTSelectSeedView.SCAN_WIF not in buttons
        assert psbt_views.PSBTSelectSeedView.TYPE_WIF not in buttons


# ======================================================================
# Raw private key signing, against psbts shaped the way Electrum exports them
# ======================================================================

class TestElectrumStyleWifSigning:
    """
    A watch-only single-address wallet in Electrum is the reference producer here.

    It holds an address and nothing else, so the psbt it exports carries a utxo and a
    script and *no derivation fields at all* -- no bip32_derivations, no fingerprints.
    That is the shape a Satodime key has to sign, and it is what broke: routing asked
    ``has_matching_input_fingerprint``, which walks bip32_derivations, found none, and
    quietly dropped the key on the seed-picker screen even though it signs perfectly.

    The vectors below build that psbt for each script type such a wallet can hold, and
    walk the whole path: route -> parse -> sign -> finalize.
    """

    # A fixed key, so a failure is reproducible rather than a one-in-a-run fluke.
    PRIV = ec.PrivateKey(bytes.fromhex(
        "1111111111111111111111111111111111111111111111111111111111111111"))
    KINDS = ("p2pkh", "p2wpkh", "p2sh-p2wpkh", "p2tr")

    def _spk_and_redeem(self, kind, pub):
        if kind == "p2pkh":
            return script.p2pkh(pub), None
        if kind == "p2wpkh":
            return script.p2wpkh(pub), None
        if kind == "p2sh-p2wpkh":
            redeem = script.p2wpkh(pub)
            return script.p2sh(redeem), redeem
        if kind == "p2tr":
            return script.p2tr(pub), None
        raise ValueError(kind)

    def _build(self, kind, priv=None):
        """A psbt spending one output of `kind` back out to an unrelated address."""
        priv = priv or self.PRIV
        pub = priv.get_public_key()
        spk, redeem = self._spk_and_redeem(kind, pub)
        dest = script.p2wpkh(ec.PrivateKey(bytes(31) + bytes([9])).get_public_key())

        prev = Transaction(
            version=2,
            vin=[TransactionInput(b"\x22" * 32, 0)],
            vout=[TransactionOutput(100_000, spk)],
            locktime=0,
        )
        spend = Transaction(
            version=2,
            vin=[TransactionInput(bytes.fromhex(prev.txid().hex()), 0)],
            vout=[TransactionOutput(90_000, dest)],
            locktime=0,
        )
        p = psbt.PSBT(spend)
        inp = p.inputs[0]
        # Electrum must ship the whole previous transaction for a legacy input (it is
        # the only proof of the amount) and sends a witness_utxo for segwit ones.
        if kind == "p2pkh":
            inp.non_witness_utxo = prev
        else:
            inp.witness_utxo = TransactionOutput(100_000, spk)
        if redeem is not None:
            inp.redeem_script = redeem
        if kind == "p2tr":
            inp.taproot_internal_key = pub
        return p

    def test_psbt_carries_no_derivation_fields(self):
        """Guards the premise: if these ever gain derivations the vectors are wrong."""
        for kind in self.KINDS:
            inp = self._build(kind).inputs[0]
            assert not inp.bip32_derivations, kind
            assert not inp.taproot_bip32_derivations, kind

    @pytest.mark.parametrize("kind", KINDS)
    def test_routing_agrees_with_signing(self, kind):
        """
        The regression. Routing must not claim a key cannot sign what it can sign:
        PSBTSelectSeedView drops the key and sends the user to the seed picker, where a
        WIF is not on offer at all.
        """
        key = WIFKey(self.PRIV.wif())
        p = self._build(kind)

        # The check used for seeds walks bip32_derivations, of which this psbt has
        # none -- so it answers False for a key that signs. That is the bug, and it is
        # why PSBTSelectSeedView needs a separate branch for raw keys rather than a
        # tweak to this one.
        assert PSBTParser.has_matching_input_fingerprint(
            psbt=p, seed=key, network=SettingsConstants.MAINNET
        ) is False, f"{kind}: premise changed -- fingerprint routing now finds something"

        routed = PSBTParser.wif_can_sign_any_input(psbt=p, wif_key=key)
        signed = p.sign_with(key.privkey)

        assert signed == 1, f"{kind}: key should sign its own input"
        assert routed is True, f"{kind}: routing said the key cannot sign, but it did"

    @pytest.mark.parametrize("kind", KINDS)
    def test_parses_signs_and_finalizes(self, kind):
        """The whole path a Satodime key takes, ending in a broadcastable transaction."""
        key = WIFKey(self.PRIV.wif())
        p = self._build(kind)

        parser = PSBTParser(p, seed=key, network=SettingsConstants.MAINNET)
        assert isinstance(parser.root, ec.PrivateKey)
        assert parser.num_inputs == 1
        assert parser.policy["type"] == kind

        assert p.sign_with(parser.root) == 1
        assert PSBTParser.sig_count(p) == 1

        tx = finalize_psbt(p)
        assert tx is not None, f"{kind}: finalize produced no transaction"
        assert len(tx.serialize()) > 0

    @pytest.mark.parametrize("kind", KINDS)
    def test_a_key_that_owns_nothing_is_not_routed(self, kind):
        """Routing is a hint, but it must not be a hint that points the wrong way."""
        stranger = WIFKey(ec.PrivateKey(bytes(31) + bytes([7])).wif())
        p = self._build(kind)

        assert PSBTParser.wif_can_sign_any_input(psbt=p, wif_key=stranger) is False
        assert p.sign_with(stranger.privkey) == 0

    def test_legacy_input_resolves_its_amount_from_the_previous_transaction(self):
        """
        p2pkh carries no witness_utxo, so the input amount can only come from
        non_witness_utxo. Worth pinning separately: it is the one script type whose
        utxo lookup goes down a different path.
        """
        key = WIFKey(self.PRIV.wif())
        p = self._build("p2pkh")
        assert p.inputs[0].witness_utxo is None
        assert p.inputs[0].non_witness_utxo is not None

        parser = PSBTParser(p, seed=key, network=SettingsConstants.MAINNET)
        assert parser.input_amount == 100_000
        assert parser.spend_amount == 90_000

    def test_signature_verifies_against_the_key(self):
        """A signature that does not verify would still count towards sig_count."""
        key = WIFKey(self.PRIV.wif())
        p = self._build("p2wpkh")
        p.sign_with(key.privkey)

        pub = self.PRIV.get_public_key()
        raw = p.inputs[0].partial_sigs[pub]
        assert raw[-1] == 0x01, "SIGHASH_ALL"

        from embit.psbt import SIGHASH

        sighash = p.sighash(0, sighash=SIGHASH.ALL)
        assert pub.verify(ec.Signature.parse(raw[:-1]), sighash)
