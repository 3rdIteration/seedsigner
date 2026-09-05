from binascii import a2b_base64
from unittest.mock import Mock

from embit.psbt import PSBT

from base import BaseTest, FlowTest, FlowStep
from psbt_testing_util import (PSBTTestData, claim_seed_owns_key, create_output,
    foreign_public_key)

from seedsigner.controller import Controller
from seedsigner.views.view import MainMenuView
from seedsigner.views import scan_views, seed_views, psbt_views
from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants


class TestPSBTFlows(FlowTest):

    def test_scan_psbt_first_then_correct_seedqr_flow(self):
        """
            Selecting "Scan" from the MainMenuView and scanning a PSBT should enter the PSBTSelectSeedView flow
            when Scan a Seed is selected from PSBTSelectSeedView it should enter the ScanView flow
            when a SeedQR is scanned it should enter the PSBTOverviewView flow
            since the PSBT has change no warning is displayed and it should enter the PSBTMathView flow
            since the PSBT is not a self transfer it should enter the PSBTAddressDetailsView flow
        """
        def load_psbt_into_decoder(view: scan_views.ScanView):
            """
                PSBT Tx and Wallet Details
                - Single Sig Wallet P2WPKH (Native Segwit) with no passphrase
                - Regtest c751dc07 m/84'/1'/0' tpubDDZBrnxMxbVzqt8EoEiABPxeKzFWma5pra5UEbg3Wst1hrwr6feuvcy7Sov7cpuYx94ypuy1PQ9NDNoQagFs37wGALzLb5Ei3FvyJWPPPKZ
                - 2 Inputs
                    - 56,522,834 sats
                    - 1,990,245,069 sats
                - 4 Outputs
                    - 1 Output to another wallet (bcrt1q7cw0wzy8g6mq5qvkpvhnk5gsps5ncy3srp0n2j) of 123,456 sats
                    - 3 Outputs change
                        - 3 outputs to emulate a fake mix to increase privacy
                        - Change addresses are index 1/7, 1/8, 1/9
                        - 1/7 address bcrt1q53j0xwuskuf5gnvynadh0hlazyy8srydlucrhg with amount 123,456 sats
                        - 1/8 address bcrt1q5gtw3zfp4cx67yk5q42q6j6rfza8aqcwpyyslv with amount 1,990,121,477 sats
                        - 1/9 address bcrt1q9rrg7399m43cn0yg4tz0v0ate89jgf2d6kpz7v with amount 56,399,242 sats
                    - Fee 272 sats
            """
            view.decoder.add_data("cHNidP8BANgCAAAAAsTXZs3fz/dmGb6M80+jjvJZdYya+cw5bT/dGuhZFdSlAAAAAAD9////qo6xg/UZAvUkcbse1F+C9zbP/FeZNjThx7SCIn6eMCgBAAAAAP3///8EQOIBAAAAAAAWABSkZPM7kLcTRE2En1t33/0RCHgMjQXYnnYAAAAAFgAUKMaPRKXdY4m8iKrE9j+rycskJU1A4gEAAAAAABYAFPYc9wiHRrYKAZYLLztREAwpPBIwipVcAwAAAAAWABSiFuiJIa4NrxLUBVQNS0NIun6DDtoRAABPAQQ1h88DBcQGZIAAAAA+0J+jlNL3dpWwlnBi8Dx+Ipg4e6uvB3HdjzFPX7r9CAOOlAIxgII+/xCcj+XoEenKH7wj5s5wlu7Q7CCZWFLGLhA5Su0UVAAAgAEAAIAAAACAAAEA7QIAAAAEE6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0BAAAAAP3///8TqeNf9+e+fuFuQohFzHM1gU5J9sJ015ad3sV7/VRxDQMAAAAA/f///xOp41/3575+4W5CiEXMczWBTkn2wnTXlp3exXv9VHENBAAAAAD9////E6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0GAAAAAP3///8CUnheAwAAAAAWABRCfygPJ+Fjsx4BknYvvm3A3qKn2xJ/XQcAAAAAF6kU1I4TAst5nAj15ey7vwe5cM3OFq+HlhEAAAEBH1J4XgMAAAAAFgAUQn8oDyfhY7MeAZJ2L75twN6ip9sBAwQBAAAAIgYCo7sfm78RQY3B5n0ac/QF8VtMAzFnci+h5D1MtpgRY7oYOUrtFFQAAIABAACAAAAAgAEAAAAGAAAAAAEAcQIAAAABxY7wh0nsfJQfzWrD/9rN9BYsM+iOmPaO6I0ANFgO/PcAAAAAAP3///8CptiUAAAAAAAWABRIm4HhQY/TzOjeWSPRrbuJo9MlW826oHYAAAAAFgAU0z+0L2QSLGtyQTn8FhbCpcI7jbliAQAAAQEfzbqgdgAAAAAWABTTP7QvZBIsa3JBOfwWFsKlwjuNuQEDBAEAAAAiBgITHmebEANk81CraV4xZIpqkNjjw0tIvezl1Ism1NRH3Rg5Su0UVAAAgAEAAIAAAACAAQAAAAAAAAAAIgICuTT7WnuiUTpObjWnZFHzIeEvW9PTB+1LLVFNQJVFeIIYOUrtFFQAAIABAACAAAAAgAEAAAAHAAAAACICAk8f3hpc5C35chgSg+Pe2zZ9IhHREd4aKW2+yAMRIFeqGDlK7RRUAACAAQAAgAAAAIABAAAACQAAAAAAIgIDjt1CjvrnMMnjbmTNKUAYoKEDRbmKjNjbq+6Ppqj3bqQYOUrtFFQAAIABAACAAAAAgAEAAAAIAAAAAA==")

        def load_seed_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("080115060387063104071857067618681125136207731354")
    
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),  # simulate read PSBT; ret val is ignored
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=load_seed_into_decoder),
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTAddressDetailsView, button_data_selection=0),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
            FlowStep(MainMenuView)
        ])

        # Run the same PSBT flow again, this time selecting the seed that the
        # previous flow left loaded in memory.
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView),
        ])

        # Selecting the existing seed should have set it as the signing seed
        assert self.controller.psbt_seed is self.controller.storage.seeds[0]


    def test_scan_psbt_first_then_load_electrum_seed(self):
        """
            Should be able to load an Electrum mnemonic after first loading in a psbt.
        """
        def load_psbt_into_decoder(view: scan_views.ScanView):
            # Single sig psbt for the below Electrum mnemonic
            view.decoder.add_data("cHNidP8BAHECAAAAAX9/d6VyI7nvVTyhLBfqu05za2AJ2Z0dKMC0cUX+S2U7AQAAAAD9////AgeHAAAAAAAAFgAUOnNPuZMD1sQudt3+7LvHBUvGhyd//gAAAAAAABYAFGO9QLvu4V9/hz6ZjbIGMrqsEiIYAjQTAAABAR+ghgEAAAAAABYAFKawrgcT62jmIVQwyHPCV0thmJWbAQDBAQAAAAABAYeHL9UQlz/jEKUuNNY3LTeQRjudjBinsP2L0ppvgRt0AAAAAAD/////AnbP3rsPAAAAIlEgtgmCioGjfKwp6f8rOoI4OPb+ZV8db581J9IizZPskl2ghgEAAAAAABYAFKawrgcT62jmIVQwyHPCV0thmJWbAUDCBlMh9VjZN2NdU9Wabi0o3Ct1q9YHTsJRLAkLfUuIHB+BE+ucR4bdGAJG5nBhCWOmCXbpRwKP1INRYvkuQ2fHAAAAACIGA2+PEYHyVy6nhYwAx5SJKBIWXjsWgjhhf/2FEWqXgxnoEKNOC3gAAACAAAAAAAAAAAAAACICA0SBeeHxfHdny6rUnQJuteAnQ7shSydexjJCkSJarn3mEKNOC3gAAACAAQAAAAEAAAAA")

        self.settings.set_value(SettingsConstants.SETTING__ELECTRUM_SEEDS, SettingsConstants.OPTION__ENABLED)

        sequence = [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),  # simulate read PSBT; ret val is ignored
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.TYPE_ELECTRUM),
            FlowStep(seed_views.SeedElectrumMnemonicStartView),
        ]

        # Load the associated Electrum mnemonic during the flow
        for word in "apple drip silly junior language resource unaware whale snake copy gravity tank".split():
            sequence += [
                FlowStep(seed_views.SeedMnemonicEntryView, screen_return_value=word),
            ]

        sequence += [
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMathView),
        ]

        self.run_sequence(sequence)


    def test_scan_multisig_psbt_seed_already_signed_flow(self):
        
        def load_psbt_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("cHNidP8BAIkCAAAAAc9dCSh2RcRPfHaT5bNVBpbg0jAekRLqOK+bpN/QA0jeAAAAAAD9////AtAHAAAAAAAAIlEg24shYsV3IRCzlgmMKjAsR4Ad9tX896z7zDAi5q0TU9H3CgAAAAAAACIAIByGQg/VP2aRID62ty40E64HYZeRRsKRGLt8J/76R6stQ04FAE8BBDWHzwSLLGdzgAAAAq3q6nR20JnHR+vKrBQdWxN9C7xU8zNX942mVF7AQpl2ArrdLwVlkGxaatQJ4wwkvypNBKbwOq9hXGLNlKi7rZWAFDUxzXUwAACAAQAAgAAAAIACAACATwEENYfPBHOCZmWAAAACmH6KTXIny0vueRgQFBq4M6oMuG8f1QM0I/RzKQ03bCgCHrF0fyUtV0+FD2N34u/woqb8MAt/o+7Ed58RddhY8zYUCUjSaDAAAIABAACAAAAAgAIAAIAAAQEriBMAAAAAAAAiACBY4WsjDgJXLj3VW222jU1tkIIhT26ce/2efH73BWGGBiICAqyfkrdUO662QBrdvJcSOZMFxniD7M1awm9U0Kb5XCm5RzBEAiAPkQTY84YjFFkpD6MI2cc5rJySqws5fsTQA/8XEZFpbAIgTNVykbEH4Z7bqyzhhy6lty0K8rtCUDCaHNv+47NNIWgBAQMEAQAAAAEFR1IhApL4XO+VE1pPYn5wnRFyJQKVSc9TX2dO6KIBH6jwvgPaIQKsn5K3VDuutkAa3byXEjmTBcZ4g+zNWsJvVNCm+VwpuVKuIgYCkvhc75UTWk9ifnCdEXIlApVJz1NfZ07oogEfqPC+A9ocNTHNdTAAAIABAACAAAAAgAIAAIAAAAAAAAAAACIGAqyfkrdUO662QBrdvJcSOZMFxniD7M1awm9U0Kb5XCm5HAlI0mgwAACAAQAAgAAAAIACAACAAAAAAAAAAAAAAAEBR1IhApYXaczuYbBM/A+EH639Ir2yIB4PxL46dK/I1V1O9aHgIQLa02HCI/+EP+9gGpxHskjYWFN5hZzXY7RRvwV4UF42ylKuIgIClhdpzO5hsEz8D4Qfrf0ivbIgHg/Evjp0r8jVXU71oeAcNTHNdTAAAIABAACAAAAAgAIAAIABAAAAAAAAACICAtrTYcIj/4Q/72AanEeySNhYU3mFnNdjtFG/BXhQXjbKHAlI0mgwAACAAQAAgAAAAIACAACAAQAAAAAAAAAA")
        
        def load_seed_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("073318950739065415961602009907670428187212261116")
            
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),  # simulate read PSBT; ret val is ignored
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=load_seed_into_decoder),
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTAddressDetailsView, button_data_selection=0),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.SKIP_VERIFICATION),
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSigningErrorView, button_data_selection=psbt_views.PSBTSigningErrorView.SELECT_DIFF_SEED),
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=load_seed_into_decoder),
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.TYPE_PASSPHRASE),
            FlowStep(seed_views.SeedAddPassphraseView, screen_return_value=dict(passphrase="abc")),
            FlowStep(seed_views.SeedReviewPassphraseView, button_data_selection=seed_views.SeedReviewPassphraseView.DONE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTAddressDetailsView, button_data_selection=0),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.SKIP_VERIFICATION),
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
            FlowStep(MainMenuView),
        ])


    def test_parse_and_display_op_return_content(self):
        """
            PSBTs that include an OP_RETURN should be able to be parsed like any other
            PSBT and route to the dedicated OP_RETURN View to display the content
        """
        def load_psbt_into_decoder(view: scan_views.ScanView):
            """
                PSBT Tx and Wallet Details
                - Single Sig Wallet P2WPKH (Native Segwit) with no passphrase
                - Regtest 0fb882ff m/84'/1'/0' tpubDCfk37PqcQx6nFtFVuYHvRLJHxvYj33NjHkKRyRmWyCjyJ64sYBXyVjsTHaLBp5GLhM91VBgJ8nKDWDu52J2xVRy64c7ybEjjyWQJuQGLcg
                - 1 Input
                    - 99,992,460 sats
                - 2 Outputs
                    - 1 Output back to self (bcrt1qvwkhakqhz7m7kmz6332avatsmdy32m644g86vv) of 99,992,296 sats
                    - 1 OP_RETURN: "Chancellor on the brink of third bailout"
                - Fee 164 sats
            """
            view.decoder.add_data("cHNidP8BAIYCAAAAATpQ10o+gKdZ8ThpKsbfHiHYn3NhvUrQ5DvW0ZWX8jKLAAAAAAD9////AujC9QUAAAAAFgAUY61+2BcXt+tsWoxV1nVw20kVb1UAAAAAAAAAACtqTChDaGFuY2VsbG9yIG9uIHRoZSBicmluayBvZiB0aGlyZCBiYWlsb3V0aQAAAE8BBDWHzwNXmUmVgAAAANRFa7R5gYD84Wbha3d1QnjgfYPOBw87on6cXS32WoyqAsPFtPxB7PRTdbujUnBPUVDh9YUBtwrl4nc0OcRNGvIyEA+4gv9UAACAAQAAgAAAAIAAAQB0AgAAAAGNFK/1X0fP5q+nu5XX7Tk2VRa0EL+jkGI9CHiJvsjZCgAAAAAA/f///wKMw/UFAAAAABYAFIpZMNnUU6cQt8Q0YpZ0pnvsSA5fAAAAAAAAAAAZakwWYml0Y29pbiBpcyBmcmVlIHNwZWVjaGgAAAABAR+Mw/UFAAAAABYAFIpZMNnUU6cQt8Q0YpZ0pnvsSA5fAQMEAQAAACIGAvxDI0eNI1oQ2AU69R7A0jf+hUdilWCgrWHgdzkqlaXMGA+4gv9UAACAAQAAgAAAAIAAAAAAAQAAAAAiAgK9qKtzGWyiRrpmupdA99NVLriz3GQy6cENbyD19sfl/hgPuIL/VAAAgAEAAIAAAACAAAAAAAIAAAAAAA==")

        def load_seed_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("114006021552133507590698063102151531110102551496")

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),  # simulate read PSBT; ret val is ignored
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=load_seed_into_decoder),
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),

            # Should route to display OP_RETURN content
            FlowStep(psbt_views.PSBTOpReturnView, button_data_selection=0),

            # Should be able to sign the psbt
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSignedQRDisplayView),
            FlowStep(MainMenuView)
        ])


    def test_scan_psbt_then_scan_wif_flow(self):
        from embit import ec, script, psbt
        from embit.transaction import Transaction, TransactionInput, TransactionOutput
        import os, base64

        # Enable WIF signing for this test
        self.settings.set_value(SettingsConstants.SETTING__WIF_KEYS, SettingsConstants.OPTION__ENABLED)

        priv = ec.PrivateKey(os.urandom(32))
        wif = priv.wif()
        pub = priv.get_public_key()
        spk = script.p2wpkh(pub)
        tx = Transaction(1, [TransactionInput(b"\x00" * 32, 0)], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].witness_utxo = TransactionOutput(1000, spk)
        psbt_b64 = base64.b64encode(p.serialize()).decode()

        def load_psbt_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(psbt_b64)

        def load_wif_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(wif)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SCAN_WIF),
            FlowStep(scan_views.ScanWIFQRView, before_run=load_wif_into_decoder),
            FlowStep(psbt_views.PSBTOverviewView),
        ])

    def test_scan_psbt_then_scan_bip38_flow(self):
        from embit import ec, script, psbt
        from embit.transaction import Transaction, TransactionInput, TransactionOutput
        import base64
        from seedsigner.models.bip38 import BIP38Key

        # Enable BIP38 signing for this test
        self.settings.set_value(SettingsConstants.SETTING__BIP38_KEYS, SettingsConstants.OPTION__ENABLED)

        enc = "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg"
        passphrase = "TestingOneTwoThree"
        priv = BIP38Key(enc).decrypt(passphrase).privkey
        pub = priv.get_public_key()
        spk = script.p2wpkh(pub)
        tx = Transaction(1, [TransactionInput(b"\x00" * 32, 0)], [TransactionOutput(900, spk)], 0)
        p = psbt.PSBT(tx)
        p.inputs[0].witness_utxo = TransactionOutput(1000, spk)
        psbt_b64 = base64.b64encode(p.serialize()).decode()

        def load_psbt_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(psbt_b64)

        def load_bip38_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(enc)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SCAN_BIP38),
            FlowStep(scan_views.ScanBIP38QRView, before_run=load_bip38_into_decoder),
            FlowStep(psbt_views.PSBTBIP38PassphraseView, screen_return_value=dict(passphrase=passphrase)),
            FlowStep(psbt_views.PSBTOverviewView),
        ])


class TestPSBTSatochip(FlowTest):

    def test_satochip_connect_failure_returns_to_select_menu(self, monkeypatch):
        """Satochip connection failure should return to the signer selection menu."""
        from seedsigner.views import scan_views, psbt_views
        from seedsigner.views.view import MainMenuView
        from seedsigner.helpers import seedkeeper_utils

        def load_psbt_into_decoder(view: scan_views.ScanView):
            # Single sig PSBT for tests
            view.decoder.add_data(
                "cHNidP8BAHECAAAAAX9/d6VyI7nvVTyhLBfqu05za2AJ2Z0dKMC0cUX+S2U7AQAAAAD9////AgeHAAAAAAAAFgAUOnNPuZMD1sQudt3+7LvHBUvGhyd//gAAAAAAABYAFGO9QLvu4V9/hz6ZjbIGMrqsEiIYAjQTAAABAR+ghgEAAAAAABYAFKawrgcT62jmIVQwyHPCV0thmJWbAQDBAQAAAAABAYeHL9UQlz/jEKUuNNY3LTeQRjudjBinsP2L0ppvgRt0AAAAAAD/////AnbP3rsPAAAAIlEgtgmCioGjfKwp6f8rOoI4OPb+ZV8db581J9IizZPskl2ghgEAAAAAABYAFKawrgcT62jmIVQwyHPCV0thmJWbAUDCBlMh9VjZN2NdU9Wabi0o3Ct1q9YHTsJRLAkLfUuIHB+BE+ucR4bdGAJG5nBhCWOmCXbpRwKP1INRYvkuQ2fHAAAAACIGA2+PEYHyVy6nhYwAx5SJKBIWXjsWgjhhf/2FEWqXgxnoEKNOC3gAAACAAAAAAAAAAAAAACICA0SBeeHxfHdny6rUnQJuteAnQ7shSydexjJCkSJarn3mEKNOC3gAAACAAQAAAAEAAAAA"
            )

        def mock_init_satochip(parent, init_card_filter=None, require_pin=True, backend_preference=None):
            return None

        monkeypatch.setattr(seedkeeper_utils, "init_satochip", mock_init_satochip)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SATOCHIP),
            FlowStep(psbt_views.PSBTSelectSeedView),
        ])

    def test_satochip_fingerprint_mismatch_shows_warning(self, monkeypatch):
        """Mismatch between card fingerprint and PSBT should warn and return to selection."""
        from embit.bip32 import HDKey
        from embit import networks
        from seedsigner.views import scan_views, psbt_views
        from seedsigner.views.view import MainMenuView
        from seedsigner.helpers import seedkeeper_utils

        def load_psbt_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(
                "cHNidP8BAHECAAAAAX9/d6VyI7nvVTyhLBfqu05za2AJ2Z0dKMC0cUX+S2U7AQAAAAD9////AgeHAAAAAAAAFgAUOnNPuZMD1sQudt3+7LvHBUvGhyd//gAAAAAAABYAFGO9QLvu4V9/hz6ZjbIGMrqsEiIYAjQTAAABAR+ghgEAAAAAABYAFKawrgcT62jmIVQwyHPCV0thmJWbAQDBAQAAAAABAYeHL9UQlz/jEKUuNNY3LTeQRjudjBinsP2L0ppvgRt0AAAAAAD/////AnbP3rsPAAAAIlEgtgmCioGjfKwp6f8rOoI4OPb+ZV8db581J9IizZPskl2ghgEAAAAAABYAFKawrgcT62jmIVQwyHPCV0thmJWbAUDCBlMh9VjZN2NdU9Wabi0o3Ct1q9YHTsJRLAkLfUuIHB+BE+ucR4bdGAJG5nBhCWOmCXbpRwKP1INRYvkuQ2fHAAAAACIGA2+PEYHyVy6nhYwAx5SJKBIWXjsWgjhhf/2FEWqXgxnoEKNOC3gAAACAAAAAAAAAAAAAACICA0SBeeHxfHdny6rUnQJuteAnQ7shSydexjJCkSJarn3mEKNOC3gAAACAAQAAAAEAAAAA"
            )

        seed = b"\x01" * 32
        root = HDKey.from_seed(seed, version=networks.NETWORKS["main"]["xprv"])
        master_xpub = root.to_public().to_base58()
        account_xpub = root.derive("m/84h/0h/0h").to_public().to_base58()

        class MockConnector:
            def card_bip32_get_xpub(self, path, xtype, is_mainnet):
                if path == "":
                    return master_xpub
                if path == "m/84'/0'/0'":
                    return account_xpub
                raise ValueError("unexpected path")

        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *args, **kwargs: MockConnector())

        controller = Controller.get_instance()
        controller.storage.seeds = []
        controller.psbt_parser = None
        controller.psbt_sign_with_satochip = False
        controller.Satochip_Connector = None

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTSelectSeedView),
        ])

        assert controller.psbt_parser is None
        assert controller.psbt_sign_with_satochip is False

    def test_satochip_2fa_enabled_blocks_signing(self, monkeypatch):
        """A card with 2FA enabled should warn and return to selection without signing."""
        from seedsigner.helpers import seedkeeper_utils

        def load_psbt_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(
                "cHNidP8BAHECAAAAAX9/d6VyI7nvVTyhLBfqu05za2AJ2Z0dKMC0cUX+S2U7AQAAAAD9////AgeHAAAAAAAAFgAUOnNPuZMD1sQudt3+7LvHBUvGhyd//gAAAAAAABYAFGO9QLvu4V9/hz6ZjbIGMrqsEiIYAjQTAAABAR+ghgEAAAAAABYAFKawrgcT62jmIVQwyHPCV0thmJWbAQDBAQAAAAABAYeHL9UQlz/jEKUuNNY3LTeQRjudjBinsP2L0ppvgRt0AAAAAAD/////AnbP3rsPAAAAIlEgtgmCioGjfKwp6f8rOoI4OPb+ZV8db581J9IizZPskl2ghgEAAAAAABYAFKawrgcT62jmIVQwyHPCV0thmJWbAUDCBlMh9VjZN2NdU9Wabi0o3Ct1q9YHTsJRLAkLfUuIHB+BE+ucR4bdGAJG5nBhCWOmCXbpRwKP1INRYvkuQ2fHAAAAACIGA2+PEYHyVy6nhYwAx5SJKBIWXjsWgjhhf/2FEWqXgxnoEKNOC3gAAACAAAAAAAAAAAAAACICA0SBeeHxfHdny6rUnQJuteAnQ7shSydexjJCkSJarn3mEKNOC3gAAACAAQAAAAEAAAAA"
            )

        class MockConnector:
            needs_2FA = True

        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *args, **kwargs: MockConnector())

        controller = Controller.get_instance()
        controller.storage.seeds = []
        controller.psbt_parser = None
        controller.psbt_sign_with_satochip = False
        controller.Satochip_Connector = None

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),
            # No seeds loaded -> index 0 is the SATOCHIP option. screen_return_value (not
            # button_data_selection) because the View shows a second, non-button Screen
            # (the 2FA warning) during this step.
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTSelectSeedView),
        ])

        assert controller.psbt_parser is None
        assert controller.psbt_sign_with_satochip is False


class TestPSBTMultisigDescriptorMismatch(BaseTest):

    def test_descriptor_mismatch_clears_descriptor_and_prompts(self):
        from embit import psbt
        from embit.descriptor import Descriptor

        from seedsigner.gui.screens.screen import WarningScreen, RET_CODE__BACK_BUTTON
        from seedsigner.models.psbt_parser import PSBTParser

        psbt_b64 = "cHNidP8BAIkCAAAAAc9dCSh2RcRPfHaT5bNVBpbg0jAekRLqOK+bpN/QA0jeAAAAAAD9////AtAHAAAAAAAAIlEg24shYsV3IRCzlgmMKjAsR4Ad9tX896z7zDAi5q0TU9H3CgAAAAAAACIAIByGQg/VP2aRID62ty40E64HYZeRRsKRGLt8J/76R6stQ04FAE8BBDWHzwSLLGdzgAAAAq3q6nR20JnHR+vKrBQdWxN9C7xU8zNX942mVF7AQpl2ArrdLwVlkGxaatQJ4wwkvypNBKbwOq9hXGLNlKi7rZWAFDUxzXUwAACAAQAAgAAAAIACAACATwEENYfPBHOCZmWAAAACmH6KTXIny0vueRgQFBq4M6oMuG8f1QM0I/RzKQ03bCgCHrF0fyUtV0+FD2N34u/woqb8MAt/o+7Ed58RddhY8zYUCUjSaDAAAIABAACAAAAAgAIAAIAAAQEriBMAAAAAAAAiACBY4WsjDgJXLj3VW222jU1tkIIhT26ce/2efH73BWGGBiICAqyfkrdUO662QBrdvJcSOZMFxniD7M1awm9U0Kb5XCm5RzBEAiAPkQTY84YjFFkpD6MI2cc5rJySqws5fsTQA/8XEZFpbAIgTNVykbEH4Z7bqyzhhy6lty0K8rtCUDCaHNv+47NNIWgBAQMEAQAAAAEFR1IhApL4XO+VE1pPYn5wnRFyJQKVSc9TX2dO6KIBH6jwvgPaIQKsn5K3VDuutkAa3byXEjmTBcZ4g+zNWsJvVNCm+VwpuVKuIgYCkvhc75UTWk9ifnCdEXIlApVJz1NfZ07oogEfqPC+A9ocNTHNdTAAAIABAACAAAAAgAIAAIAAAAAAAAAAACIGAqyfkrdUO662QBrdvJcSOZMFxniD7M1awm9U0Kb5XCm5HAlI0mgwAACAAQAAgAAAAIACAACAAAAAAAAAAAAAAAEBR1IhApYXaczuYbBM/A+EH639Ir2yIB4PxL46dK/I1V1O9aHgIQLa02HCI/+EP+9gGpxHskjYWFN5hZzXY7RRvwV4UF42ylKuIgIClhdpzO5hsEz8D4Qfrf0ivbIgHg/Evjp0r8jVXU71oeAcNTHNdTAAAIABAACAAAAAgAIAAIABAAAAAAAAACICAtrTYcIj/4Q/72AanEeySNhYU3mFnNdjtFG/BXhQXjbKHAlI0mgwAACAAQAAgAAAAIACAACAAQAAAAAAAAAA"

        psbt_obj = psbt.PSBT.from_string(psbt_b64)
        parser = PSBTParser(psbt_obj)
        parser.parse()

        self.controller.psbt = psbt_obj
        self.controller.psbt_parser = parser

        mismatch_descriptor = Descriptor.from_string(
            "wsh(sortedmulti(1,[3531cd75/48h/1h/0h/2h]tpubDEvs8aQCFkexBPVGJoqctrxgK9zeFwejWUWsAn7fKeSbbSUQ8sW6BJHrkKpNGRXwAfk7UWZDKz6amomvE2bo7DzokRtH8gnfweyQZf2ufFz/0/*,"
            "[0948d268/48h/1h/0h/2h]tpubDEkn1ih27ZcgHeu4tLzDw5EceCBa8hYMhRoCP7QmfijsrxDgchvMEC8ukFncE9Y7qBCBozBzYjEz4ophQ2quGRZsbN2bTziJxpLeK7mHq4L/0/*))"
        )
        self.controller.multisig_wallet_descriptor = mismatch_descriptor

        change_view = psbt_views.PSBTChangeDetailsView(change_address_num=0)
        change_view.run_screen = Mock(return_value=0)

        destination = change_view.run()

        assert self.controller.multisig_wallet_descriptor is None
        assert destination.View_cls == psbt_views.PSBTChangeDetailsView
        assert destination.view_args == {"change_address_num": 0}
        assert destination.skip_current_view is True

        change_view.run_screen.assert_called_once()
        args, kwargs = change_view.run_screen.call_args
        assert args[0] is WarningScreen
        assert kwargs["show_back_button"] is False
        assert len(kwargs["button_data"]) == 1
        assert kwargs["button_data"][0].button_label == "OK"

        follow_up_view = psbt_views.PSBTChangeDetailsView(change_address_num=0)
        follow_up_view.run_screen = Mock(return_value=RET_CODE__BACK_BUTTON)

        follow_up_destination = follow_up_view.run()

        follow_up_view.run_screen.assert_called_once()
        _, follow_up_kwargs = follow_up_view.run_screen.call_args
        assert follow_up_kwargs["button_data"][0] is follow_up_view.VERIFY_MULTISIG
        assert follow_up_kwargs["button_data"][1] is follow_up_view.SKIP_VERIFICATION
        assert follow_up_destination.View_cls.__name__ == "BackStackView"



class TestPSBTOwnershipClaimRouting(FlowTest):
    """
    A psbt carrying an ownership claim that does not hold up is rejected while it is being
    parsed, before the user is shown anything about the transaction. These cover the
    routing that turns that rejection into a warning screen instead of a crash.
    """

    def _load_psbt_for_signing(self, psbt: PSBT, seed: Seed = None):
        """
        Stage the psbt in the Controller and load the signing seed into storage, as if
        both had just been scanned. Each test's sequence then starts at seed selection;
        the parse itself runs when PSBTOverviewView is instantiated.
        """
        self.settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)
        self.controller.psbt = psbt
        self.controller.storage.set_pending_seed(seed if seed is not None else PSBTTestData.seed)
        self.controller.storage.finalize_pending_seed()


    def _psbt_with_change(self):
        psbt = PSBT.parse(a2b_base64(PSBTTestData.SINGLE_SIG_NATIVE_SEGWIT_1_INPUT))
        psbt.outputs.append(create_output(PSBTTestData.SINGLE_SIG_NATIVE_SEGWIT_CHANGE, 10_000))
        return psbt


    def test_forged_output_claim_terminates_signing_flow(self):
        """
        A forged ownership claim on an output is framed as a potential attack, so it
        routes to a warning that aborts the signing flow.
        """
        psbt = self._psbt_with_change()
        claim_seed_owns_key(psbt.outputs[0], "m/84h/1h/0h/1/0", foreign_public_key())
        self._load_psbt_for_signing(psbt)

        self.run_sequence([
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView, is_redirect=True),
            FlowStep(psbt_views.PSBTOutputOwnershipClaimFailedView, button_data_selection=psbt_views.PSBTOutputOwnershipClaimFailedView.DISCARD),
            FlowStep(MainMenuView),
        ])


    def test_forged_input_claim_terminates_signing_flow(self):
        """
        A false claim on an input is framed as inconsistent data rather than as an attack,
        but also routes to its own information screen that aborts the signing flow.
        """
        psbt = self._psbt_with_change()
        claim_seed_owns_key(psbt.inputs[0], "m/84h/1h/0h/0/0", foreign_public_key())
        self._load_psbt_for_signing(psbt)

        self.run_sequence([
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView, is_redirect=True),
            FlowStep(psbt_views.PSBTInputOwnershipClaimFailedView, button_data_selection=psbt_views.PSBTInputOwnershipClaimFailedView.DISCARD),
            FlowStep(MainMenuView),
        ])


    def test_wrong_seed_routes_back_to_seed_selection_flow(self):
        """
        The wrong seed for a psbt redirects before any transaction detail is rendered and
        routes back to seed selection with the signing seed cleared so another can be
        picked.
        """
        self._load_psbt_for_signing(self._psbt_with_change(), seed=PSBTTestData.recipient_seed)

        self.run_sequence([
            FlowStep(psbt_views.PSBTSelectSeedView, screen_return_value=0),
            FlowStep(psbt_views.PSBTOverviewView, is_redirect=True),
            FlowStep(psbt_views.PSBTSeedCannotSignView, button_data_selection=psbt_views.PSBTSeedCannotSignView.SELECT_DIFFERENT_SEED),
            FlowStep(psbt_views.PSBTSelectSeedView),
        ])

        assert self.controller.psbt_seed is None
        assert self.controller.psbt_parser is None

        # The psbt itself is kept: the user is choosing a different seed for it, not
        # starting over
        assert self.controller.psbt is not None
