# Must import test base before the Controller
from base import FlowTest, FlowStep

from seedsigner.controller import Controller
from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON, ButtonOption
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants, SettingsDefinition
from seedsigner.views.view import ErrorView, MainMenuView
from seedsigner.views import scan_views, seed_views, tools_views
from embit.bip32 import HDKey
from embit import bip39, networks
from seedsigner.helpers import seedkeeper_utils
from binascii import hexlify
from unittest import mock



class TestToolsFlows(FlowTest):

    def test__address_explorer__flow(self):
        """
            Test the simplest AddressExplorer flow when a seed is already loaded.
        """
        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon "* 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerSelectSourceView, screen_return_value=0),  # ret 1st onboard seed
            FlowStep(seed_views.SeedExportXpubScriptTypeView, button_data_selection=ButtonOption(SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__SCRIPT_TYPES).get_selection_option_display_name_by_value(SettingsConstants.NATIVE_SEGWIT), return_data=SettingsConstants.NATIVE_SEGWIT)),
            FlowStep(tools_views.ToolsAddressExplorerAddressTypeView, button_data_selection=tools_views.ToolsAddressExplorerAddressTypeView.RECEIVE),
            FlowStep(tools_views.ToolsAddressExplorerAddressListView, screen_return_value=10),  # ret NEXT page of addrs
            FlowStep(tools_views.ToolsAddressExplorerAddressListView, screen_return_value=4),  # ret a specific addr from the list
            FlowStep(tools_views.ToolsAddressExplorerAddressView),  # runs until dismissed; no ret value
            FlowStep(tools_views.ToolsAddressExplorerAddressListView),
        ])


    def test__address_explorer__loadseed__sideflow(self):
        """
            Finalizing a seed during the Address Explorer flow should return to the next
            Address Explorer step upon completion.
        """
        def load_seed_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("0000" * 11 + "0003")

        # Finalize the new seed w/out passphrase
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerSelectSourceView, button_data_selection=tools_views.ToolsAddressExplorerSelectSourceView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=load_seed_into_decoder),  # simulate read SeedQR
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(seed_views.SeedExportXpubScriptTypeView),
        ])

        assert self.controller.resume_main_flow == Controller.FLOW__ADDRESS_EXPLORER

        # Reset
        self.controller.storage.seeds.clear()
        self.controller.storage.set_pending_seed(Seed(mnemonic=["abandon "* 11 + "about"]))

        # Finalize the new seed w/passphrase
        self.run_sequence(
            sequence=[
                FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.TYPE_PASSPHRASE),
                FlowStep(seed_views.SeedAddPassphraseView, screen_return_value=dict(passphrase="mypassphrase")),
                FlowStep(seed_views.SeedReviewPassphraseView, button_data_selection=seed_views.SeedReviewPassphraseView.DONE),
                FlowStep(seed_views.SeedOptionsView, is_redirect=True),
                FlowStep(seed_views.SeedExportXpubScriptTypeView),
            ]
        )


    def test__address_explorer__load_electrum_seed__sideflow(self):
        """
            Loading an Electrum seed during the Address Explorer flow should return to
            the Address Explorer flow upon completion, skip the script type selection,
            and successfully generate receive or change addresses.
        """
        self.settings.set_value(SettingsConstants.SETTING__ELECTRUM_SEEDS, SettingsConstants.OPTION__ENABLED)

        sequence = [
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerSelectSourceView, button_data_selection=tools_views.ToolsAddressExplorerSelectSourceView.TYPE_ELECTRUM),
            FlowStep(seed_views.SeedElectrumMnemonicStartView),
        ]

        # Load an Electrum mnemonic during the flow (same one used in test_seed.py)
        for word in "regular reject rare profit once math fringe chase until ketchup century escape".split():
            sequence += [
                FlowStep(seed_views.SeedMnemonicEntryView, screen_return_value=word),
            ]

        sequence += [
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(seed_views.SeedExportXpubScriptTypeView, is_redirect=True),
            FlowStep(tools_views.ToolsAddressExplorerAddressTypeView, button_data_selection=tools_views.ToolsAddressExplorerAddressTypeView.RECEIVE),
            FlowStep(tools_views.ToolsAddressExplorerAddressListView),
        ]

        self.run_sequence(sequence)



    def test__address_explorer__scan_wrong_qrtype__flow(self):
        """
        Scanning the wrong type of QR code when a SeedQR is expected should route to ErrorView
        """
        def load_wrong_data_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")

        # Finalize the new seed w/out passphrase
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerSelectSourceView, button_data_selection=tools_views.ToolsAddressExplorerSelectSourceView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=load_wrong_data_into_decoder),  # simulate scanning the wrong QR type
            FlowStep(ErrorView),
        ])


    def test__address_explorer__back_button__flow(self):
        """
        Backing out of AddressExplorer behavior depends on current Settings:
        * Multiple script types enabled: BACK to SeedExportXpubScriptTypeView
        * One script type enabled: BACK to where we started:
            * SeedOptions
            * ToolsAddressExplorerSelectSourceView if seed was already onboard
            * MainMenu if no seed was onboard when we entered via ToolsMenu (loading a
                seed during the flow wipes out any history before the load so our only
                option is to return to MainMenu).
        """
        def load_seed_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("0000" * 11 + "0003")

        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon "* 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()

        # Scenario 1: Seed already onboard, multiple script types enabled, BACK can still
        #  change script type selection.
        self.settings.set_value(SettingsConstants.SETTING__SCRIPT_TYPES, [SettingsConstants.NATIVE_SEGWIT, SettingsConstants.TAPROOT])
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView, screen_return_value=0),  # select the first onboard seed
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.EXPLORER),
            FlowStep(seed_views.SeedExportXpubScriptTypeView, screen_return_value=0),
            FlowStep(tools_views.ToolsAddressExplorerAddressTypeView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(seed_views.SeedExportXpubScriptTypeView),
        ])

        # Scenario 2: Seed already onboard, one script type enabled, started from 
        # SeedOptionsView, BACK to SeedOptionsView.
        self.settings.set_value(SettingsConstants.SETTING__SCRIPT_TYPES, [SettingsConstants.NATIVE_SEGWIT])
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SEEDS),
            FlowStep(seed_views.SeedsMenuView, screen_return_value=0),  # select the first onboard seed
            FlowStep(seed_views.SeedOptionsView, button_data_selection=seed_views.SeedOptionsView.EXPLORER),
            FlowStep(seed_views.SeedExportXpubScriptTypeView, is_redirect=True),
            FlowStep(tools_views.ToolsAddressExplorerAddressTypeView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(seed_views.SeedOptionsView),
        ])

        # Scenario 3: Seed already onboard, one script type enabled, started from
        # ToolsMenu, BACK to ToolsAddressExplorerSelectSourceView.
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerSelectSourceView, screen_return_value=0),  # select the first onboard seed
            FlowStep(seed_views.SeedExportXpubScriptTypeView, is_redirect=True),
            FlowStep(tools_views.ToolsAddressExplorerAddressTypeView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(tools_views.ToolsAddressExplorerSelectSourceView),
        ])

        # Scenario 4: No seed onboard, one script type enabled, started from Tools, BACK
        # can only go to MainMenu because of mid-flow seed load.
        controller.discard_seed(0)
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerSelectSourceView, button_data_selection=tools_views.ToolsAddressExplorerSelectSourceView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=load_seed_into_decoder),  # simulate read SeedQR
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(seed_views.SeedExportXpubScriptTypeView, is_redirect=True),
            FlowStep(tools_views.ToolsAddressExplorerAddressTypeView, screen_return_value=RET_CODE__BACK_BUTTON),
            FlowStep(MainMenuView),
        ])


    def test__address_explorer__legacy_multisig_p2sh__flow(self):
        """
            Address Explorer should be able to parse a legacy multisig p2sh (m/45')
            descriptor and generate addresses.
        """
        def load_descriptor_into_decoder(view: scan_views.ScanView):
            # descriptor from test_psbt_parser.py
            p2sh_descriptor = "sh(sortedmulti(2,[0f889044/45h]tpubD8NkS3Gngj7L4FJRYrwojKhsx2seBhrNrXVdvqaUyvtVe1YDCVcziZVa9g3KouXz7FN5CkGBkoC16nmNu2HcG9ubTdtCbSW8DEXSMHmmu62/<0;1>/*,[03cd0a2b/45h]tpubD8HkLLgkdJkVitn1i9CN4HpFKJdom48iKm9PyiXYz5hivn1cGz6H3VeS6ncmCEgamvzQA2Qofu2YSTwWzvuaYWbJDEnvTUtj5R96vACdV6L/<0;1>/*,[769f695c/45h]tpubD98hRDKvtATTM8hy5Vvt5ZrvDXwJvrUZm1p1mTKDmd7FqUHY9Wj2k4X1CvxjjtTf3JoChWqYbnWjfkRJ65GQnpVJKbbMfjnGzCwoBUXafyM/<0;1>/*))#uardwtq4".replace("<0;1>", "{0,1}")
            view.decoder.add_data(p2sh_descriptor)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerSelectSourceView, button_data_selection=tools_views.ToolsAddressExplorerSelectSourceView.SCAN_DESCRIPTOR),
            FlowStep(scan_views.ScanWalletDescriptorView, before_run=load_descriptor_into_decoder),  # simulate read descriptor QR
            FlowStep(seed_views.MultisigWalletDescriptorView, button_data_selection=seed_views.MultisigWalletDescriptorView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerAddressTypeView, button_data_selection=tools_views.ToolsAddressExplorerAddressTypeView.RECEIVE),
            FlowStep(tools_views.ToolsAddressExplorerAddressListView, screen_return_value=10),  # ret NEXT page of addrs
            FlowStep(tools_views.ToolsAddressExplorerAddressListView, screen_return_value=4),  # ret a specific addr from the list
            FlowStep(tools_views.ToolsAddressExplorerAddressView),  # runs until dismissed; no ret value
            FlowStep(tools_views.ToolsAddressExplorerAddressListView),
        ])


    def test__address_explorer__satochip_descriptor__flow(self, monkeypatch):
        """Address Explorer should be able to load a descriptor from a Satochip card."""
        seed_bytes = bip39.mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        )
        root = HDKey.from_seed(seed_bytes, version=networks.NETWORKS["main"]["xprv"])
        derived_xpub = root.derive("m/84h/0h/0h").to_public().to_string()
        master_xpub = root.to_public().to_string()
        master_fingerprint = hexlify(root.my_fingerprint).decode()

        class MockConnector:
            def card_bip32_get_xpub(self, path, xtype, is_mainnet):
                if path == "":
                    return master_xpub
                elif path == "m/84'/0'/0'":
                    return derived_xpub
                raise ValueError("unexpected path")

            def card_get_status(self):
                return None, 0x90, 0x00, {"feature_schnorr_policy": 0}

        monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *args, **kwargs: MockConnector())

        controller = Controller.get_instance()
        controller.multisig_wallet_descriptor = None

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerSelectSourceView, button_data_selection=tools_views.ToolsAddressExplorerSelectSourceView.SATOCHIP),
            FlowStep(
                tools_views.SatochipLoadDescriptorScriptTypeView,
                button_data_selection=ButtonOption(
                    SettingsDefinition.get_settings_entry(SettingsConstants.SETTING__SCRIPT_TYPES).get_selection_option_display_name_by_value(SettingsConstants.NATIVE_SEGWIT),
                    return_data=SettingsConstants.NATIVE_SEGWIT,
                ),
            ),
            FlowStep(tools_views.SatochipLoadDescriptorDetailsView, screen_return_value=0),
            FlowStep(seed_views.MultisigWalletDescriptorView, button_data_selection=seed_views.MultisigWalletDescriptorView.ADDRESS_EXPLORER),
            FlowStep(tools_views.ToolsAddressExplorerAddressTypeView, button_data_selection=tools_views.ToolsAddressExplorerAddressTypeView.RECEIVE),
            FlowStep(tools_views.ToolsAddressExplorerAddressListView),
        ])

        descriptor = controller.multisig_wallet_descriptor
        assert hexlify(descriptor.keys[0].fingerprint).decode() == master_fingerprint


    def test__verify_address__legacy_multisig_p2sh__flow(self):
        """
            Address Explorer should be able to scan a legacy multisig p2sh address and
            verify it against its descriptor.
        """
        def load_address_into_decoder(view: scan_views.ScanView):
            # Receive addr @ index 5 from test_psbt_parser.py
            view.decoder.add_data("2N5eN5vUpgsLHAGzKm2VfmYyvNwXmCug5dH")

        def load_descriptor_into_decoder(view: scan_views.ScanView):
            # descriptor from test_psbt_parser.py
            p2sh_descriptor = "sh(sortedmulti(2,[0f889044/45h]tpubD8NkS3Gngj7L4FJRYrwojKhsx2seBhrNrXVdvqaUyvtVe1YDCVcziZVa9g3KouXz7FN5CkGBkoC16nmNu2HcG9ubTdtCbSW8DEXSMHmmu62/<0;1>/*,[03cd0a2b/45h]tpubD8HkLLgkdJkVitn1i9CN4HpFKJdom48iKm9PyiXYz5hivn1cGz6H3VeS6ncmCEgamvzQA2Qofu2YSTwWzvuaYWbJDEnvTUtj5R96vACdV6L/<0;1>/*,[769f695c/45h]tpubD98hRDKvtATTM8hy5Vvt5ZrvDXwJvrUZm1p1mTKDmd7FqUHY9Wj2k4X1CvxjjtTf3JoChWqYbnWjfkRJ65GQnpVJKbbMfjnGzCwoBUXafyM/<0;1>/*))#uardwtq4".replace("<0;1>", "{0,1}")
            view.decoder.add_data(p2sh_descriptor)
        
        settings = Controller.get_instance().settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.VERIFY_ADDRESS),
            FlowStep(scan_views.ScanAddressView, before_run=load_address_into_decoder),  # simulate read address QR
            FlowStep(seed_views.AddressVerificationStartView, is_redirect=True),
            FlowStep(seed_views.AddressVerificationSigTypeView, button_data_selection=seed_views.AddressVerificationSigTypeView.MULTISIG),
            FlowStep(seed_views.LoadMultisigWalletDescriptorView, button_data_selection=seed_views.LoadMultisigWalletDescriptorView.SCAN),
            FlowStep(scan_views.ScanWalletDescriptorView, before_run=load_descriptor_into_decoder),  # simulate read descriptor QR
            FlowStep(seed_views.MultisigWalletDescriptorView, screen_return_value=0),
            FlowStep(seed_views.SeedAddressVerificationView),
            FlowStep(seed_views.SeedAddressVerificationSuccessView),
        ])


    def test__verify_address__singlesig__flow(self):
        """
            Address Explorer should be able to scan a singlesig address and
            verify it against a loaded key.
        """
        controller = Controller.get_instance()
        controller.storage.set_pending_seed(Seed(mnemonic=["abandon "* 11 + "about"]))
        controller.storage.finalize_pending_seed()        
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)

        addrs = [
            # Native segwit regtest receive addr @ index 6
            "bcrt1q4e9q5taxnsvc6m0uxv6h75mkzvnkxeqk6l90u2",

            # Taproot regtest change addr @ index 0
            "bcrt1p6uav7en8k7zsumsqugdmg5j6930zmzy4dg7jcddshsr0fvxlqx7qnc7l22",

            # Legacy P2PKH mainnet receive addr @ index 0 (m/44'/0'/0')
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        ]

        for test_addr in addrs:
            def load_address_into_decoder(view: scan_views.ScanView):
                # Native segwit regtest receive addr @ index 6
                view.decoder.add_data(test_addr)

            self.run_sequence([
                FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.VERIFY_ADDRESS),
                FlowStep(scan_views.ScanAddressView, before_run=load_address_into_decoder),  # simulate read address QR
                FlowStep(seed_views.AddressVerificationStartView, is_redirect=True),
                FlowStep(seed_views.SeedSelectSeedView, screen_return_value=0),
                FlowStep(seed_views.SeedAddressVerificationView),
                FlowStep(seed_views.SeedAddressVerificationSuccessView),
            ])

    def test__seed_select_includes_satochip_for_verify_address(self):
        """Seed picker should offer Satochip option when verifying an address."""

        controller = Controller.get_instance()
        controller.storage.seeds.clear()
        view = seed_views.SeedSelectSeedView(flow=Controller.FLOW__VERIFY_SINGLESIG_ADDR)

        def fake_run_screen(*args, **kwargs):
            # Return immediately to inspect button_data
            return RET_CODE__BACK_BUTTON

        with mock.patch.object(view, "run_screen", side_effect=fake_run_screen) as mocked:
            view.run()
        button_data = mocked.call_args.kwargs["button_data"]
        assert seed_views.SeedSelectSeedView.SATOCHIP in button_data


    def test__verify_address__expanded_search__singlesig_default(self):
        """Singlesig address verification should start with simple search
        (detected path/type) which shows both Skip 10 and Cancel buttons."""
        controller = Controller.get_instance()
        controller.storage.set_pending_seed(Seed(mnemonic=["abandon " * 11 + "about"]))
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)

        controller.unverified_address = dict(
            address="bcrt1q4e9q5taxnsvc6m0uxv6h75mkzvnkxeqk6l90u2",
            script_type=SettingsConstants.NATIVE_SEGWIT,
            network=SettingsConstants.REGTEST,
            sig_type=SettingsConstants.SINGLE_SIG,
            derivation_path="m/84'/1'/0'",
        )

        view = seed_views.SeedAddressVerificationView(seed_num=0)

        def fake_run_screen(*args, **kwargs):
            return RET_CODE__BACK_BUTTON

        with mock.patch.object(view, "run_screen", side_effect=fake_run_screen) as mocked:
            view.run()

        button_data = mocked.call_args.kwargs["button_data"]
        assert seed_views.SeedAddressVerificationView.CANCEL in button_data
        assert seed_views.SeedAddressVerificationView.SKIP_10 in button_data


    def test__verify_address__expanded_search__flow(self, monkeypatch):
        """
            Singlesig address verification should find an address derived from
            a mismatched derivation path/script type combination (BIP44 path
            with native segwit addresses instead of the standard BIP84 path)
            after the user chooses "Expanded Search" from the simple not-found
            prompt.
        """
        from seedsigner.helpers import embit_utils

        # Use a small number of addresses per path to keep the test fast
        monkeypatch.setattr(seed_views.SeedAddressVerificationView, "EXPANDED_ADDRS_PER_PATH", 5)

        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon " * 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)

        # Generate a native segwit address from BIP44 (legacy) derivation path.
        # A single-path search on m/84'/1'/0' would NOT find this address.
        non_standard_path = "m/44'/1'/0'"
        xpub = seed.get_xpub(wallet_path=non_standard_path, network=SettingsConstants.REGTEST)
        embit_network = SettingsConstants.map_network_to_embit(SettingsConstants.REGTEST)
        test_addr = embit_utils.get_single_sig_address(
            xpub=xpub, script_type=SettingsConstants.NATIVE_SEGWIT,
            index=2, is_change=False, embit_network=embit_network,
        )

        def load_address_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(test_addr)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.VERIFY_ADDRESS),
            FlowStep(scan_views.ScanAddressView, before_run=load_address_into_decoder),
            FlowStep(seed_views.AddressVerificationStartView, is_redirect=True),
            FlowStep(seed_views.SeedSelectSeedView, screen_return_value=0),
            # Simple search won't find it (wrong path); batch exhausted
            FlowStep(seed_views.SeedAddressVerificationView),
            # User chooses "Expanded Search" from the not-found prompt
            FlowStep(seed_views.SeedAddressVerificationSimpleNotFoundView,
                     button_data_selection=seed_views.SeedAddressVerificationSimpleNotFoundView.EXPANDED_SEARCH),
            # Expanded search finds the address
            FlowStep(seed_views.SeedAddressVerificationView),
            FlowStep(seed_views.SeedAddressVerificationSuccessView),
        ])


    def test__verify_address__success_reports_derivation_path(self):
        """Success screen should report derivation path, script type, and
        non-standard flag when the address was found via expanded search."""
        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon " * 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)

        # Set up a non-standard match: native segwit address on BIP44 path
        non_standard_path = "m/44'/1'/0'"
        controller.unverified_address = dict(
            address="bcrt1q_fake",
            script_type=SettingsConstants.NATIVE_SEGWIT,
            network=SettingsConstants.REGTEST,
            sig_type=SettingsConstants.SINGLE_SIG,
            derivation_path=non_standard_path,
            verified_index=2,
            verified_index_is_change=False,
        )

        view = seed_views.SeedAddressVerificationSuccessView(seed_num=0)

        def fake_run_screen(*args, **kwargs):
            return 0

        with mock.patch.object(view, "run_screen", side_effect=fake_run_screen) as mocked:
            view.run()

        kwargs = mocked.call_args.kwargs
        assert kwargs["derivation_path"] == non_standard_path
        assert kwargs["script_type_display"] is not None
        assert kwargs["is_non_standard"] is True


    def test__verify_address__success_standard_path_not_flagged(self):
        """Success screen should not flag a standard derivation path as
        non-standard."""
        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon " * 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.REGTEST)

        standard_path = "m/84'/1'/0'"
        controller.unverified_address = dict(
            address="bcrt1q_fake",
            script_type=SettingsConstants.NATIVE_SEGWIT,
            network=SettingsConstants.REGTEST,
            sig_type=SettingsConstants.SINGLE_SIG,
            derivation_path=standard_path,
            verified_index=6,
            verified_index_is_change=False,
        )

        view = seed_views.SeedAddressVerificationSuccessView(seed_num=0)

        def fake_run_screen(*args, **kwargs):
            return 0

        with mock.patch.object(view, "run_screen", side_effect=fake_run_screen) as mocked:
            view.run()

        kwargs = mocked.call_args.kwargs
        assert kwargs["derivation_path"] == standard_path
        assert kwargs["is_non_standard"] is False


    def test__verify_address__cross_network_path__flow(self, monkeypatch):
        """
            Expanded search should find an address derived from a testnet
            derivation path even when the address format is mainnet.
            This covers wallets that use cross-network derivation paths.
        """
        from seedsigner.helpers import embit_utils

        monkeypatch.setattr(seed_views.SeedAddressVerificationView, "EXPANDED_ADDRS_PER_PATH", 5)

        controller = Controller.get_instance()
        seed = Seed(mnemonic=["together insane echo jeans lyrics cash window object trust visa jeans moral"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET)

        # Address derived from testnet path m/49'/1'/0' but with mainnet encoding
        # and LEGACY_P2PKH script type (non-standard combo)
        test_addr = "1ptQ7z81vUMLVvMj1rtdhv1bd58Aiset2"

        def load_address_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(test_addr)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.VERIFY_ADDRESS),
            FlowStep(scan_views.ScanAddressView, before_run=load_address_into_decoder),
            FlowStep(seed_views.AddressVerificationStartView, is_redirect=True),
            FlowStep(seed_views.SeedSelectSeedView, screen_return_value=0),
            # Simple search won't find it (cross-network path); batch exhausted
            FlowStep(seed_views.SeedAddressVerificationView),
            # User chooses "Expanded Search"
            FlowStep(seed_views.SeedAddressVerificationSimpleNotFoundView,
                     button_data_selection=seed_views.SeedAddressVerificationSimpleNotFoundView.EXPANDED_SEARCH),
            # Expanded search finds the address
            FlowStep(seed_views.SeedAddressVerificationView),
            FlowStep(seed_views.SeedAddressVerificationSuccessView),
        ])


    def test__verify_address__expanded_not_found__shows_failure(self, monkeypatch):
        """When the simple search exhausts its batch without a match, it should
        route to SeedAddressVerificationSimpleNotFoundView."""
        monkeypatch.setattr(seed_views.SeedAddressVerificationView, "SIMPLE_SEARCH_BATCH_SIZE", 10)

        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon " * 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET)

        # Use an address that definitely won't match
        controller.unverified_address = dict(
            address="1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            script_type=SettingsConstants.LEGACY_P2PKH,
            network=SettingsConstants.MAINNET,
            sig_type=SettingsConstants.SINGLE_SIG,
            derivation_path="m/44'/0'/0'",
        )

        view = seed_views.SeedAddressVerificationView(seed_num=0)

        def fake_run_screen(*args, **kwargs):
            return None

        with mock.patch.object(view, "run_screen", side_effect=fake_run_screen):
            destination = view.run()

        assert destination.View_cls == seed_views.SeedAddressVerificationSimpleNotFoundView
        assert destination.view_args["seed_num"] == 0
        assert destination.view_args["addrs_checked"] >= 10
        assert destination.view_args["next_start_index"] >= 10


    def test__verify_address__expanded_not_found__after_expanded(self, monkeypatch):
        """When the expanded search exhausts all paths without a match, it should
        route to SeedAddressVerificationNotFoundView."""
        monkeypatch.setattr(seed_views.SeedAddressVerificationView, "EXPANDED_ADDRS_PER_PATH", 2)

        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon " * 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET)

        controller.unverified_address = dict(
            address="1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            script_type=SettingsConstants.LEGACY_P2PKH,
            network=SettingsConstants.MAINNET,
            sig_type=SettingsConstants.SINGLE_SIG,
            derivation_path="m/44'/0'/0'",
        )

        view = seed_views.SeedAddressVerificationView(seed_num=0, use_expanded=True)

        def fake_run_screen(*args, **kwargs):
            return None

        with mock.patch.object(view, "run_screen", side_effect=fake_run_screen):
            destination = view.run()

        assert destination.View_cls == seed_views.SeedAddressVerificationNotFoundView
        assert destination.view_args["seed_num"] == 0
        assert destination.view_args["addrs_per_path_checked"] == 2
        assert destination.view_args["next_start_index"] == 2


    def test__verify_address__not_found_check_next__flow(self):
        """The 'Check Next 10' button on the expanded not-found screen should route
        back to SeedAddressVerificationView with the next start index and
        use_expanded=True."""
        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon " * 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET)

        controller.unverified_address = dict(
            address="1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            script_type=SettingsConstants.LEGACY_P2PKH,
            network=SettingsConstants.MAINNET,
            sig_type=SettingsConstants.SINGLE_SIG,
            derivation_path="m/44'/0'/0'",
        )

        view = seed_views.SeedAddressVerificationNotFoundView(
            seed_num=0, addrs_per_path_checked=10, next_start_index=10,
        )

        def fake_run_screen(*args, **kwargs):
            # Simulate pressing "Check Next 10" (first button = index 0)
            return 0

        with mock.patch.object(view, "run_screen", side_effect=fake_run_screen):
            destination = view.run()

        assert destination.View_cls == seed_views.SeedAddressVerificationView
        assert destination.view_args["seed_num"] == 0
        assert destination.view_args["expanded_start_index"] == 10
        assert destination.view_args["use_expanded"] is True


    def test__verify_address__not_found_done__flow(self):
        """The 'Done' button on the not-found screen should route to MainMenuView."""
        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon " * 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET)

        controller.unverified_address = dict(
            address="1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            script_type=SettingsConstants.LEGACY_P2PKH,
            network=SettingsConstants.MAINNET,
            sig_type=SettingsConstants.SINGLE_SIG,
            derivation_path="m/44'/0'/0'",
        )

        view = seed_views.SeedAddressVerificationNotFoundView(
            seed_num=0, addrs_per_path_checked=100, next_start_index=100,
        )

        def fake_run_screen(*args, **kwargs):
            # Simulate pressing "Done" (second button = index 1)
            return 1

        with mock.patch.object(view, "run_screen", side_effect=fake_run_screen):
            destination = view.run()

        assert destination.View_cls == MainMenuView


    def test__verify_address__nested_segwit_singlesig__flow(self, monkeypatch):
        """Expanded search should find a Nested Segwit (P2SH-P2WPKH) address
        at its standard BIP49 derivation path."""
        from seedsigner.helpers import embit_utils

        monkeypatch.setattr(seed_views.SeedAddressVerificationView, "EXPANDED_ADDRS_PER_PATH", 5)

        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon " * 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET)

        # Standard BIP49 nested segwit mainnet address at index 0
        xpub = seed.get_xpub(wallet_path="m/49'/0'/0'", network=SettingsConstants.MAINNET)
        embit_network = SettingsConstants.map_network_to_embit(SettingsConstants.MAINNET)
        test_addr = embit_utils.get_single_sig_address(
            xpub=xpub, script_type=SettingsConstants.NESTED_SEGWIT,
            index=0, is_change=False, embit_network=embit_network,
        )

        def load_address_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(test_addr)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.VERIFY_ADDRESS),
            FlowStep(scan_views.ScanAddressView, before_run=load_address_into_decoder),
            FlowStep(seed_views.AddressVerificationStartView, is_redirect=True),
            # Nested segwit requires sig type selection
            FlowStep(seed_views.AddressVerificationSigTypeView, button_data_selection=seed_views.AddressVerificationSigTypeView.SINGLE_SIG),
            FlowStep(seed_views.SeedSelectSeedView, screen_return_value=0),
            FlowStep(seed_views.SeedAddressVerificationView),
            FlowStep(seed_views.SeedAddressVerificationSuccessView),
        ])


    def test__verify_address__expanded_search_ignores_disabled_script_types(self, monkeypatch):
        """Expanded search should find addresses for ALL script types even
        when they are disabled in Settings (recovery feature)."""
        from seedsigner.helpers import embit_utils

        monkeypatch.setattr(seed_views.SeedAddressVerificationView, "EXPANDED_ADDRS_PER_PATH", 5)

        controller = Controller.get_instance()
        seed = Seed(mnemonic=["abandon " * 11 + "about"])
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET)

        # Restrict settings to ONLY native segwit (LEGACY_P2PKH is disabled)
        settings.set_value(SettingsConstants.SETTING__SCRIPT_TYPES, [SettingsConstants.NATIVE_SEGWIT])

        # Use a Legacy P2PKH address — its script type is disabled in settings
        xpub = seed.get_xpub(wallet_path="m/44'/0'/0'", network=SettingsConstants.MAINNET)
        embit_network = SettingsConstants.map_network_to_embit(SettingsConstants.MAINNET)
        test_addr = embit_utils.get_single_sig_address(
            xpub=xpub, script_type=SettingsConstants.LEGACY_P2PKH,
            index=0, is_change=False, embit_network=embit_network,
        )

        def load_address_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(test_addr)

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.VERIFY_ADDRESS),
            FlowStep(scan_views.ScanAddressView, before_run=load_address_into_decoder),
            FlowStep(seed_views.AddressVerificationStartView, is_redirect=True),
            FlowStep(seed_views.SeedSelectSeedView, screen_return_value=0),
            FlowStep(seed_views.SeedAddressVerificationView),
            FlowStep(seed_views.SeedAddressVerificationSuccessView),
        ])


    def test__verify_address__bug_report_all_script_types(self, monkeypatch):
        """
            Regression test for the bug report: addresses at m/44'/0'/0'/0/0 (P2PKH),
            m/49'/0'/0'/0/0 (Nested Segwit), m/84'/0'/0'/0/0 (Native Segwit), and
            m/86'/0'/0'/0/0 (Taproot) should all be found by the expanded search.

            Uses the exact mnemonic from the bug report plus a Taproot address
            for complete coverage of all 4 script types.
        """
        monkeypatch.setattr(seed_views.SeedAddressVerificationView, "EXPANDED_ADDRS_PER_PATH", 5)

        controller = Controller.get_instance()
        mnemonic = "nerve oven detect rookie refuse double combine lyrics broom noble obey auto fuel print river vapor salon glow select east amused decide guess helmet"
        seed = Seed(mnemonic=mnemonic.split())
        controller.storage.set_pending_seed(seed)
        controller.storage.finalize_pending_seed()
        settings = controller.settings
        settings.set_value(SettingsConstants.SETTING__NETWORK, SettingsConstants.MAINNET)

        # Addresses from the bug report + Taproot for complete coverage
        test_cases = [
            # (address, requires_sig_type_selection)
            ("1PgAiLuE71xmy67htmn4PVaSBNwFonaC15", False),   # Legacy P2PKH m/44'/0'/0'/0/0
            ("39X53GD2W1rNzVkew5wTWU5tFba8NSxXG5", True),    # Nested Segwit m/49'/0'/0'/0/0
            ("bc1qf8sxhhpswt7jpea2lgxdj0yp0xzadcc6x3qf0a", False),  # Native Segwit m/84'/0'/0'/0/0
            ("bc1p36p22wa9td3p9q9e4ruj6cr86qlrpah8267uyf7799485277x6uqgsnqpc", False),  # Taproot m/86'/0'/0'/0/0
        ]

        for test_addr, needs_sig_type in test_cases:
            def load_address_into_decoder(view: scan_views.ScanView):
                view.decoder.add_data(test_addr)

            if needs_sig_type:
                # Nested segwit requires sig type selection
                self.run_sequence([
                    FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                    FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.VERIFY_ADDRESS),
                    FlowStep(scan_views.ScanAddressView, before_run=load_address_into_decoder),
                    FlowStep(seed_views.AddressVerificationStartView, is_redirect=True),
                    FlowStep(seed_views.AddressVerificationSigTypeView, button_data_selection=seed_views.AddressVerificationSigTypeView.SINGLE_SIG),
                    FlowStep(seed_views.SeedSelectSeedView, screen_return_value=0),
                    FlowStep(seed_views.SeedAddressVerificationView),
                    FlowStep(seed_views.SeedAddressVerificationSuccessView),
                ])
            else:
                self.run_sequence([
                    FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
                    FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.VERIFY_ADDRESS),
                    FlowStep(scan_views.ScanAddressView, before_run=load_address_into_decoder),
                    FlowStep(seed_views.AddressVerificationStartView, is_redirect=True),
                    FlowStep(seed_views.SeedSelectSeedView, screen_return_value=0),
                    FlowStep(seed_views.SeedAddressVerificationView),
                    FlowStep(seed_views.SeedAddressVerificationSuccessView),
                ])
