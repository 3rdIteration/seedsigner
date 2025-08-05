from gettext import gettext as _

from binascii import hexlify
from embit import bip32
import logging

from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings import SettingsConstants
from seedsigner.gui.components import FontAwesomeIconConstants, SeedSignerIconConstants
from seedsigner.gui.screens.screen import (RET_CODE__BACK_BUTTON, ButtonListScreen, ButtonOption, WarningScreen, DireWarningScreen, QRDisplayScreen)
from seedsigner.views.view import BackStackView, MainMenuView, NotYetImplementedView, View, Destination

logger = logging.getLogger(__name__)



class PSBTSelectSeedView(View):
    SCAN_SEED = ButtonOption("Scan a seed", SeedSignerIconConstants.QRCODE)
    SATOCHIP = ButtonOption("Use Satochip card", SeedSignerIconConstants.FINGERPRINT)
    TYPE_12WORD = ButtonOption("Enter 12-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=12)
    TYPE_15WORD = ButtonOption("Enter 15-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=15)
    TYPE_18WORD = ButtonOption("Enter 18-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=18)
    TYPE_21WORD = ButtonOption("Enter 21-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=21)
    TYPE_24WORD = ButtonOption("Enter 24-word seed", FontAwesomeIconConstants.KEYBOARD, return_data=24)
    TYPE_ELECTRUM = ButtonOption("Enter Electrum seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_WIF = ButtonOption("Enter WIF", FontAwesomeIconConstants.KEYBOARD)
    SCAN_WIF = ButtonOption("Scan WIF", SeedSignerIconConstants.QRCODE)
    TYPE_BIP38 = ButtonOption("Enter BIP38", FontAwesomeIconConstants.KEYBOARD)
    SCAN_BIP38 = ButtonOption("Scan BIP38", SeedSignerIconConstants.QRCODE)


    def run(self):
        from seedsigner.controller import Controller

        # Note: we can't just autoroute to the PSBT Overview because we might have a
        # multisig where we want to sign with more than one key on this device.
        if not self.controller.psbt:
            # Shouldn't be able to get here
            raise Exception("No PSBT currently loaded")

        if self.controller.psbt_seed:
             if PSBTParser.has_matching_input_fingerprint(psbt=self.controller.psbt, seed=self.controller.psbt_seed, network=self.settings.get_value(SettingsConstants.SETTING__NETWORK)):
                 # skip the seed prompt if a seed was previous selected and has matching input fingerprint
                 return Destination(PSBTOverviewView)

        seeds = self.controller.storage.seeds
        button_data = []
        for seed in seeds:
            button_str = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            if not PSBTParser.has_matching_input_fingerprint(psbt=self.controller.psbt, seed=seed, network=self.settings.get_value(SettingsConstants.SETTING__NETWORK)):
                # Doesn't look like this seed can sign the current PSBT
                # TRANSLATOR_NOTE: Inserts fingerprint w/"?" to indicate that this seed can't sign the current PSBT
                button_str = _("{} (?)").format(button_str)

            button_data.append(ButtonOption(button_str, SeedSignerIconConstants.FINGERPRINT))

        button_data.append(self.SATOCHIP)
        button_data.append(self.SCAN_SEED)
        if self.settings.get_value(SettingsConstants.SETTING__WIF_KEYS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.SCAN_WIF)
        if self.settings.get_value(SettingsConstants.SETTING__BIP38_KEYS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.SCAN_BIP38)
        seed_lengths = self.settings.get_value(SettingsConstants.SETTING__SEED_WORD_LENGTHS)
        options = {
            12: self.TYPE_12WORD,
            15: self.TYPE_15WORD,
            18: self.TYPE_18WORD,
            21: self.TYPE_21WORD,
            24: self.TYPE_24WORD,
        }
        for l in seed_lengths:
            button_data.append(options[l])
        if self.settings.get_value(SettingsConstants.SETTING__ELECTRUM_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_ELECTRUM)
        if self.settings.get_value(SettingsConstants.SETTING__WIF_KEYS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_WIF)
        if self.settings.get_value(SettingsConstants.SETTING__BIP38_KEYS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_BIP38)

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Select Signer"),
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if len(seeds) > 0 and selected_menu_num < len(seeds):
            # User selected one of the n seeds
            self.controller.psbt_seed = self.controller.get_seed(selected_menu_num)
            return Destination(PSBTOverviewView)
        
        # The remaining flows are a sub-flow; resume PSBT flow once the seed is loaded.
        self.controller.resume_main_flow = Controller.FLOW__PSBT

        if button_data[selected_menu_num] == self.SCAN_SEED:
            from seedsigner.views.scan_views import ScanSeedQRView
            return Destination(ScanSeedQRView)

        elif button_data[selected_menu_num] == self.SCAN_WIF:
            from seedsigner.views.scan_views import ScanWIFQRView
            return Destination(ScanWIFQRView)

        elif button_data[selected_menu_num] == self.SCAN_BIP38:
            from seedsigner.views.scan_views import ScanBIP38QRView
            return Destination(ScanBIP38QRView)

        elif button_data[selected_menu_num] == self.SATOCHIP:
            from seedsigner.helpers import seedkeeper_utils
            from embit.bip32 import HDKey

            connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])
            if not connector:
                return Destination(PSBTSelectSeedView, clear_history=True)

            network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            is_mainnet = network == SettingsConstants.MAINNET
            first_der = next(iter(self.controller.psbt.inputs[0].bip32_derivations.values())).derivation
            account_path = []
            HARDENED_INDEX = 0x80000000
            for idx in first_der:
                if idx & HARDENED_INDEX:
                    account_path.append(idx)
                else:
                    break

            account_path_str = "m"
            for i in account_path:
                hardened = bool(i & HARDENED_INDEX)
                index = i & 0x7FFFFFFF
                suffix = "'" if hardened else ""
                account_path_str += f"/{index}{suffix}"

            purpose = account_path[0] & 0x7FFFFFFF if account_path else 0
            xtype = {
                44: "standard",
                49: "p2wpkh-p2sh",
                84: "p2wpkh",
                48: "p2wsh-p2sh" if len(account_path) > 3 and (account_path[3] & 0x7FFFFFFF) == 1 else "p2wsh",
            }.get(purpose, "standard")

            from seedsigner.gui.screens.screen import LoadingScreenThread
            loading = LoadingScreenThread(text=_("Parsing PSBT..."))
            loading.start()
            try:
                try:
                    account_xpub = connector.card_bip32_get_xpub(account_path_str, xtype, is_mainnet)
                    master_xpub = connector.card_bip32_get_xpub("", xtype, is_mainnet)
                except Exception as e:
                    logger.exception("Failed to export xpub from Satochip card")
                    self.run_screen(
                        WarningScreen,
                        title="Failed",
                        status_headline=None,
                        text=str(e),
                    )
                    return Destination(PSBTSelectSeedView, clear_history=True)

                root_key = HDKey.from_base58(account_xpub)
                master_fp = HDKey.from_base58(master_xpub).my_fingerprint

                try:
                    self.controller.psbt_parser = PSBTParser(
                        self.controller.psbt,
                        seed=None,
                        root=root_key,
                        root_path=account_path,
                        master_fingerprint=master_fp,
                        network=network,
                    )
                except Exception as e:
                    logger.exception("Failed to parse PSBT with Satochip data")
                    self.run_screen(
                        WarningScreen,
                        title="Failed",
                        status_headline=None,
                        text=str(e),
                    )
                    return Destination(PSBTSelectSeedView, clear_history=True)
            finally:
                loading.stop()

            self.controller.psbt_seed = None
            self.controller.psbt_sign_with_satochip = True
            return Destination(PSBTOverviewView)

        elif button_data[selected_menu_num] in [self.TYPE_12WORD, self.TYPE_15WORD, self.TYPE_18WORD, self.TYPE_21WORD, self.TYPE_24WORD]:
            from seedsigner.views.seed_views import SeedMnemonicEntryView
            self.controller.storage.init_pending_mnemonic(num_words=button_data[selected_menu_num].return_data)
            return Destination(SeedMnemonicEntryView)

        elif button_data[selected_menu_num] == self.TYPE_ELECTRUM:
            from seedsigner.views.seed_views import SeedElectrumMnemonicStartView
            return Destination(SeedElectrumMnemonicStartView)

        elif button_data[selected_menu_num] == self.TYPE_WIF:
            return Destination(PSBTWIFEntryView)

        elif button_data[selected_menu_num] == self.TYPE_BIP38:
            return Destination(PSBTBIP38EntryView)



class PSBTWIFEntryView(View):
    def run(self):
        from seedsigner.gui.screens import seed_screens

        ret = self.run_screen(
            seed_screens.SeedAddPassphraseScreen,
            title=_("Private Key (WIF)"),
            passphrase="",
        )

        if "is_back_button" in ret:
            return Destination(BackStackView)

        wif = ret["passphrase"]
        from seedsigner.models.wif import WIFKey
        from seedsigner.models.seed import InvalidSeedException

        try:
            key = WIFKey(wif)
        except InvalidSeedException:
            self.run_screen(
                DireWarningScreen,
                status_headline=_("Invalid WIF!"),
                text=_("Not a valid WIF-encoded private key."),
                button_data=[ButtonOption("OK")],
                show_back_button=False,
            )
            return Destination(PSBTSelectSeedView)

        self.controller.psbt_seed = key
        return Destination(PSBTOverviewView)


class PSBTBIP38EntryView(View):
    def run(self):
        from seedsigner.gui.screens import seed_screens

        ret = self.run_screen(
            seed_screens.SeedAddPassphraseScreen,
            title=_("BIP38 Key"),
            passphrase="",
        )

        if "is_back_button" in ret:
            return Destination(BackStackView)

        bip38 = ret["passphrase"]
        return Destination(PSBTBIP38PassphraseView, view_args=dict(encrypted=bip38))


class PSBTBIP38PassphraseView(View):
    def __init__(self, encrypted: str):
        super().__init__()
        self.encrypted = encrypted

    def run(self):
        from seedsigner.gui.screens import seed_screens
        from seedsigner.models.bip38 import BIP38Key
        from seedsigner.models.seed import InvalidSeedException

        ret = self.run_screen(
            seed_screens.SeedAddPassphraseScreen,
            title=_("BIP38 Passphrase"),
            passphrase="",
        )

        if "is_back_button" in ret:
            return Destination(BackStackView)

        passphrase = ret["passphrase"]
        try:
            key = BIP38Key(self.encrypted).decrypt(passphrase, self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        except InvalidSeedException:
            self.run_screen(
                DireWarningScreen,
                status_headline=_("Invalid BIP38!"),
                text=_("Could not decrypt BIP38 key."),
                button_data=[ButtonOption("OK")],
                show_back_button=False,
            )
            return Destination(PSBTSelectSeedView)

        self.controller.psbt_seed = key
        return Destination(PSBTOverviewView)

class PSBTOverviewView(View):
    def __init__(self):
        super().__init__()

        self.loading_screen = None

        if not self.controller.psbt_parser or self.controller.psbt_parser.seed != self.controller.psbt_seed:
            # The PSBTParser takes a while to read the PSBT. Run the loading screen while
            # we wait.
            from seedsigner.gui.screens.screen import LoadingScreenThread
            self.loading_screen = LoadingScreenThread(text=_("Parsing PSBT..."))
            self.loading_screen.start()
                
            try:
                self.controller.psbt_parser = PSBTParser(
                    self.controller.psbt,
                    seed=self.controller.psbt_seed,
                    network=self.settings.get_value(SettingsConstants.SETTING__NETWORK)
                )
            except Exception as e:
                self.loading_screen.stop()
                raise e


    def run(self):
        from seedsigner.gui.screens.psbt_screens import PSBTOverviewScreen
        psbt_parser = self.controller.psbt_parser

        change_data = psbt_parser.change_data
        """
            change_data = [
                {
                    'address': 'bc1q............', 
                    'amount': 397621401, 
                    'fingerprint': ['22bde1a9', '73c5da0a'], 
                    'derivation_path': ['m/48h/1h/0h/2h/1/0', 'm/48h/1h/0h/2h/1/0']
                }, {},
            ]
        """
        num_change_outputs = 0
        num_self_transfer_outputs = 0
        for change_output in change_data:
            path_ints = bip32.parse_path(change_output["derivation_path"][0])
            if len(path_ints) >= 2 and (path_ints[-2] & 0x7FFFFFFF) == 1:
                num_change_outputs += 1
            else:
                num_self_transfer_outputs += 1

        # Everything is set. Stop the loading screen
        if self.loading_screen:
            self.loading_screen.stop()

        # Run the overview screen
        selected_menu_num = self.run_screen(
            PSBTOverviewScreen,
            spend_amount=psbt_parser.spend_amount,
            change_amount=psbt_parser.change_amount,
            fee_amount=psbt_parser.fee_amount,
            num_inputs=psbt_parser.num_inputs,
            num_self_transfer_outputs=num_self_transfer_outputs,
            num_change_outputs=num_change_outputs,
            destination_addresses=psbt_parser.destination_addresses,
            has_op_return=psbt_parser.op_return_data is not None,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            self.controller.psbt_seed = None
            return Destination(BackStackView)

        # expecting p2sh (legacy multisig) and p2pkh to have no policy set
        # skip change warning and psbt math view
        if psbt_parser.policy == None:
            return Destination(PSBTUnsupportedScriptTypeWarningView)
        
        elif psbt_parser.change_amount == 0:
            return Destination(PSBTNoChangeWarningView)

        else:
            return Destination(PSBTMathView)



class PSBTUnsupportedScriptTypeWarningView(View):
    def run(self):
        selected_menu_num = WarningScreen(
            status_headline=_("Unsupported Script Type!"),
            text=_("PSBT has unsupported input script type, please verify your change addresses."),
            button_data=[ButtonOption("Continue")],
        ).display()
        
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        # Only one exit point
        # skip PSBTMathView
        return Destination(
            PSBTAddressDetailsView, view_args={"address_num": 0},
            skip_current_view=True,  # Prevent going BACK to WarningViews
        )



class PSBTNoChangeWarningView(View):
    def run(self):
        selected_menu_num = WarningScreen(
            # TRANSLATOR_NOTE: User will receive no change back; the inputs to this transaction are fully spent
            status_headline=_("Full Spend!"),
            text=_("This PSBT spends its entire input value. No change is coming back to your wallet."),
            button_data=[ButtonOption("Continue")],
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Only one exit point
        return Destination(
            PSBTMathView,
            skip_current_view=True,  # Prevent going BACK to WarningViews
        )



class PSBTMathView(View):
    """
        Follows the Overview pictogram. Shows:
        + total input value
        - recipients' value
        - fees
        -------------------
        + change value
    """
    def run(self):
        from seedsigner.gui.screens.psbt_screens import PSBTMathScreen
        psbt_parser: PSBTParser = self.controller.psbt_parser
        if not psbt_parser:
            # Should not be able to get here
            return Destination(MainMenuView)
        
        selected_menu_num = self.run_screen(
            PSBTMathScreen,
            input_amount=psbt_parser.input_amount,
            num_inputs=psbt_parser.num_inputs,
            spend_amount=psbt_parser.spend_amount,
            num_recipients=psbt_parser.num_destinations,
            fee_amount=psbt_parser.fee_amount,
            change_amount=psbt_parser.change_amount,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if len(psbt_parser.destination_addresses) > 0:
            return Destination(PSBTAddressDetailsView, view_args={"address_num": 0})
        else:
            # This is a self-transfer
            return Destination(PSBTChangeDetailsView, view_args={"change_address_num": 0})



class PSBTAddressDetailsView(View):
    """
        Shows the recipient's address and amount they will receive
    """
    def __init__(self, address_num):
        super().__init__()
        self.address_num = address_num


    def run(self):
        from seedsigner.gui.screens.psbt_screens import PSBTAddressDetailsScreen
        psbt_parser: PSBTParser = self.controller.psbt_parser

        if not psbt_parser:
            # Should not be able to get here
            raise Exception("Routing error")

        # TRANSLATOR_NOTE: Future-tense used to indicate that this transaction will send this amount, as opposed to "Send" on its own which could be misread as an instant command (e.g. "Send Now").
        title = _("Will Send")
        if psbt_parser.num_destinations > 1:
            title += f" (#{self.address_num + 1})"

        button_data = []
        if self.address_num < psbt_parser.num_destinations - 1:
            button_data.append(ButtonOption("Next Recipient"))
        else:
            # TRANSLATOR_NOTE: Short for "Next step"
            button_data.append(ButtonOption("Next"))

        selected_menu_num = self.run_screen(
            PSBTAddressDetailsScreen,
            title=title,
            button_data=button_data,
            address=psbt_parser.destination_addresses[self.address_num],
            amount=psbt_parser.destination_amounts[self.address_num],
        )
        
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if self.address_num < len(psbt_parser.destination_addresses) - 1:
            # Show the next receive addr
            return Destination(PSBTAddressDetailsView, view_args={"address_num": self.address_num + 1})

        elif psbt_parser.change_amount > 0:
            # Move on to display change
            return Destination(PSBTChangeDetailsView, view_args={"change_address_num": 0})

        elif psbt_parser.op_return_data:
            return Destination(PSBTOpReturnView)

        else:
            # There's no change output to verify. Move on to sign the PSBT.
            return Destination(PSBTFinalizeView)



class PSBTChangeDetailsView(View):
    NEXT = ButtonOption("Next")
    SKIP_VERIFICATION = ButtonOption("Skip Verification")
    VERIFY_MULTISIG = ButtonOption("Verify Multisig Change")

    def __init__(self, change_address_num):
        super().__init__()
        self.change_address_num = change_address_num


    def run(self):
        from seedsigner.gui.screens.psbt_screens import PSBTChangeDetailsScreen
        psbt_parser: PSBTParser = self.controller.psbt_parser

        if not psbt_parser:
            # Should not be able to get here
            return Destination(MainMenuView)

        # Can we verify this change addr?
        change_data = psbt_parser.get_change_data(change_num=self.change_address_num)
        """
            change_data:
            {
                'address': 'bc1q............', 
                'amount': 397621401, 
                'fingerprint': ['22bde1a9', '73c5da0a'], 
                'derivation_path': ['m/48h/1h/0h/2h/1/0', 'm/48h/1h/0h/2h/1/0']
            }
        """

        # Single-sig verification is easy. We expect to find a single fingerprint
        # and derivation path.
        if self.controller.psbt_seed:
            seed_fingerprint = self.controller.psbt_seed.get_fingerprint(
                self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            )
        else:
            seed_fingerprint = hexlify(psbt_parser.master_fingerprint).decode()

        if seed_fingerprint not in change_data.get("fingerprint"):
            # TODO: Something is wrong with this psbt(?). Reroute to warning?
            return Destination(NotYetImplementedView)

        i = change_data.get("fingerprint").index(seed_fingerprint)
        derivation_path = change_data.get("derivation_path")[i]

        # 'm/84h/1h/0h/1/0' would be a change addr while 'm/84h/1h/0h/0/0' is a self-receive
        path_ints = bip32.parse_path(derivation_path)
        is_change_derivation_path = len(path_ints) >= 2 and (path_ints[-2] & 0x7FFFFFFF) == 1
        derivation_path_addr_index = path_ints[-1] & 0x7FFFFFFF if path_ints else 0

        if is_change_derivation_path:
            # TRANSLATOR_NOTE: The amount you're receiving back from the transaction
            title = _("Your Change")
        else:
            title = _("Self-Transfer")
            self.VERIFY_MULTISIG.button_label = _("Verify Multisig Addr")
        # if psbt_parser.num_change_outputs > 1:
        #     title += f" (#{self.change_address_num + 1})"

        is_change_addr_verified = False
        if psbt_parser.is_multisig:
            print("isMultisig")
            # if the known-good multisig descriptor is already onboard:
            if self.controller.multisig_wallet_descriptor:
                is_change_addr_verified = psbt_parser.verify_multisig_output(self.controller.multisig_wallet_descriptor, change_num=self.change_address_num)
                button_data = [self.NEXT]

            else:
                # Have the Screen offer to load in the multisig descriptor.            
                button_data = [self.VERIFY_MULTISIG, self.SKIP_VERIFICATION]

        else:
            # Single sig
            print("isSinglesig")
            try:
                from embit import script
                from embit.networks import NETWORKS

                if is_change_derivation_path:
                    loading_screen_text = _("Verifying Change...")
                else:
                    loading_screen_text = _("Verifying Self-Transfer...")
                from seedsigner.gui.screens.screen import LoadingScreenThread
                loading_screen = LoadingScreenThread(text=loading_screen_text)
                loading_screen.start()

                # convert change address to script pubkey to get script type
                pubkey = script.address_to_scriptpubkey(change_data["address"])
                script_type = pubkey.script_type()
                
                # extract derivation path to get wallet and change derivation
                change_path = bip32.path_to_str(path_ints[-2:])[2:] if len(path_ints) >= 2 else ""
                wallet_path_list = path_ints[:-2]
                wallet_path = bip32.path_to_str(wallet_path_list)
                
                if self.controller.psbt_seed:
                    xpub = self.controller.psbt_seed.get_xpub(
                        wallet_path=wallet_path,
                        network=self.settings.get_value(SettingsConstants.SETTING__NETWORK)
                    )
                    xpub_key = xpub.derive(change_path).key
                else:
                    rel_wallet_path_list = wallet_path_list[len(psbt_parser.root_path):]
                    rel_wallet_path = (
                        bip32.path_to_str(rel_wallet_path_list)[2:]
                        if rel_wallet_path_list
                        else ""
                    )
                    xpub = (
                        psbt_parser.root.derive(rel_wallet_path)
                        if rel_wallet_path
                        else psbt_parser.root
                    )
                    xpub_key = xpub.derive(change_path).key

                network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
                scriptcall = getattr(script, script_type)
                if script_type == "p2sh":
                    # single sig only so p2sh is always p2sh-p2wpkh
                    calc_address = script.p2sh(script.p2wpkh(xpub_key)).address(
                        network=NETWORKS[SettingsConstants.map_network_to_embit(network)]
                    )
                else:
                    # single sig so this handles p2wpkh and p2wpkh (and p2tr in the future)
                    calc_address = scriptcall(xpub_key).address(
                        network=NETWORKS[SettingsConstants.map_network_to_embit(network)]
                    )

                if change_data["address"] == calc_address:
                    is_change_addr_verified = True
                    button_data = [self.NEXT]

            finally:
                loading_screen.stop()

        if is_change_addr_verified == False and (not psbt_parser.is_multisig or self.controller.multisig_wallet_descriptor is not None):
            return Destination(PSBTAddressVerificationFailedView, view_args=dict(is_change=is_change_derivation_path, is_multisig=psbt_parser.is_multisig), clear_history=True)

        selected_menu_num = self.run_screen(
            PSBTChangeDetailsScreen,
            title=title,
            button_data=button_data,
            address=change_data.get("address"),
            amount=change_data.get("amount"),
            is_multisig=psbt_parser.is_multisig,
            fingerprint=seed_fingerprint,
            derivation_path=derivation_path,
            is_change_derivation_path=is_change_derivation_path,
            derivation_path_addr_index=derivation_path_addr_index,
            is_change_addr_verified=is_change_addr_verified,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.NEXT or button_data[selected_menu_num] == self.SKIP_VERIFICATION:
            if self.change_address_num < psbt_parser.num_change_outputs - 1:
                return Destination(PSBTChangeDetailsView, view_args={"change_address_num": self.change_address_num + 1})

            elif psbt_parser.op_return_data:
                return Destination(PSBTOpReturnView)

            else:
                # There's no more change to verify. Move on to sign the PSBT.
                return Destination(PSBTFinalizeView)
            
        elif button_data[selected_menu_num] == self.VERIFY_MULTISIG:
            from seedsigner.controller import Controller
            from seedsigner.views.seed_views import LoadMultisigWalletDescriptorView
            self.controller.resume_main_flow = Controller.FLOW__PSBT
            return Destination(LoadMultisigWalletDescriptorView)
            


class PSBTAddressVerificationFailedView(View):
    def __init__(self, is_change: bool = True, is_multisig: bool = False):
        super().__init__()
        self.is_change = is_change
        self.is_multisig = is_multisig


    def run(self):
        if self.is_multisig:
            # TRANSLATOR_NOTE: Variable is either "change" or "self-transfer".
            text = _("PSBT's {} address could not be verified from wallet descriptor.").format(_("change") if self.is_change else _("self-transfer"))
        else:
            # TRANSLATOR_NOTE: Variable is either "change" or "self-transfer".
            text = _("PSBT's {} address could not be generated from your seed.").format(_("change") if self.is_change else _("self-transfer"))
        
        DireWarningScreen(
            title=_("Suspicious PSBT"),
            status_headline=_("Address Verification Failed"),
            text=text,
            button_data=[ButtonOption("Discard PSBT")],
            show_back_button=False,
        ).display()

        # We're done with this PSBT. Route back to MainMenuView which always
        #   clears all ephemeral data (except in-memory seeds).
        return Destination(MainMenuView, clear_history=True)



class PSBTOpReturnView(View):
    """
        Shows the OP_RETURN data
    """
    def run(self):
        from seedsigner.gui.screens.psbt_screens import PSBTOpReturnScreen
        psbt_parser: PSBTParser = self.controller.psbt_parser

        if not psbt_parser:
            # Should not be able to get here
            raise Exception("Routing error")

        title = _("OP_RETURN")
        button_data = [ButtonOption("Next")]

        selected_menu_num = self.run_screen(
            PSBTOpReturnScreen,
            title=title,
            button_data=button_data,
            op_return_data=psbt_parser.op_return_data,
        )
        
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        return Destination(PSBTFinalizeView)



class PSBTFinalizeView(View):
    """
    """
    APPROVE_PSBT = ButtonOption("Approve PSBT")

    
    def run(self):
        from embit.psbt import PSBT
        from seedsigner.gui.screens.psbt_screens import PSBTFinalizeScreen
        from seedsigner.models.wif import WIFKey
        from embit.finalizer import finalize_psbt

        psbt_parser: PSBTParser = self.controller.psbt_parser
        psbt: PSBT = self.controller.psbt

        if psbt is None:
            # Should not be able to get here
            return Destination(MainMenuView)

        if not self.controller.psbt_sign_with_satochip and psbt_parser is None:
            return Destination(MainMenuView)

        selected_menu_num = self.run_screen(
            PSBTFinalizeScreen,
            button_data=[self.APPROVE_PSBT]
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        from seedsigner.gui.screens.screen import LoadingScreenThread
        loading = LoadingScreenThread(text=_("Signing PSBT..."))
        loading.start()
        try:
            sig_cnt = PSBTParser.sig_count(psbt)
            if self.controller.psbt_sign_with_satochip:
                from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip
                if not self.controller.Satochip_Connector:
                    return Destination(PSBTSigningErrorView)
                sign_psbt_with_satochip(psbt, self.controller.Satochip_Connector)
            else:
                psbt.sign_with(psbt_parser.root)
            if isinstance(self.controller.psbt_seed, WIFKey):
                tx = finalize_psbt(psbt)
                self.controller.signed_tx_hex = tx.serialize().hex() if tx else None
            else:
                self.controller.signed_tx_hex = None

            trimmed_psbt = PSBTParser.trim(psbt)
        finally:
            loading.stop()

        if sig_cnt == PSBTParser.sig_count(trimmed_psbt):
            return Destination(PSBTSigningErrorView)

        self.controller.psbt = trimmed_psbt
        self.controller.psbt_sign_with_satochip = False
        return Destination(PSBTSignedQRDisplayView)



class PSBTSignedQRDisplayView(View):
    def run(self):
        from seedsigner.models.encode_qr import UrPsbtQrEncoder, GenericStringEncoder
        from seedsigner.models.wif import WIFKey
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if isinstance(self.controller.psbt_seed, WIFKey) and getattr(self.controller, "signed_tx_hex", None):
            qr_encoder = GenericStringEncoder(self.controller.signed_tx_hex)
        else:
            loading = LoadingScreenThread(text=_("Encoding PSBT..."))
            loading.start()
            try:
                qr_encoder = UrPsbtQrEncoder(
                    psbt=self.controller.psbt,
                    qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
                )
            finally:
                loading.stop()

        self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)

        # We're done with this PSBT. Route back to MainMenuView which always
        #   clears all ephemeral data (except in-memory seeds).
        return Destination(MainMenuView, clear_history=True)



class PSBTSigningErrorView(View):
    SELECT_DIFF_SEED = ButtonOption("Select Diff Seed")
    
    def run(self):
        psbt_parser: PSBTParser = self.controller.psbt_parser
        if not psbt_parser:
            # Should not be able to get here
            return Destination(MainMenuView)

        # Just a WarningScreen here; only use DireWarningScreen for true security risks.
        selected_menu_num = self.run_screen(
            WarningScreen,
            title=_("PSBT Error"),
            status_icon_name=SeedSignerIconConstants.WARNING,
            status_headline=_("Signing Failed"),
            text=_("Signing with this seed did not add a valid signature."),
            button_data=[self.SELECT_DIFF_SEED]
        )

        if selected_menu_num == 0:
            # clear seed selected for psbt signing since it did not add a valid signature
            self.controller.psbt_seed = None
            return Destination(PSBTSelectSeedView, clear_history=True)

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
