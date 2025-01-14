import hashlib
import logging
import os
import time
import platform
import binascii

from embit.descriptor import Descriptor
from embit.descriptor.checksum import checksum
from PIL import Image
from PIL.ImageOps import autocontrast
from gettext import gettext as _

from seedsigner.gui.components import FontAwesomeIconConstants, GUIConstants, SeedSignerIconConstants
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON, ButtonListScreen
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.helpers import mnemonic_generation
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.seed_views import SeedDiscardView, SeedFinalizeView, SeedMnemonicEntryView, SeedOptionsView, SeedWordsWarningView, SeedExportXpubScriptTypeView, LoadSeedView

from .view import View, Destination, BackStackView, MainMenuView

from seedsigner.helpers import seedkeeper_utils
from seedsigner.gui.screens import (RET_CODE__BACK_BUTTON, ButtonListScreen,
    WarningScreen, DireWarningScreen, seed_screens, LargeIconStatusScreen)
logger = logging.getLogger(__name__)

from pysatochip.JCconstants import SEEDKEEPER_DIC_TYPE, SEEDKEEPER_DIC_ORIGIN, SEEDKEEPER_DIC_EXPORT_RIGHTS, BIP39_WORDLIST_DIC
from binascii import unhexlify, hexlify

class ToolsMenuView(View):
    IMAGE = ButtonOption(" New seed", FontAwesomeIconConstants.CAMERA)
    DICE = ButtonOption("New seed", FontAwesomeIconConstants.DICE)
    KEYBOARD = ButtonOption("Calc 12th/24th word", FontAwesomeIconConstants.KEYBOARD)
    ADDRESS_EXPLORER = ButtonOption("Address Explorer")
    VERIFY_ADDRESS = ButtonOption("Verify address")
    SMARTCARD = ButtonOption("Smartcard Tools", FontAwesomeIconConstants.LOCK)
    MICROSD = ButtonOption("MicroSD Tools")
    CLEAR_DESCRIPTOR = ButtonOption("Clear Multisig Descriptor")

    def run(self):
        button_data = [self.IMAGE, self.DICE, self.KEYBOARD, self.ADDRESS_EXPLORER, self.VERIFY_ADDRESS, self.SMARTCARD, self.MICROSD, self.CLEAR_DESCRIPTOR]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Tools"),
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.IMAGE:
            return Destination(ToolsImageEntropyLivePreviewView)

        elif button_data[selected_menu_num] == self.DICE:
            return Destination(ToolsDiceEntropyMnemonicLengthView)

        elif button_data[selected_menu_num] == self.KEYBOARD:
            return Destination(ToolsCalcFinalWordNumWordsView)

        elif button_data[selected_menu_num] == self.ADDRESS_EXPLORER:
            return Destination(ToolsAddressExplorerSelectSourceView)

        elif button_data[selected_menu_num] == self.VERIFY_ADDRESS:
            from seedsigner.views.scan_views import ScanAddressView
            return Destination(ScanAddressView)

        elif button_data[selected_menu_num] == self.SMARTCARD:
            return Destination(ToolsSmartcardMenuView)
        
        elif button_data[selected_menu_num] == self.MICROSD:
            return Destination(ToolsMicroSDMenuView)

        elif button_data[selected_menu_num] == self.CLEAR_DESCRIPTOR:
            self.controller.multisig_wallet_descriptor = None
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Multisig Descriptor Cleared",
                show_back_button=False,
            )
            return Destination(BackStackView)



"""****************************************************************************
    Image entropy Views
****************************************************************************"""
class ToolsImageEntropyLivePreviewView(View):
    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsImageEntropyLivePreviewScreen
        self.controller.image_entropy_preview_frames = None
        ret = ToolsImageEntropyLivePreviewScreen().display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        self.controller.image_entropy_preview_frames = ret
        return Destination(ToolsImageEntropyFinalImageView)



class ToolsImageEntropyFinalImageView(View):
    def run(self):
        from PIL import Image
        from PIL.ImageOps import autocontrast
        from seedsigner.gui.screens.tools_screens import ToolsImageEntropyFinalImageScreen
        if not self.controller.image_entropy_final_image:
            from seedsigner.hardware.camera import Camera
            # Take the final full-res image
            camera = Camera.get_instance()
            camera.start_single_frame_mode(resolution=(720, 480))
            time.sleep(0.25)
            self.controller.image_entropy_final_image = camera.capture_frame()
            camera.stop_single_frame_mode()

        # Prep a copy of the image for display. The actual image data is 720x480
        # Present just a center crop and resize it to fit the screen and to keep some of
        #   the data hidden.
        display_version = autocontrast(
            self.controller.image_entropy_final_image,
            cutoff=2
        ).crop(
            (120, 0, 600, 480)
        ).resize(
            (self.canvas_width, self.canvas_height), Image.Resampling.BICUBIC
        )
        
        ret = ToolsImageEntropyFinalImageScreen(
            final_image=display_version
        ).display()

        if ret == RET_CODE__BACK_BUTTON:
            # Go back to live preview and reshoot
            self.controller.image_entropy_final_image = None
            return Destination(BackStackView)
        
        return Destination(ToolsImageEntropyMnemonicLengthView)



class ToolsImageEntropyMnemonicLengthView(View):
    TWELVE_WORDS = ButtonOption("12 words", return_data=12)
    TWENTYFOUR_WORDS = ButtonOption("24 words", return_data=24)

    def run(self):
        button_data = [self.TWELVE_WORDS, self.TWENTYFOUR_WORDS]

        selected_menu_num = ButtonListScreen(
            title=_("Mnemonic Length?"),
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        mnemonic_length = button_data[selected_menu_num].return_data

        preview_images = self.controller.image_entropy_preview_frames
        seed_entropy_image = self.controller.image_entropy_final_image

        # Build in some hardware-level uniqueness via CPU unique Serial num
        try:
            stream = os.popen("cat /proc/cpuinfo | grep Serial")
            output = stream.read()
            serial_num = output.split(":")[-1].strip().encode('utf-8')
            serial_hash = hashlib.sha256(serial_num)
            hash_bytes = serial_hash.digest()
        except Exception as e:
            logger.info(repr(e), exc_info=True)
            hash_bytes = b'0'

        # Build in modest entropy via millis since power on
        millis_hash = hashlib.sha256(hash_bytes + str(time.time()).encode('utf-8'))
        hash_bytes = millis_hash.digest()

        # Build in better entropy by chaining the preview frames
        for frame in preview_images:
            img_hash = hashlib.sha256(hash_bytes + frame.tobytes())
            hash_bytes = img_hash.digest()

        # Finally build in our headline entropy via the new full-res image
        final_hash = hashlib.sha256(hash_bytes + seed_entropy_image.tobytes()).digest()

        if mnemonic_length == 12:
            # 12-word mnemonic only uses the first 128 bits / 16 bytes of entropy
            final_hash = final_hash[:16]

        # Generate the mnemonic
        mnemonic = mnemonic_generation.generate_mnemonic_from_bytes(final_hash)

        # Image should never get saved nor stick around in memory
        seed_entropy_image = None
        preview_images = None
        final_hash = None
        hash_bytes = None
        self.controller.image_entropy_preview_frames = None
        self.controller.image_entropy_final_image = None

        # Add the mnemonic as an in-memory Seed
        seed = Seed(mnemonic, wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
        self.controller.storage.set_pending_seed(seed)
        
        # Cannot return BACK to this View
        return Destination(SeedWordsWarningView, view_args={"seed_num": None}, clear_history=True)



"""****************************************************************************
    Dice rolls Views
****************************************************************************"""
class ToolsDiceEntropyMnemonicLengthView(View):
    def run(self):
        # Since we're dynamically building the ButtonOption button_labels here, it's too
        # awkward to use the usual class-level attr approach.

        # TRANSLATOR_NOTE: Inserts the number of dice rolls needed for a 12-word mnemonic
        twelve = _("12 words ({} rolls)").format(mnemonic_generation.DICE__NUM_ROLLS__12WORD)
        TWELVE = ButtonOption(twelve, return_data=mnemonic_generation.DICE__NUM_ROLLS__12WORD)

        # TRANSLATOR_NOTE: Inserts the number of dice rolls needed for a 24-word mnemonic
        twenty_four = _("24 words ({} rolls)").format(mnemonic_generation.DICE__NUM_ROLLS__24WORD)
        TWENTY_FOUR = ButtonOption(twenty_four, return_data=mnemonic_generation.DICE__NUM_ROLLS__24WORD)

        button_data = [TWELVE, TWENTY_FOUR]
        selected_menu_num = ButtonListScreen(
            title=_("Mnemonic Length"),
            is_bottom_list=True,
            is_button_text_centered=True,
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == TWELVE:
            return Destination(ToolsDiceEntropyEntryView, view_args=dict(total_rolls=mnemonic_generation.DICE__NUM_ROLLS__12WORD))

        elif button_data[selected_menu_num] == TWENTY_FOUR:
            return Destination(ToolsDiceEntropyEntryView, view_args=dict(total_rolls=mnemonic_generation.DICE__NUM_ROLLS__24WORD))



class ToolsDiceEntropyEntryView(View):
    def __init__(self, total_rolls: int):
        super().__init__()
        self.total_rolls = total_rolls
    

    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsDiceEntropyEntryScreen
        ret = ToolsDiceEntropyEntryScreen(
            return_after_n_chars=self.total_rolls,
        ).display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        dice_seed_phrase = mnemonic_generation.generate_mnemonic_from_dice(ret)

        # Add the mnemonic as an in-memory Seed
        seed = Seed(dice_seed_phrase, wordlist_language_code=self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
        self.controller.storage.set_pending_seed(seed)

        # Cannot return BACK to this View
        return Destination(SeedWordsWarningView, view_args={"seed_num": None}, clear_history=True)



"""****************************************************************************
    Calc final word Views
****************************************************************************"""
class ToolsCalcFinalWordNumWordsView(View):
    TWELVE = ButtonOption("12 words", return_data=12)
    TWENTY_FOUR = ButtonOption("24 words", return_data=24)

    def run(self):
        button_data = [self.TWELVE, self.TWENTY_FOUR]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Mnemonic Length"),
            is_bottom_list=True,
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.controller.storage.init_pending_mnemonic(button_data[selected_menu_num].return_data)

        return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True))



class ToolsCalcFinalWordFinalizePromptView(View):
    # TRANSLATOR_NOTE: Label to gather entropy through coin tosses
    COIN_FLIPS = ButtonOption("Coin flip entropy")

    # TRANSLATOR_NOTE: Label to gather entropy through user specified BIP-39 word
    SELECT_WORD = ButtonOption("Word selection entropy")

    # TRANSLATOR_NOTE: Label to allow user to default entropy as all-zeros
    ZEROS = ButtonOption("Finalize with zeros")

    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsCalcFinalWordFinalizePromptScreen
        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_length = len(mnemonic)
        if mnemonic_length == 12:
            num_entropy_bits = 7
        else:
            num_entropy_bits = 3

        button_data = [self.COIN_FLIPS, self.SELECT_WORD, self.ZEROS]
        selected_menu_num = ToolsCalcFinalWordFinalizePromptScreen(
            mnemonic_length=mnemonic_length,
            num_entropy_bits=num_entropy_bits,
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.COIN_FLIPS:
            return Destination(ToolsCalcFinalWordCoinFlipsView)

        elif button_data[selected_menu_num] == self.SELECT_WORD:
            # Clear the final word slot, just in case we're returning via BACK button
            self.controller.storage.update_pending_mnemonic(None, mnemonic_length - 1)
            return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True, cur_word_index=mnemonic_length - 1))

        elif button_data[selected_menu_num] == self.ZEROS:
            # User skipped the option to select a final word to provide last bits of
            # entropy. We'll insert all zeros and piggy-back on the coin flip attr
            wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
            self.controller.storage.update_pending_mnemonic(Seed.get_wordlist(wordlist_language_code)[0], mnemonic_length - 1)
            return Destination(ToolsCalcFinalWordShowFinalWordView, view_args=dict(coin_flips="0" * num_entropy_bits))



class ToolsCalcFinalWordCoinFlipsView(View):
    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsCoinFlipEntryScreen
        mnemonic_length = len(self.controller.storage.pending_mnemonic)

        if mnemonic_length == 12:
            total_flips = 7
        else:
            total_flips = 3
        
        ret_val = ToolsCoinFlipEntryScreen(
            return_after_n_chars=total_flips,
        ).display()

        if ret_val == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        else:
            return Destination(ToolsCalcFinalWordShowFinalWordView, view_args=dict(coin_flips=ret_val))



class ToolsCalcFinalWordShowFinalWordView(View):
    NEXT = ButtonOption("Next")

    def __init__(self, coin_flips: str = None):
        super().__init__()
        # Construct the actual final word. The user's selected_final_word
        # contributes:
        #   * 3 bits to a 24-word seed (plus 8-bit checksum)
        #   * 7 bits to a 12-word seed (plus 4-bit checksum)
        from seedsigner.helpers import mnemonic_generation

        wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        wordlist = Seed.get_wordlist(wordlist_language_code)

        # Prep the user's selected word / coin flips and the actual final word for
        # the display.
        if coin_flips:
            self.selected_final_word = None
            self.selected_final_bits = coin_flips
        else:
            # Convert the user's final word selection into its binary index equivalent
            self.selected_final_word = self.controller.storage.pending_mnemonic[-1]
            self.selected_final_bits = format(wordlist.index(self.selected_final_word), '011b')

        if coin_flips:
            # fill the last bits (what will eventually be the checksum) with zeros
            binary_string = coin_flips + "0" * (11 - len(coin_flips))

            # retrieve the matching word for the resulting index
            wordlist_index = int(binary_string, 2)
            wordlist = Seed.get_wordlist(self.controller.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE))
            word = wordlist[wordlist_index]

            # update the pending mnemonic with our new "final" (pre-checksum) word
            self.controller.storage.update_pending_mnemonic(word, -1)

        # Now calculate the REAL final word (has a proper checksum)
        final_mnemonic = mnemonic_generation.calculate_checksum(
            mnemonic=self.controller.storage.pending_mnemonic,
            wordlist_language_code=wordlist_language_code,
        )

        # Update our pending mnemonic with the real final word
        self.controller.storage.update_pending_mnemonic(final_mnemonic[-1], -1)

        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_length = len(mnemonic)

        # And grab the actual final word's checksum bits
        self.actual_final_word = self.controller.storage.pending_mnemonic[-1]
        num_checksum_bits = 4 if mnemonic_length == 12 else 8
        self.checksum_bits = format(wordlist.index(self.actual_final_word), '011b')[-num_checksum_bits:]


    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsCalcFinalWordScreen
        button_data = [self.NEXT]

        # TRANSLATOR_NOTE: label to calculate the last word of a BIP-39 mnemonic seed phrase
        title = _("Final Word Calc")

        selected_menu_num = self.run_screen(
            ToolsCalcFinalWordScreen,
            title=title,
            button_data=button_data,
            selected_final_word=self.selected_final_word,
            selected_final_bits=self.selected_final_bits,
            checksum_bits=self.checksum_bits,
            actual_final_word=self.actual_final_word,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.NEXT:
            return Destination(ToolsCalcFinalWordDoneView)



class ToolsCalcFinalWordDoneView(View):
    LOAD = ButtonOption("Load seed")
    DISCARD = ButtonOption("Discard", button_label_color="red")

    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsCalcFinalWordDoneScreen
        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_word_length = len(mnemonic)
        final_word = mnemonic[-1]

        button_data = [self.LOAD, self.DISCARD]

        selected_menu_num = ToolsCalcFinalWordDoneScreen(
            final_word=final_word,
            mnemonic_word_length=mnemonic_word_length,
            fingerprint=self.controller.storage.get_pending_mnemonic_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK)),
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        self.controller.storage.convert_pending_mnemonic_to_pending_seed()

        if button_data[selected_menu_num] == self.LOAD:
            return Destination(SeedFinalizeView)
        
        elif button_data[selected_menu_num] == self.DISCARD:
            return Destination(SeedDiscardView)



"""****************************************************************************
    Address Explorer Views
****************************************************************************"""
class ToolsAddressExplorerSelectSourceView(View):
    SCAN_SEED = ButtonOption("Scan a seed", SeedSignerIconConstants.QRCODE)
    SCAN_DESCRIPTOR = ButtonOption("Scan wallet descriptor", SeedSignerIconConstants.QRCODE)
    TYPE_12WORD = ButtonOption("Enter 12-word seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_18WORD = ButtonOption("Enter 18-word seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_24WORD = ButtonOption("Enter 24-word seed", FontAwesomeIconConstants.KEYBOARD)
    LOADED_DESCRIPTOR = ButtonOption("Loaded Multisig Descriptor")
    TYPE_ELECTRUM = ButtonOption("Electrum Seed", FontAwesomeIconConstants.KEYBOARD)

    def run(self):
        from seedsigner.controller import Controller

        seeds = self.controller.storage.seeds
        button_data = []
        for seed in seeds:
            button_str = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            button_data.append(ButtonOption(button_str, SeedSignerIconConstants.FINGERPRINT))

        if self.controller.multisig_wallet_descriptor:
            button_data.append(self.LOADED_DESCRIPTOR)

        button_data = button_data + [self.SCAN_SEED, self.SCAN_DESCRIPTOR, self.TYPE_12WORD, self.TYPE_18WORD, self.TYPE_24WORD]
        if self.settings.get_value(SettingsConstants.SETTING__ELECTRUM_SEEDS) == SettingsConstants.OPTION__ENABLED:
            button_data.append(self.TYPE_ELECTRUM)

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Address Explorer"),
            button_data=button_data,
            is_button_text_centered=False,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Most of the options require us to go through a side flow(s) before we can
        # continue to the address explorer. Set the Controller-level flow so that it
        # knows to re-route us once the side flow is complete.        
        self.controller.resume_main_flow = Controller.FLOW__ADDRESS_EXPLORER

        if len(seeds) > 0 and selected_menu_num < len(seeds):
            # User selected one of the n seeds
            return Destination(
                SeedExportXpubScriptTypeView,
                view_args=dict(
                    seed_num=selected_menu_num,
                    sig_type=SettingsConstants.SINGLE_SIG,
                )
            )
        
        
        elif button_data[selected_menu_num] == self.LOADED_DESCRIPTOR:
            return Destination(ToolsAddressExplorerAddressTypeView)

        elif button_data[selected_menu_num] == self.SCAN_SEED:
            from seedsigner.views.scan_views import ScanSeedQRView
            return Destination(ScanSeedQRView)

        elif button_data[selected_menu_num] == self.SCAN_DESCRIPTOR:
            from seedsigner.views.scan_views import ScanWalletDescriptorView
            return Destination(ScanWalletDescriptorView)

        elif button_data[selected_menu_num] in [self.TYPE_12WORD, self.TYPE_18WORD, self.TYPE_24WORD]:
            from seedsigner.views.seed_views import SeedMnemonicEntryView

            self.controller.storage.init_pending_mnemonic(num_words=button_data[selected_menu_num].return_data)

            return Destination(SeedMnemonicEntryView)

        elif button_data[selected_menu_num] == self.TYPE_ELECTRUM:
            from seedsigner.views.seed_views import SeedElectrumMnemonicStartView
            return Destination(SeedElectrumMnemonicStartView)



class ToolsAddressExplorerAddressTypeView(View):
    # TRANSLATOR_NOTE: label for addresses where others send us incoming payments
    RECEIVE = ButtonOption("Receive Addresses")

    # TRANSLATOR_NOTE: label for addresses that collect the change from our own outgoing payments
    CHANGE = ButtonOption("Change Addresses")


    def __init__(self, seed_num: int = None, script_type: str = None, custom_derivation: str = None):
        """
            If the explorer source is a seed, `seed_num` and `script_type` must be
            specified. `custom_derivation` can be specified as needed.

            If the source is a multisig or single sig wallet descriptor, `seed_num`,
            `script_type`, and `custom_derivation` should be `None`.
        """
        super().__init__()
        self.seed_num = seed_num
        self.script_type = script_type
        self.custom_derivation = custom_derivation
    
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)

        # Store everything in the Controller's `address_explorer_data` so we don't have
        # to keep passing vals around from View to View and recalculating.
        data = dict(
            seed_num=seed_num,
            network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
            embit_network=SettingsConstants.map_network_to_embit(network),
            script_type=script_type,
        )
        if self.seed_num is not None:
            self.seed = self.controller.storage.seeds[seed_num]
            data["seed_num"] = self.seed
            seed_derivation_override = self.seed.derivation_override(sig_type=SettingsConstants.SINGLE_SIG)

            if self.script_type == SettingsConstants.CUSTOM_DERIVATION:
                derivation_path = self.custom_derivation
            elif seed_derivation_override:
                derivation_path = seed_derivation_override
            else:
                from seedsigner.helpers import embit_utils
                derivation_path = embit_utils.get_standard_derivation_path(
                    network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
                    wallet_type=SettingsConstants.SINGLE_SIG,
                    script_type=self.script_type,
                )

            data["derivation_path"] = derivation_path
            data["xpub"] = self.seed.get_xpub(derivation_path, network=network)
        
        else:
            data["wallet_descriptor"] = self.controller.multisig_wallet_descriptor

        self.controller.address_explorer_data = data


    def run(self):
        from seedsigner.gui.screens.tools_screens import ToolsAddressExplorerAddressTypeScreen
        data = self.controller.address_explorer_data

        wallet_descriptor_display_name = None
        if "wallet_descriptor" in data:
            wallet_descriptor_display_name = data["wallet_descriptor"].brief_policy.replace(" (sorted)", "")
            wallet_descriptor_display_name = " / ".join(wallet_descriptor_display_name.split(" of ")) # i18n w/o l10n since coming from non-l10n embit

        script_type = data["script_type"] if "script_type" in data else None

        button_data = [self.RECEIVE, self.CHANGE]

        selected_menu_num = self.run_screen(
            ToolsAddressExplorerAddressTypeScreen,
            button_data=button_data,
            fingerprint=self.seed.get_fingerprint() if self.seed_num is not None else None,
            wallet_descriptor_display_name=wallet_descriptor_display_name,
            script_type=script_type,
            custom_derivation_path=self.custom_derivation,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            # If we entered this flow via an already-loaded seed's SeedOptionsView, we
            # need to clear the `resume_main_flow` so that we don't get stuck in a 
            # SeedOptionsView redirect loop.
            # TODO: Refactor to a cleaner `BackStack.get_previous_View_cls()`
            if len(self.controller.back_stack) > 1 and self.controller.back_stack[-2].View_cls == SeedOptionsView:
                # The BackStack has the current View on the top with the real "back" in second position.
                self.controller.resume_main_flow = None
                self.controller.address_explorer_data = None
            return Destination(BackStackView)
        
        elif button_data[selected_menu_num] in [self.RECEIVE, self.CHANGE]:
            return Destination(ToolsAddressExplorerAddressListView, view_args=dict(is_change=button_data[selected_menu_num] == self.CHANGE))



class ToolsAddressExplorerAddressListView(View):
    def __init__(self, is_change: bool = False, start_index: int = 0, selected_button_index: int = 0, initial_scroll: int = 0):
        super().__init__()
        self.is_change = is_change
        self.start_index = start_index
        self.selected_button_index = selected_button_index
        self.initial_scroll = initial_scroll


    def run(self):
        self.loading_screen = None

        addresses = []
        button_data = []
        data = self.controller.address_explorer_data
        addrs_per_screen = 10

        addr_storage_key = "receive_addrs"
        if self.is_change:
            addr_storage_key = "change_addrs"

        if addr_storage_key in data and len(data[addr_storage_key]) >= self.start_index + addrs_per_screen:
            # We already calculated this range of addresses; just retrieve them
            addresses = data[addr_storage_key][self.start_index:self.start_index + addrs_per_screen]

        else:
            try:
                from seedsigner.gui.screens.screen import LoadingScreenThread
                from seedsigner.helpers import embit_utils
                # TRANSLATOR_NOTE: a status message that our payment addresses are being calculated
                self.loading_screen = LoadingScreenThread(text=_("Calculating addrs..."))
                self.loading_screen.start()

                if addr_storage_key not in data:
                    data[addr_storage_key] = []

                if "xpub" in data:
                    # Single sig explore from seed
                    if "script_type" in data and data["script_type"] != SettingsConstants.CUSTOM_DERIVATION:
                        # Standard derivation path
                        for i in range(self.start_index, self.start_index + addrs_per_screen):
                            address = embit_utils.get_single_sig_address(xpub=data["xpub"], script_type=data["script_type"], index=i, is_change=self.is_change, embit_network=data["embit_network"])
                            addresses.append(address)
                            data[addr_storage_key].append(address)
                    else:
                        # TODO: Custom derivation path
                        raise Exception(_("Custom Derivation address explorer not yet implemented"))

                elif "wallet_descriptor" in data:
                    from embit.descriptor import Descriptor
                    descriptor: Descriptor = data["wallet_descriptor"]
                    for i in range(self.start_index, self.start_index + addrs_per_screen):
                        address = embit_utils.get_multisig_address(descriptor=descriptor, index=i, is_change=self.is_change, embit_network=data["embit_network"])
                        addresses.append(address)
                        data[addr_storage_key].append(address)

            finally:
                # Everything is set. Stop the loading screen
                self.loading_screen.stop()

        for i, address in enumerate(addresses):
            cur_index = i + self.start_index

            # Adjust the trailing addr display length based on available room
            # (the index number will push it out on each order of magnitude)
            if cur_index < 10:
                end_digits = -6
            elif cur_index < 100:
                end_digits = -5
            else:
                end_digits = -4
            button_data.append(ButtonOption(f"{cur_index}:{address[:8]}...{address[end_digits:]}", active_button_label=f"{cur_index}:{address}"))

        # TRANSLATOR_NOTE: Insert the number of addrs displayed per screen (e.g. "Next 10")
        button_label = _("Next {}").format(addrs_per_screen)
        button_data.append(ButtonOption(button_label, right_icon_name=SeedSignerIconConstants.CHEVRON_RIGHT))

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Receive Addrs") if not self.is_change else _("Change Addrs"),
            button_data=button_data,
            button_font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            button_font_size=GUIConstants.get_button_font_size() + 4,
            is_button_text_centered=False,
            is_bottom_list=True,
            selected_button=self.selected_button_index,
            scroll_y_initial_offset=self.initial_scroll,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        if selected_menu_num == len(addresses):
            # User clicked NEXT
            return Destination(ToolsAddressExplorerAddressListView, view_args=dict(is_change=self.is_change, start_index=self.start_index + addrs_per_screen))
        
        # Preserve the list's current scroll so we can return to the same spot
        initial_scroll = self.screen.buttons[0].scroll_y

        index = selected_menu_num + self.start_index
        return Destination(ToolsAddressExplorerAddressView, view_args=dict(index=index, address=addresses[selected_menu_num], is_change=self.is_change, start_index=self.start_index, parent_initial_scroll=initial_scroll), skip_current_view=True)



class ToolsAddressExplorerAddressView(View):
    # TODO: pull address str from controller.address_explorer_data and pass addr_storage_key and addr_index instead
    def __init__(self, index: int, address: str, is_change: bool, start_index: int, parent_initial_scroll: int = 0):
        super().__init__()
        self.index = index
        self.address = address
        self.is_change = is_change
        self.start_index = start_index
        self.parent_initial_scroll = parent_initial_scroll

    
    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        from seedsigner.models.encode_qr import GenericStaticQrEncoder

        qr_encoder = GenericStaticQrEncoder(data=self.address)
        self.run_screen(
            QRDisplayScreen,
            qr_encoder=qr_encoder,
        )
    
        # Exiting/Cancelling the QR display screen always returns to the list
        return Destination(ToolsAddressExplorerAddressListView, view_args=dict(is_change=self.is_change, start_index=self.start_index, selected_button_index=self.index - self.start_index, initial_scroll=self.parent_initial_scroll), skip_current_view=True)

"""****************************************************************************
    Smartcard Views
****************************************************************************"""
class ToolsSmartcardMenuView(View):
    CHANGE_PIN = ButtonOption("Change PIN")
    CHANGE_LABEL = ButtonOption("Change Label")
    SATOCHIP = ButtonOption("Satochip Functions")
    SEEDKEEPER = ButtonOption("SeedKeeper Functions")
    Satochip_DIY = ButtonOption("DIY Tools")

    def run(self):
        button_data = [self.CHANGE_PIN, self.CHANGE_LABEL, self.SEEDKEEPER, self.SATOCHIP, self.Satochip_DIY]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Smartcard Tools",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(MainMenuView)

        elif button_data[selected_menu_num] == self.CHANGE_PIN:
            return Destination(ToolsSatochipChangePinView)
        
        elif button_data[selected_menu_num] == self.CHANGE_LABEL:
            return Destination(ToolsSatochipChangeLabelView)

        elif button_data[selected_menu_num] == self.SATOCHIP:
            return Destination(ToolsSatochipView)
        
        elif button_data[selected_menu_num] == self.SEEDKEEPER:
            return Destination(ToolsSeedkeeperView)

        elif button_data[selected_menu_num] == self.Satochip_DIY:
            return Destination(ToolsSatochipDIYView)


class ToolsSatochipChangePinView(View):
    def run(self):
        
        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip", "seedkeeper"])

        if not Satochip_Connector:
            return Destination(BackStackView)

        NewPin = seed_screens.SeedAddPassphraseScreen(title="New PIN").display()

        if "is_back_button" in NewPin:
            return Destination(ToolsSmartcardMenuView)
        
        new_pin = list(NewPin['passphrase'].encode('utf8'))
        response, sw1, sw2 = Satochip_Connector.card_change_PIN(0, Satochip_Connector.pin, new_pin)
        if sw1 == 0x90 and sw2 == 0x00:
            logger.info("Success: Pin Changed")
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"PIN Updated",
                show_back_button=False,
            )
        else:
            logger.info("Failure: Pin Change Failed")
            self.run_screen(
                WarningScreen,
                title="Invalid PIN",
                status_headline=None,
                text=f"Invalid PIN entered, select another and try again.",
                show_back_button=True,
            )
        
        return Destination(MainMenuView)

class ToolsSatochipChangeLabelView(View):
    def run(self):
        
        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip", "seedkeeper"])

        if not Satochip_Connector:
            return Destination(BackStackView)

        NewLabel = seed_screens.SeedAddPassphraseScreen(title="New Label").display()

        if "is_back_button" in NewLabel:
            return Destination(ToolsSmartcardMenuView)

        """Sets a plain text label for the card (Optional)"""
        try:
            (response, sw1, sw2) = Satochip_Connector.card_set_label(NewLabel['passphrase'])
            if sw1 != 0x90 or sw2 != 0x00:
                logger.info("ERROR: Set Label Failed")
                self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text=f"Set Label Failed...",
                    show_back_button=True,
                )
            else:
                logger.info("Device Label Updated")
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"Label Updated",
                    show_back_button=False,
                )
        except Exception as e:
            self.loading_screen.stop()
            logger.info("Set Label Failed:", str(e))
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=str(e)[:100],
                show_back_button=True,
            )

        return Destination(MainMenuView)

class ToolsSeedkeeperView(View):
    VIEW_SECRETS = ButtonOption("View Secrets on Card")
    IMPORT_PASSWORD = ButtonOption("Save Password to Card")
    DELETE_SECRET = ButtonOption("Delete Secret from Card")
    LOAD_DESCRIPTOR = ButtonOption("Load MultiSig Descriptor")
    SAVE_DESCRIPTOR = ButtonOption("Save MultiSig Descriptor")

    def run(self):
        button_data = [self.VIEW_SECRETS, self.IMPORT_PASSWORD, self.DELETE_SECRET, self.LOAD_DESCRIPTOR, self.SAVE_DESCRIPTOR]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="SeedKeeper",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(ToolsSmartcardMenuView)

        elif button_data[selected_menu_num] == self.VIEW_SECRETS:
            return Destination(ToolsSeedkeeperViewSecretsView)

        elif button_data[selected_menu_num] == self.IMPORT_PASSWORD:
            return Destination(ToolsSeedkeeperImportPasswordView)

        elif button_data[selected_menu_num] == self.DELETE_SECRET:
            return Destination(ToolsSeedkeeperDeleteSecretView)

        elif button_data[selected_menu_num] == self.LOAD_DESCRIPTOR:
            return Destination(ToolsSeedkeeperLoadDescriptorView)
        
        elif button_data[selected_menu_num] == self.SAVE_DESCRIPTOR:
            return Destination(ToolsSeedkeeperSaveDescriptorView)

class ToolsSeedkeeperViewSecretsView(View):

    def entropy_to_mnemonic(self, entropy_bytes, wordlist):
        from mnemonic import Mnemonic
        logger.info(f"Worldlist: {wordlist}")

        mnemonic_obj = Mnemonic(wordlist)
        mnemonic = mnemonic_obj.to_mnemonic(entropy_bytes)

        return mnemonic # str

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        try:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
            
            if not Satochip_Connector:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Listing Secrets\n\n\n\n\n\n")
            self.loading_screen.start()

            headers = Satochip_Connector.seedkeeper_list_secret_headers()

            self.loading_screen.stop()

            headers_parsed = []
            button_data = []
            for header in headers:
                sid = header['id']
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))  # hex(header['type'])
                subtype = header['subtype']
                label = stype
                if stype == "Password":
                    label = "Pass:" + header['label']
                elif stype == "BIP39 mnemonic": # Older Seedkeeper v1 BIP39 seeds
                    label = "Seed:" + header['label']
                elif stype == 'Masterseed' and subtype==0x01: # Newer SeedKeeper V2 Seeds
                    label = "Seed:" + header['label']
                elif stype == "2FA secret":
                    label = "2FA:" + header['label']
                elif stype == "Descriptor":
                    label = "Descriptor:" + header['label']
                elif stype == "Data":
                    label = "Data:" + header['label']
                else: 
                    label = header['label']
                origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))  # hex(header['origin'])
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],
                                                                 hex(header[
                                                                         'export_rights']))  # str(header['export_rights'])
                export_nbplain = str(header['export_nbplain'])
                export_nbsecure = str(header['export_nbsecure'])
                export_nbcounter = str(header['export_counter']) if header['type'] == 0x70 else 'N/A'
                fingerprint = header['fingerprint']

                if export_rights == 'Plaintext export allowed':
                    if len(label) == 0: label = "Unnamed Secret"
                    headers_parsed.append((sid, label))
                    button_data.append(ButtonOption(label))

            logger.info(headers_parsed)
            if len(headers_parsed) < 1:
                self.run_screen(
                WarningScreen,
                title="No Secrets to Load",
                status_headline=None,
                text=f"No Secrets to Load from Seedkeeper",
                show_back_button=False,
                )   
                return Destination(BackStackView)

            selected_menu_num = self.run_screen(
                ButtonListScreen,
                title="Select Secret",
                is_button_text_centered=False,
                button_data=button_data,
                show_back_button=True,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Loading Secret\n\n\n\n\n\n")
            self.loading_screen.start()

            secret_dict = Satochip_Connector.seedkeeper_export_secret(headers_parsed[selected_menu_num][0], None)

            self.loading_screen.stop()

            stype = SEEDKEEPER_DIC_TYPE.get(secret_dict['type'], hex(secret_dict['type']))  # hex(header['type'])

            if 'mnemonic' in stype:
                secret_dict['secret'] = unhexlify(secret_dict['secret'])[1:].decode().rstrip("\x00")

                bip39_secret = secret_dict['secret']

                secret_size = secret_dict['secret_list'][0]
                secret_mnemonic = bip39_secret[:secret_size]
                secret_passphrase = bip39_secret[secret_size + 1:]

                secret_dict['secret'] = "Mnemonic:" + secret_mnemonic + " Passphrase:" + secret_passphrase

            #elif stype == 'BIP39 mnemonic v2':
            elif stype == 'Masterseed' and subtype==0x01:

                # this format is backward compatible with Masterseed (BIP39 info appended after Masterseed)
                # mnemonic in compressed format using entropy (16-32 bytes)
                secret_raw_hex = secret_dict['secret']
                secret_raw_bytes = bytes.fromhex(secret_raw_hex)
                
                offset = 0
                masterseed_size = secret_raw_bytes[offset]
                offset+=1

                masterseed_bytes= secret_raw_bytes[offset: (offset+masterseed_size)]
                offset+=masterseed_size
                masterseed_hex= masterseed_bytes.hex()

                wordlist_byte = secret_raw_bytes[offset]
                offset+=1
                wordlist = BIP39_WORDLIST_DIC.get(wordlist_byte)
                if wordlist == None:
                    logger.info(f"Error: wordlist byte {wordlist_byte} unsupported!")
                    exit()
                
                entropy_size = secret_raw_bytes[offset]
                offset+=1

                entropy_bytes = secret_raw_bytes[offset:(offset+entropy_size)]
                offset+=entropy_size
                try:
                    bip39_mnemonic = self.entropy_to_mnemonic(entropy_bytes, wordlist)

                except Exception as ex:
                    logger.info(f"Error during entropy conversion: {ex}")
                    bip39_mnemonic = f"failed to convert entropy: {entropy_bytes.hex()}"

                passphrase_size= secret_raw_bytes[offset]
                offset+=1

                passphrase_bytes= secret_raw_bytes[offset: (offset+passphrase_size)]
                offset+=passphrase_size
                try:
                    passphrase = passphrase_bytes.decode("utf-8")
                except Exception as ex:
                    logger.info(f"Error during passphrase decoding: {ex}")
                    passphrase = f"failed to decode passphrase bytes: {passphrase_bytes.hex()}"

                secret_dict['secret']= f'BIP39 mnemonic: "{bip39_mnemonic}" \nPassphrase: "{passphrase}"'  

            elif stype == 'Password':
                
                password_length = secret_dict['secret_list'][0]
                try:
                    login_length = secret_dict['secret_list'][password_length + 1]
                    url_length = secret_dict['secret_list'][password_length + login_length + 2]
                except IndexError: # Older Seedkeeper software didn't include these optional fields
                    login_length = 0
                    url_length = 0

                secret_string = ""

                # Password is always present, so no need to test for this
                password_text = binascii.unhexlify(secret_dict['secret'])[1:password_length+1].decode()
                secret_string += " Password:" + "\"" + password_text + "\""

                if login_length > 0:
                    login_text = binascii.unhexlify(secret_dict['secret'])[
                                    password_length + 2: password_length + login_length + 2].decode()
                    secret_string += " Login:" + "\"" + login_text + "\""

                if url_length > 0:
                    url_text = binascii.unhexlify(secret_dict['secret'])[-url_length:].decode()
                    secret_string += " URL:" + "\"" + url_text + "\""

                secret_dict['secret'] = secret_string


            elif stype in ('Descriptor', 'Data'):
                secret_dict['secret'] = unhexlify(secret_dict['secret'])[2:].decode()
                
            else:
                secret_dict['secret'] =  secret_dict['secret'][2:]

            selected_menu_num = self.run_screen(
                LargeIconStatusScreen,
                title=secret_dict['label'],
                status_headline=None,
                text = secret_dict['secret'],
                status_icon_size=0,
                show_back_button=True,
                allow_text_overflow=True,
                button_data=[ButtonOption("Show as QR")],
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            else:
                from seedsigner.gui.screens.screen import QRDisplayScreen
                from seedsigner.models.encode_qr import GenericStaticQrEncoder

                qr_encoder = GenericStaticQrEncoder(data=secret_dict['secret'])
                self.run_screen(
                    QRDisplayScreen,
                    qr_encoder=qr_encoder,
                )

            return Destination(BackStackView)
            
        except Exception as e:
            logger.info(e)
            self.loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=True,
                button_data=[ButtonOption("Show as QR")],
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            else:
                from seedsigner.gui.screens.screen import QRDisplayScreen
                from seedsigner.models.encode_qr import GenericStaticQrEncoder

                qr_encoder = GenericStaticQrEncoder(data=secret_dict['secret'])
                self.run_screen(
                    QRDisplayScreen,
                    qr_encoder=qr_encoder,
                )

            return Destination(BackStackView)



class ToolsSeedkeeperImportPasswordView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread

        secret_label = seed_screens.SeedAddPassphraseScreen(title="Secret Label").display()
        if "is_back_button" in secret_label:
            return Destination(BackStackView)

        secret_text = seed_screens.SeedAddPassphraseScreen(title="Secret Text").display()
        if "is_back_button" in secret_text:
            return Destination(BackStackView)

        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
        if not Satochip_Connector:
            return Destination(BackStackView)
        
        header = Satochip_Connector.make_header("Password", "Plaintext export allowed", secret_label['passphrase'])
        secret_text_list = list(bytes(secret_text['passphrase'], 'utf-8'))
        secret_list = [len(secret_text_list)] + secret_text_list
        secret_dic = {'header': header, 'secret_list': secret_list}
        try:
            self.loading_screen = LoadingScreenThread(text="Saving Secret\n\n\n\n\n\n")
            self.loading_screen.start()

            (sid, fingerprint) = Satochip_Connector.seedkeeper_import_secret(secret_dic)

            self.loading_screen.stop()

            logger.info("Imported - SID:", sid, " Fingerprint:", fingerprint)
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Password Imported",
                show_back_button=False,
            )
        except Exception as e:
            logger.info(e)
            self.loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=f"Password Import Failed",
                show_back_button=False,
            )
        
        return Destination(BackStackView)

class ToolsSeedkeeperDeleteSecretView(View):

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        try:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
            
            if not Satochip_Connector:
                return Destination(BackStackView)

            # for v1, secret deletion is not supported
            status = Satochip_Connector.card_get_status()[3]
            if status['protocol_minor_version'] == 1:
                raise ValueError("Secret deletion is not supported on Seedkeeper v1")

            self.loading_screen = LoadingScreenThread(text="Listing Secrets\n\n\n\n\n\n")
            self.loading_screen.start()

            headers = Satochip_Connector.seedkeeper_list_secret_headers()

            self.loading_screen.stop()

            headers_parsed = []
            button_data = []
            for header in headers:
                sid = header['id']
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))  # hex(header['type'])
                subtype = header['subtype']
                label = stype
                if stype == "Password":
                    label = "Pass:" + header['label']
                elif stype == "BIP39 mnemonic": # Older Seedkeeper v1 BIP39 seeds
                    label = "Seed:" + header['label']
                elif stype == 'Masterseed' and subtype==0x01: # Newer SeedKeeper V2 Seeds
                    label = "Seed:" + header['label']
                elif stype == "2FA secret":
                    label = "2FA:" + header['label']
                elif stype == "Descriptor":
                    label = "Descriptor:" + header['label']
                elif stype == "Data":
                    label = "Data:" + header['label']
                else: 
                    label = header['label']
                origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))  # hex(header['origin'])
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],
                                                                 hex(header[
                                                                         'export_rights']))  # str(header['export_rights'])
                export_nbplain = str(header['export_nbplain'])
                export_nbsecure = str(header['export_nbsecure'])
                export_nbcounter = str(header['export_counter']) if header['type'] == 0x70 else 'N/A'
                fingerprint = header['fingerprint']

                if export_rights == 'Plaintext export allowed':
                    if len(label) == 0: label = "Unnamed Secret"
                    headers_parsed.append((sid, label))
                    button_data.append(ButtonOption(label))

            logger.info(headers_parsed)
            if len(headers_parsed) < 1:
                self.run_screen(
                WarningScreen,
                title="No Secrets to Load",
                status_headline=None,
                text=f"No Secrets to Load from Seedkeeper",
                show_back_button=False,
                )   
                return Destination(BackStackView)

            selected_menu_num = self.run_screen(
                ButtonListScreen,
                title="Select Secret",
                is_button_text_centered=False,
                button_data=button_data,
                show_back_button=True,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            warning_screen_num = DireWarningScreen(
                status_headline="Delete Confirmation",
                text="This will delete this secret, this cannot be un-done",
            ).display()

            if warning_screen_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Deleting Secret\n\n\n\n\n\n")
            self.loading_screen.start()

            result = Satochip_Connector.seedkeeper_reset_secret(headers_parsed[selected_menu_num][0])

            self.loading_screen.stop()

            LargeIconStatusScreen(
                text="Secret Deleted",
            ).display()

            return Destination(BackStackView)
            
        except Exception as e:
            logger.info(e)
            self.loading_screen.stop()
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=True,
            )
            return Destination(BackStackView)

class ToolsSeedkeeperLoadDescriptorView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.views.seed_views import MultisigWalletDescriptorView
        try:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
            
            if not Satochip_Connector:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Retrieving List of Secrets\n\n\n\n\n\n")
            self.loading_screen.start()

            headers = Satochip_Connector.seedkeeper_list_secret_headers()

            multisig_descriptor_secrets = []
            xpub_secrets = []
            button_data = []
            for header in headers:
                sid = header['id']
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))  # hex(header['type'])
                subtype = header['subtype']
                label = header['label']
                origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))  # hex(header['origin'])
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],
                                                                 hex(header[
                                                                         'export_rights']))  # str(header['export_rights'])
                export_nbplain = str(header['export_nbplain'])
                export_nbsecure = str(header['export_nbsecure'])
                export_nbcounter = str(header['export_counter']) if header['type'] == 0x70 else 'N/A'
                fingerprint = header['fingerprint']

                if export_rights == 'Plaintext export allowed':
                    # Check for Seedkeeper V1 style Descriptors
                    if "msig_desc_" in label:
                        multisig_descriptor_secrets.append((sid, label.replace("msig_desc_", "")))
                        button_data.append(ButtonOption(label.replace("msig_desc_", "")))

                    if "xpub_" in label:
                        xpub_secrets.append((sid, label))

                    # Check for Seedkeeper V2 Style Descriptors
                    if stype == "Descriptor": 
                        multisig_descriptor_secrets.append((sid, label))
                        button_data.append(ButtonOption(label))

            logger.info("Multisig Descriptor Secrets:", multisig_descriptor_secrets)
            logger.info("Xpub Secrets:",xpub_secrets)

            self.loading_screen.stop()

            if len(multisig_descriptor_secrets) < 1:
                self.run_screen(
                WarningScreen,
                title="No Descriptors",
                status_headline=None,
                text=f"No Multisig Descriptors to Load from Seedkeeper",
                show_back_button=False,
                )   
                return Destination(BackStackView)

            selected_menu_num = self.run_screen(
                ButtonListScreen,
                title="Select Descriptor",
                is_button_text_centered=False,
                button_data=button_data,
                show_back_button=True,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            
            self.loading_screen = LoadingScreenThread(text="Loading Descriptor\n\n\n\n\n\n")
            self.loading_screen.start()

            secret_dict = Satochip_Connector.seedkeeper_export_secret(multisig_descriptor_secrets[selected_menu_num][0], None)

            stype = SEEDKEEPER_DIC_TYPE.get(secret_dict['type'], hex(secret_dict['type']))  # hex(header['type'])

            if stype == "Descriptor": # Seedkeeper V2 
                secret_template = unhexlify(secret_dict['secret'])[2:].decode()
            else:
                secret_dict['secret'] = unhexlify(secret_dict['secret'])[1:].decode()
                secret_template = secret_dict['secret']

                for xpub_secret_id, xpub_secret_label in xpub_secrets: 
                    if xpub_secret_label in secret_template:
                        logger.info("Matched on:", xpub_secret_label)
                        secret_dict = Satochip_Connector.seedkeeper_export_secret(xpub_secret_id, None)
                        secret_dict['secret'] = unhexlify(secret_dict['secret'])[1:].decode()
                        secret_template = secret_template.replace(xpub_secret_label, secret_dict['secret'])
                
            # Depending on where the descriptor came from whem imported into the SeedKeeper, it may need some characters swapped to work with Embit
            secret_template = secret_template.replace("<","{").replace(">","}").replace(";",",")

            self.controller.multisig_wallet_descriptor = Descriptor.from_string(secret_template)
            
            self.loading_screen.stop()

            return Destination(MultisigWalletDescriptorView, skip_current_view=True)
            

        except Exception as e:
            self.loading_screen.stop()
            logger.info(e)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=True,
            )
            return Destination(BackStackView)


class ToolsSeedkeeperSaveDescriptorView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        try:
            # Load
            descriptor = self.controller.multisig_wallet_descriptor

            if descriptor == None:
                # No descriptor loaded, can't proceed further
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline="No Multisig Descriptor Loaded",
                    text="Nothing to save...",
                    show_back_button=True,
                )
        
                return Destination(BackStackView)

            # Break up the descriptor for efficient storage on SeedKeeper Cards
            descriptor_string = descriptor.to_string()

            logger.info(descriptor_string)

            # Prompt for Descriptor Name
            ret = seed_screens.SeedAddPassphraseScreen(title="Descriptor Label").display()

            if "is_back_button" in ret:
                return Destination(BackStackView)

            # Set up our connection to the card
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])

            if not Satochip_Connector:
                return Destination(BackStackView)
            
            self.loading_screen = LoadingScreenThread(text="Saving Secrets\n\n\n\n\n\n")
            self.loading_screen.start()

            status = Satochip_Connector.card_get_status()[3]
            secrets_imported = 0
            secrets_skipped = 0

            key_strings = []

            if status['protocol_minor_version'] == 1: # Format needed for Seedkeeper v1 cards
                secret_type = "Password"
                # Split up the descriptor into smaller strings (needed for SeedKeeper v1)
                for key in descriptor.keys:
                    key_string = key.to_string()
                    key_name = "xpub_" + hexlify(key.fingerprint).decode()
                    
                    descriptor_string = descriptor_string.replace(key_string, key_name)
                    key_strings.append((key_name, key_string))

                key_strings.append(("msig_desc_" + ret['passphrase'], descriptor_string))
            
            else: # For Seedkeeper V2, we can just store the whole descriptor as-is
                secret_type = "Descriptor"
                key_strings.append((ret['passphrase'], descriptor_string))

            # Check for existing secrets on the Seedkeeper (Related to this descriptor)
            headers = Satochip_Connector.seedkeeper_list_secret_headers()

            multisig_descriptor_secrets = []
            xpub_labels = []
            button_data = []
            for header in headers:
                sid = header['id']
                stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))  # hex(header['type'])
                label = header['label']
                origin = SEEDKEEPER_DIC_ORIGIN.get(header['origin'], hex(header['origin']))  # hex(header['origin'])
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header['export_rights'],
                                                                    hex(header[
                                                                            'export_rights']))  # str(header['export_rights'])
                export_nbplain = str(header['export_nbplain'])
                export_nbsecure = str(header['export_nbsecure'])
                export_nbcounter = str(header['export_counter']) if header['type'] == 0x70 else 'N/A'
                fingerprint = header['fingerprint']

                if export_rights == 'Plaintext export allowed':
                    if "msig_desc_" in label:
                        multisig_descriptor_secrets.append((sid, label.replace("msig_desc_", "")))
                        button_data.append(ButtonOption(label.replace("msig_desc_", "")))

                    if "xpub_" in label:
                        xpub_labels.append(ButtonOption(label))

                    # Check for Seedkeeper V2 Style Descriptors
                    if stype == "Descriptor": 
                        multisig_descriptor_secrets.append((sid, label))

            logger.info("Multisig Descriptor Secrets:", multisig_descriptor_secrets)
            logger.info("Xpub Secrets:",xpub_labels)

            multisig_descriptor_templates = []

            for secret_id, secret_label in multisig_descriptor_secrets:
                secret_dict = Satochip_Connector.seedkeeper_export_secret(secret_id, None)

                secret_dict['secret'] = unhexlify(secret_dict['secret'])[1:].decode()

                multisig_descriptor_templates.append(secret_dict['secret'])

            logger.info(multisig_descriptor_templates)

            logger.info("Key Strings:", key_strings)

            # Add required secrets to seedkeeper
            for secret_label, secret_text in key_strings:
                if secret_text in multisig_descriptor_templates or secret_label in xpub_labels:
                    logger.info("Mached Existing Secret, skipping:", secret_label)
                    secrets_skipped += 1
                    continue
                header = Satochip_Connector.make_header(secret_type, "Plaintext export allowed", secret_label)
                if secret_type == "Password":
                    secret_text_list = list(bytes(secret_text, 'utf-8'))
                    secret_list = [len(secret_text_list)] + secret_text_list
                else:
                    secret_text_list = list(bytes(secret_text, 'utf-8'))
                    secret_list = list(len(secret_text_list).to_bytes(2,"big")) + secret_text_list
                secret_dic = {'header': header, 'secret_list': secret_list}
                (sid, fingerprint) = Satochip_Connector.seedkeeper_import_secret(secret_dic)
                logger.info("Imported - SID:", sid, " Fingerprint:", fingerprint)
                secrets_imported += 1
                
            self.loading_screen.stop()

            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Multisig Descriptor Exported." + "\nExported:" + str(secrets_imported) + "\nSkipped:" + str(secrets_skipped),
                show_back_button=False,
            )

        except Exception as e:
            self.loading_screen.stop()
            logger.info(e)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=True,
            )
        
        return Destination(BackStackView)

class ToolsSatochipView(View):
    IMPORT_SEED = ButtonOption("Import Seed")
    ENABLE_2FA = ButtonOption("Enable 2FA")

    def run(self):
        button_data = [self.IMPORT_SEED, self.ENABLE_2FA]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Satochip",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(ToolsSmartcardMenuView)

        elif button_data[selected_menu_num] == self.IMPORT_SEED:
            return Destination(ToolsSatochipImportSeedView)

        elif button_data[selected_menu_num] == self.ENABLE_2FA:
            return Destination(ToolsSatochipEnable2FAView)
        
class ToolsSatochipImportSeedView(View):
    SCAN_SEED = ("Scan a seed", SeedSignerIconConstants.QRCODE)
    TYPE_12WORD = ("Enter 12-word seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_24WORD = ("Enter 24-word seed", FontAwesomeIconConstants.KEYBOARD)

    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])

        if not Satochip_Connector:
            return Destination(BackStackView)

        seeds = self.controller.storage.seeds
        button_data = []
        for seed in seeds:
            button_str = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            button_data.append(ButtonOption(button_str, SeedSignerIconConstants.FINGERPRINT))
        
        button_data = button_data + [self.SCAN_SEED, self.TYPE_12WORD, self.TYPE_24WORD]
        
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Seed to Import",
            button_data=button_data,
            is_button_text_centered=False,
            is_bottom_list=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Most of the options require us to go through a side flow(s) before we can
        # continue to the address explorer. Set the Controller-level flow so that it
        # knows to re-route us once the side flow is complete.        
        # self.controller.resume_main_flow = Controller.FLOW__SATOCHIP_IMPORT_SEED

        if len(seeds) > 0 and selected_menu_num < len(seeds):
            # User selected one of the n seeds
            try:
                self.loading_screen = LoadingScreenThread(text="Importing Secret\n\n\n\n\n\n")
                self.loading_screen.start()

                Satochip_Connector.card_bip32_import_seed(seeds[selected_menu_num].seed_bytes)

                self.loading_screen.stop()

                logger.info("Seed Successfully Imported")
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"Seed Imported",
                    show_back_button=False,
                )
            except Exception as e:
                self.loading_screen.stop()
                logger.info("Satochip Import Failed:",str(e))
                self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text=f"Seed Import Failed",
                    show_back_button=False,
                )

        elif button_data[selected_menu_num] == self.SCAN_SEED:
            from seedsigner.views.scan_views import ScanSeedQRView
            return Destination(ScanSeedQRView)

        elif button_data[selected_menu_num] in [self.TYPE_12WORD, self.TYPE_24WORD]:
            from seedsigner.views.seed_views import SeedMnemonicEntryView
            if button_data[selected_menu_num] == self.TYPE_12WORD:
                self.controller.storage.init_pending_mnemonic(num_words=12)
            else:
                self.controller.storage.init_pending_mnemonic(num_words=24)
            return Destination(SeedMnemonicEntryView)
        
        return Destination(MainMenuView)

class ToolsSatochipEnable2FAView(View):
    def run(self):
        from os import urandom
        import binascii
        from seedsigner.gui.screens.screen import LoadingScreenThread
        key = urandom(20)
        logger.info("2FA Key:", binascii.hexlify(key))

        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])

        if not Satochip_Connector:
            return Destination(BackStackView)
        
        try:
            self.run_screen(
                WarningScreen,
                title="Warning",
                status_headline=None,
                text=f"Scan the following QR code with the Satochip 2FA app before proceeding (You will not see this code again...)",
                show_back_button=False,
            )
            from seedsigner.gui.screens.screen import QRDisplayScreen
            from seedsigner.models.encode_qr import GenericStaticQrEncoder

            qr_encoder = GenericStaticQrEncoder(data=binascii.hexlify(key).decode())

            self.run_screen(
                QRDisplayScreen,
                qr_encoder=qr_encoder,
            )

            self.loading_screen = LoadingScreenThread(text="Enabling 2FA\n\n\n\n\n\n")
            self.loading_screen.start()

            Satochip_Connector.card_set_2FA_key(key, 0)

            self.loading_screen.stop()

            logger.info("Success: 2FA Key Imported and Enabled")
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"2FA Enabled",
                show_back_button=False,
            )
        except Exception as e:
            self.loading_screen.stop()
            logger.info("Enable 2fa failed:", str(e))
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=f"Enable 2FA Failed",
                show_back_button=False,
            )

        return Destination(MainMenuView)

class ToolsSatochipDIYView(View):
    BUILD_APPLETS = ButtonOption("Build Applets")
    INSTALL_APPLET = ButtonOption("Install Applet")
    UNINSTALL_APPLET = ButtonOption("Uninstall Applet")

    def run(self):
        button_data = [self.BUILD_APPLETS, self.INSTALL_APPLET, self.UNINSTALL_APPLET]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Javacard DIY",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.BUILD_APPLETS:
            return Destination(ToolsDIYBuildAppletsView)

        elif button_data[selected_menu_num] == self.INSTALL_APPLET:
            return Destination(ToolsDIYInstallAppletView)

        elif button_data[selected_menu_num] == self.UNINSTALL_APPLET:
            return Destination(ToolsDIYUninstallAppletView)


class ToolsDIYBuildAppletsView(View):
    def run(self):
        from subprocess import run
        import os
        from seedsigner.gui.screens.screen import LoadingScreenThread

        self.loading_screen = LoadingScreenThread(text="Building Applets\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()

        if platform.uname()[1] == "seedsigner-os":
            if not os.path.exists("/mnt/microsd/javacard-build.xml"):
                os.system("cp /opt/tools/javacard-build.xml.seedsigneros /mnt/microsd/javacard-build.xml")

            if not os.path.exists("/mnt/microsd/javacard-cap/"):
                os.system("mkdir -p /mnt/microsd/javacard-cap/")

            os.environ["JAVA_HOME"] = "/mnt/diy/jdk"
            commandString = "/mnt/diy/ant/bin/ant -f /mnt/microsd/javacard-build.xml"
        else:
            if not os.path.exists("/boot/javacard-build.xml"):
                os.system("sudo cp /home/pi/seedsigner/tools/javacard-build.xml.manual /boot/javacard-build.xml")

            if not os.path.exists("/boot/javacard-cap/"):
                os.system("sudo mkdir -p /boot/javacard-cap/")

            commandString = "sudo ant -f /boot/javacard-build.xml"

        data = run(commandString, capture_output=True, shell=True, text=True)

        logger.info(data)

        self.loading_screen.stop()

        if "BUILD SUCCESSFUL" in data.stdout:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Applets Built",
                show_back_button=False,
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=data.stderr.replace("\n", " "),
                show_back_button=False,
            )


        return Destination(MainMenuView)

class ToolsDIYInstallAppletView(View):
    def run(self):
        from subprocess import run
        import os
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if platform.uname()[1] == "seedsigner-os":
            cap_files = os.listdir('/mnt/microsd/javacard-cap/')
        else:
            cap_files = os.listdir('/boot/javacard-cap/')

        cap_file_buttons = []
        for file in cap_files:
            cap_file_buttons.append(ButtonOption(file))

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select Applet",
            is_button_text_centered=False,
            button_data=cap_file_buttons
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        applet_file = cap_files[selected_file_num]
        logger.info("Selected:", applet_file)

        if platform.uname()[1] == "seedsigner-os":
            installed_applets = seedkeeper_utils.run_globalplatform(self,
                                                                    "--install /mnt/microsd/javacard-cap/" + applet_file, "Installing Applet", "Applet Installed")
        else:
            installed_applets = seedkeeper_utils.run_globalplatform(self,"--install /boot/javacard-cap/" + applet_file, "Installing Applet", "Applet Installed")

        # This process often kills IFD-NFC, so restart it if required
        scinterface = self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES)
        if "pn532" in scinterface:
            os.system("ifdnfc-activate no")
            time.sleep(1)
            os.system("ifdnfc-activate yes")

        return Destination(MainMenuView)

class ToolsDIYUninstallAppletView(View):
    def run(self):
        from subprocess import run
        import os
        from seedsigner.gui.screens.screen import LoadingScreenThread

        ret = self.run_screen(
            WarningScreen,
            title="Warning",
            status_headline=None,
            text="Uninstalling an applet will wipe ALL data associated with it. (This cannot be undone)",
            show_back_button=True,
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        installed_applets = seedkeeper_utils.run_globalplatform(self,"-l -v", "Checking Installed Applets", None)

        if installed_applets:
            installed_applets = installed_applets.split('\n')

            installed_applets_aids = []
            installed_applets_list = []

            for line in installed_applets:
                if "PKG: " in line:
                    package_info = line.split()
                    logger.info(package_info)
                    # Ignore system packages
                    if package_info[1] in ['A0000001515350', 'A00000016443446F634C697465', 'A0000000620204', 'A0000000620202', 'D27600012401','D00000000002','4B4D313031']:
                        continue
                    
                    installed_applets_list.append(ButtonOption(package_info[3][2:-2]))
                    installed_applets_aids.append(package_info[1])

            if len(installed_applets_list) > 0:
                selected_applet_num = self.run_screen(
                    ButtonListScreen,
                    title="Select Applet",
                    is_button_text_centered=False,
                    button_data=installed_applets_list
                )

                if selected_applet_num == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

                applet_aid = installed_applets_aids[selected_applet_num]

                seedkeeper_utils.run_globalplatform(self,"--delete " + applet_aid + " -force", "Uninstalling Applet", "Applet Uninstalled")

            else:
                self.run_screen(
                    WarningScreen,
                    title="Notice",
                    status_headline=None,
                    text="No Applets to Uninstall",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")]
                )

                # This process often kills IFD-NFC, so restart it if required
        scinterface = self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES)
        if "pn532" in scinterface:
            os.system("ifdnfc-activate no")
            time.sleep(1)
            os.system("ifdnfc-activate yes")

        return Destination(MainMenuView)

"""****************************************************************************
    MicroSD Views
****************************************************************************"""
class ToolsMicroSDMenuView(View):
    FLASH_IMAGE = ButtonOption("Flash Image")
    VERIFY_IMAGE = ButtonOption("Verify MicroSD")
    WIPE_ZERO = ButtonOption("Wipe (Zero)")
    WIPE_RANDOM = ButtonOption("Wipe (Random)")

    def run(self):
        button_data = [self.FLASH_IMAGE, self.VERIFY_IMAGE, self.WIPE_ZERO, self.WIPE_RANDOM]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="MicroSD Tools",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.FLASH_IMAGE:
            return Destination(ToolsMicroSDFlashView)
        
        elif button_data[selected_menu_num] == self.VERIFY_IMAGE:
            return Destination(ToolsMicroSDVerifyWarningView)

        elif button_data[selected_menu_num] == self.WIPE_ZERO:
            return Destination(ToolsMicroSDWipeZeroView)

        elif button_data[selected_menu_num] == self.WIPE_RANDOM:
            return Destination(ToolsMicroSDWipeRandomView)
        
class ToolsMicroSDFlashView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if platform.uname()[1] == "seedsigner-os":
            microsd_images = os.listdir('/mnt/microsd/microsd-images/')
        else:
            microsd_images = os.listdir('/boot/microsd-images/')

        microsd_images_buttons = []
        for file in microsd_images:
            microsd_images_buttons.append(ButtonOption(file))

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select Image",
            is_button_text_centered=False,
            button_data=microsd_images_buttons
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        microsd_image = microsd_images[selected_file_num]
        logger.info("Selected:", microsd_image)

        if platform.uname()[1] == "seedsigner-os":
            data = run("cp /mnt/microsd/microsd-images/" + microsd_image + " /tmp/img.img", capture_output=True, shell=True, text=True)
            if len(data.stderr) > 1:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="data.stderr",
                    show_back_button=False,
                )
                return Destination(MainMenuView)

            ret = self.run_screen(
                WarningScreen,
                title="Notice",
                status_headline=None,
                text="Insert MicroSD to be Flashed",
                show_back_button=True,
                button_data=[ButtonOption("Continue")]
            )

            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            self.loading_screen = LoadingScreenThread(text="Flashing MicroSD\n\n\n\n\n\n")
            self.loading_screen.start()

            data = run("dd if=/tmp/img.img of=/dev/mmcblk0", capture_output=True, shell=True, text=True)

            self.loading_screen.stop()

            data_stderr_split = data.stderr.split('\n')

            inNum = 1
            outNum = 0
            for errorLine in data_stderr_split:
                if "records in" in errorLine:
                    inNum = errorLine.split("+")[0]
                    continue
                elif "records out" in errorLine:
                    outNum = errorLine.split("+")[0]
                    continue

            if inNum != outNum:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=data.stderr,
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")]
                )
            else:
                ret = self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"MicroSD Flashed",
                    show_back_button=False,
                    button_data=[ButtonOption("Verify"),ButtonOption("Skip Verification")]
                )

                if ret == 0:
                    return Destination(ToolsMicroSDVerifyView) 
                else:
                    return Destination(MainMenuView)

        else:
            os.system("cp /boot/microsd-images/" + microsd_image + " /tmp/img.img")
            os.system("sudo dd if=/tmp/img.img of=/dev/mmcblk0")

        return Destination(MainMenuView)

class ToolsMicroSDVerifyWarningView(View):
    def run(self):
        ret = self.run_screen(
            WarningScreen,
            title="Checksum Note",
            status_headline=None,
            text="Verification test will\nonly pass for freshly\nflashed (or Read Only)\nMicroSD Cards.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")]
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        else:
            return Destination(ToolsMicroSDVerifyView)
        

class ToolsMicroSDVerifyView(View):
    known_checksums = {'5809d4ec68138c737b1b000db4c6ec60983e94544efd893bdfa40ebf19af60f4':'Zero Wiped (First 26MB)',
                       'a380cb93eb852254863718a9c000be9ec30cee14a78fc0ec90708308c17c1b8a':'seedsigner_os.0.7.0.pi0',
                       'fe0601e6da97c7711093b67a7102f8108f2bfb8a2478fd94fa9d3edea5adfb64':'seedsigner_os.0.7.0.pi02w',
                       '65be9209527ba03efe8093099dae8ec65725c90a758bc98678b9da31639637d7':'seedsigner_os.0.7.0.pi2',
                       'd574c1326d07e18b550e2f65e36a4678b05db882adb5cb8f8732ff8d75d59809':'seedsigner_os.0.7.0.pi4'}

    def run(self):
        from subprocess import run
        import os
        from seedsigner.gui.screens.screen import LoadingScreenThread

        self.loading_screen = LoadingScreenThread(text="Reading MicroSD\n\n\n\n\n\n")
        self.loading_screen.start()

        if platform.uname()[1] == "seedsigner-os":
            os.system("dd if=/dev/mmcblk0 of=/tmp/img.img bs=1M count=26")
        else:
            os.system("sudo dd if=/dev/mmcblk0 of=/tmp/img.img bs=1M count=26")

        data = run("sha256sum /tmp/img.img", capture_output=True, shell=True, text=True)

        logger.info(data)

        self.loading_screen.stop()

        checksum = data.stdout[:64]

        try:
            image_name = self.known_checksums[checksum]
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline="Matched Checksum",
                text=image_name,
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        except KeyError:
            formatted_checksum = data.stdout[:16] + "\n" + data.stdout[16:32] + "\n" + data.stdout[32:48] + "\n" + data.stdout[48:64]

            self.run_screen(
                WarningScreen,
                title="Unfamilliar Checksum",
                status_headline=None,
                text=formatted_checksum,
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        return Destination(MainMenuView)
    
class ToolsMicroSDWipeZeroView(View):
    WIPE_64MB = ButtonOption("64MB")
    WIPE_256MB = ButtonOption("256MB")
    WIPE_ALL = ButtonOption("All")

    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        button_data=[self.WIPE_64MB, self.WIPE_256MB, self.WIPE_ALL]

        wipe_selection = self.run_screen(
                LargeIconStatusScreen,
                title="Wipe MicroSD",
                status_headline=None,
                text = "Select amount to wipe (Larger takes longer)",
                status_icon_size=0,
                show_back_button=True,
                button_data=button_data,
            )
        
        if wipe_selection == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        wipesize_cmd_string = "" # Default to wiping the whole card
        if button_data[wipe_selection] == self.WIPE_64MB:
            wipesize_cmd_string = " count=64"
        elif button_data[wipe_selection] == self.WIPE_256MB:
            wipesize_cmd_string = " count=256"

        ret = self.run_screen(
            WarningScreen,
            title="Notice",
            status_headline=None,
            text="Insert MicroSD to be Wiped",
            show_back_button=True,
            button_data=[ButtonOption("Continue")]
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(text="Wiping MicroSD\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()

        if platform.uname()[1] == "seedsigner-os":
            cmd = "dd if=/dev/zero of=/dev/mmcblk0 bs=1M" + wipesize_cmd_string
        else:
            cmd = "sudo dd if=/dev/zero of=/dev/mmcblk0 bs=1M" + wipesize_cmd_string

        data = run(cmd, capture_output=True, shell=True, text=True)

        logger.info(data)

        self.loading_screen.stop()

        data_stderr_split = data.stderr.split('\n')

        inNum = 1
        outNum = 0
        for errorLine in data_stderr_split:
            if "records in" in errorLine:
                inNum = errorLine.split("+")[0]
                continue
            elif "records out" in errorLine:
                outNum = errorLine.split("+")[0]
                continue

        # The number of in/out records won't match we just keep writing until the disk is full...
        if "No space left on device" in data.stderr:
            outNum = inNum

        if inNum != outNum:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=data.stderr,
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )
        else:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"MicroSD Wiped",
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        return Destination(MainMenuView)

class ToolsMicroSDWipeRandomView(View):
    WIPE_64MB = ButtonOption("64MB")
    WIPE_256MB = ButtonOption("256MB")
    WIPE_ALL = ButtonOption("All")

    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        button_data=[self.WIPE_64MB, self.WIPE_256MB, self.WIPE_ALL]

        wipe_selection = self.run_screen(
                LargeIconStatusScreen,
                title="Wipe MicroSD",
                status_headline=None,
                text = "Select amount to wipe (Larger takes longer)",
                status_icon_size=0,
                show_back_button=True,
                button_data=button_data,
            )
        
        if wipe_selection == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        wipesize_cmd_string = "" # Default to wiping the whole card
        if button_data[wipe_selection] == self.WIPE_64MB:
            wipesize_cmd_string = " count=64"
        elif button_data[wipe_selection] == self.WIPE_256MB:
            wipesize_cmd_string = " count=256"

        ret = self.run_screen(
            WarningScreen,
            title="Notice",
            status_headline=None,
            text="Insert MicroSD to be Wiped",
            show_back_button=True,
            button_data=[ButtonOption("Continue")]
        )

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(text="Wiping MicroSD\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()

        if platform.uname()[1] == "seedsigner-os":
            cmd = "dd if=/dev/urandom of=/dev/mmcblk0 bs=1M" + wipesize_cmd_string
        else:
            cmd = "sudo dd if=/dev/urandom of=/dev/mmcblk0 bs=1M" + wipesize_cmd_string

        data = run(cmd, capture_output=True, shell=True, text=True)

        logger.info(data)

        self.loading_screen.stop()

        data_stderr_split = data.stderr.split('\n')

        inNum = 1
        outNum = 0
        for errorLine in data_stderr_split:
            if "records in" in errorLine:
                inNum = errorLine.split("+")[0]
                continue

            if "records out" in errorLine:
                outNum = errorLine.split("+")[0]
                continue

        # The number of in/out records won't match we just keep writing until the disk is full...
        if "No space left on device" in data.stderr:
            outNum = inNum

        if inNum != outNum:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=data.stderr,
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )
        else:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"MicroSD Wiped",
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        return Destination(MainMenuView)