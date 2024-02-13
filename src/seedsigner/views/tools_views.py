from dataclasses import dataclass
import hashlib
import os
import time
import platform

from embit.descriptor import Descriptor
from PIL import Image
from PIL.ImageOps import autocontrast

from seedsigner.controller import Controller
from seedsigner.gui.components import FontAwesomeIconConstants, GUIConstants, SeedSignerIconConstants
from seedsigner.gui.screens import (RET_CODE__BACK_BUTTON, ButtonListScreen)
from seedsigner.gui.screens.tools_screens import (ToolsCalcFinalWordDoneScreen, ToolsCalcFinalWordFinalizePromptScreen,
    ToolsCalcFinalWordScreen, ToolsCoinFlipEntryScreen, ToolsDiceEntropyEntryScreen, ToolsImageEntropyFinalImageScreen,
    ToolsImageEntropyLivePreviewScreen, ToolsAddressExplorerAddressTypeScreen)
from seedsigner.helpers import embit_utils, mnemonic_generation
from seedsigner.models.encode_qr import GenericStaticQrEncoder
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.seed_views import SeedDiscardView, SeedFinalizeView, SeedMnemonicEntryView, SeedOptionsView, SeedWordsWarningView, SeedExportXpubScriptTypeView, LoadSeedView

from .view import View, Destination, BackStackView, MainMenuView

from seedsigner.helpers import seedkeeper_utils
from seedsigner.gui.screens import (RET_CODE__BACK_BUTTON, ButtonListScreen,
    WarningScreen, DireWarningScreen, seed_screens, LargeIconStatusScreen)

class ToolsMenuView(View):
    IMAGE = (" New seed", FontAwesomeIconConstants.CAMERA)
    DICE = ("New seed", FontAwesomeIconConstants.DICE)
    KEYBOARD = ("Calc 12th/24th word", FontAwesomeIconConstants.KEYBOARD)
    EXPLORER = "Address Explorer"
    ADDRESS = "Verify address"
    SMARTCARD = ("Smartcard Tools", FontAwesomeIconConstants.LOCK)
    MICROSD = "MicroSD Tools"

    def run(self):
        button_data = [self.IMAGE, self.DICE, self.KEYBOARD, self.EXPLORER, self.ADDRESS, self.SMARTCARD, self.MICROSD]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Tools",
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

        elif button_data[selected_menu_num] == self.EXPLORER:
            return Destination(ToolsAddressExplorerSelectSourceView)

        elif button_data[selected_menu_num] == self.ADDRESS:
            from seedsigner.views.scan_views import ScanAddressView
            return Destination(ScanAddressView)

        elif button_data[selected_menu_num] == self.SMARTCARD:
            return Destination(ToolsSmartcardMenuView)
        
        elif button_data[selected_menu_num] == self.MICROSD:
            return Destination(ToolsMicroSDMenuView)



"""****************************************************************************
    Image entropy Views
****************************************************************************"""
class ToolsImageEntropyLivePreviewView(View):
    def run(self):
        self.controller.image_entropy_preview_frames = None
        ret = ToolsImageEntropyLivePreviewScreen().display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        self.controller.image_entropy_preview_frames = ret
        return Destination(ToolsImageEntropyFinalImageView)



class ToolsImageEntropyFinalImageView(View):
    def run(self):
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
            (self.canvas_width, self.canvas_height), Image.BICUBIC
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
    def run(self):
        TWELVE_WORDS = "12 words"
        TWENTYFOUR_WORDS = "24 words"
        button_data = [TWELVE_WORDS, TWENTYFOUR_WORDS]

        selected_menu_num = ButtonListScreen(
            title="Mnemonic Length?",
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        if button_data[selected_menu_num] == TWELVE_WORDS:
            mnemonic_length = 12
        else:
            mnemonic_length = 24

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
            print(repr(e))
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
        TWELVE = f"12 words ({mnemonic_generation.DICE__NUM_ROLLS__12WORD} rolls)"
        TWENTY_FOUR = f"24 words ({mnemonic_generation.DICE__NUM_ROLLS__24WORD} rolls)"
        
        button_data = [TWELVE, TWENTY_FOUR]
        selected_menu_num = ButtonListScreen(
            title="Mnemonic Length",
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
    TWELVE = "12 words"
    TWENTY_FOUR = "24 words"

    def run(self):
        button_data = [self.TWELVE, self.TWENTY_FOUR]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Mnemonic Length",
            is_bottom_list=True,
            is_button_text_centered=True,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.TWELVE:
            self.controller.storage.init_pending_mnemonic(12)

            # return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True))
            return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True))

        elif button_data[selected_menu_num] == self.TWENTY_FOUR:
            self.controller.storage.init_pending_mnemonic(24)

            # return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True))
            return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True))



class ToolsCalcFinalWordFinalizePromptView(View):
    def run(self):
        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_length = len(mnemonic)
        if mnemonic_length == 12:
            num_entropy_bits = 7
        else:
            num_entropy_bits = 3

        COIN_FLIPS = "Coin flip entropy"
        SELECT_WORD = f"Word selection entropy"
        ZEROS = "Finalize with zeros"

        button_data = [COIN_FLIPS, SELECT_WORD, ZEROS]
        selected_menu_num = ToolsCalcFinalWordFinalizePromptScreen(
            mnemonic_length=mnemonic_length,
            num_entropy_bits=num_entropy_bits,
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == COIN_FLIPS:
            return Destination(ToolsCalcFinalWordCoinFlipsView)

        elif button_data[selected_menu_num] == SELECT_WORD:
            # Clear the final word slot, just in case we're returning via BACK button
            self.controller.storage.update_pending_mnemonic(None, mnemonic_length - 1)
            return Destination(SeedMnemonicEntryView, view_args=dict(is_calc_final_word=True, cur_word_index=mnemonic_length - 1))

        elif button_data[selected_menu_num] == ZEROS:
            # User skipped the option to select a final word to provide last bits of
            # entropy. We'll insert all zeros and piggy-back on the coin flip attr
            wordlist_language_code = self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
            self.controller.storage.update_pending_mnemonic(Seed.get_wordlist(wordlist_language_code)[0], mnemonic_length - 1)
            return Destination(ToolsCalcFinalWordShowFinalWordView, view_args=dict(coin_flips="0" * num_entropy_bits))



class ToolsCalcFinalWordCoinFlipsView(View):
    def run(self):
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
        NEXT = "Next"
        button_data = [NEXT]
        selected_menu_num = self.run_screen(
            ToolsCalcFinalWordScreen,
            title="Final Word Calc",
            button_data=button_data,
            selected_final_word=self.selected_final_word,
            selected_final_bits=self.selected_final_bits,
            checksum_bits=self.checksum_bits,
            actual_final_word=self.actual_final_word,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == NEXT:
            return Destination(ToolsCalcFinalWordDoneView)



class ToolsCalcFinalWordDoneView(View):
    def run(self):
        mnemonic = self.controller.storage.pending_mnemonic
        mnemonic_word_length = len(mnemonic)
        final_word = mnemonic[-1]

        LOAD = "Load seed"
        DISCARD = ("Discard", None, None, "red")
        button_data = [LOAD, DISCARD]

        selected_menu_num = ToolsCalcFinalWordDoneScreen(
            final_word=final_word,
            mnemonic_word_length=mnemonic_word_length,
            fingerprint=self.controller.storage.get_pending_mnemonic_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK)),
            button_data=button_data,
        ).display()

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        
        self.controller.storage.convert_pending_mnemonic_to_pending_seed()

        if button_data[selected_menu_num] == LOAD:
            return Destination(SeedFinalizeView)
        
        elif button_data[selected_menu_num] == DISCARD:
            return Destination(SeedDiscardView)


"""****************************************************************************
    Address Explorer Views
****************************************************************************"""
class ToolsAddressExplorerSelectSourceView(View):
    SCAN_SEED = ("Scan a seed", SeedSignerIconConstants.QRCODE)
    SCAN_DESCRIPTOR = ("Scan wallet descriptor", SeedSignerIconConstants.QRCODE)
    TYPE_12WORD = ("Enter 12-word seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_24WORD = ("Enter 24-word seed", FontAwesomeIconConstants.KEYBOARD)


    def run(self):
        seeds = self.controller.storage.seeds
        button_data = []
        for seed in seeds:
            button_str = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            button_data.append((button_str, SeedSignerIconConstants.FINGERPRINT))
        button_data = button_data + [self.SCAN_SEED, self.SCAN_DESCRIPTOR, self.TYPE_12WORD, self.TYPE_24WORD]
        
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Address Explorer",
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

        elif button_data[selected_menu_num] == self.SCAN_SEED:
            from seedsigner.views.scan_views import ScanSeedQRView
            return Destination(ScanSeedQRView)

        elif button_data[selected_menu_num] == self.SCAN_DESCRIPTOR:
            from seedsigner.views.scan_views import ScanWalletDescriptorView
            return Destination(ScanWalletDescriptorView)

        elif button_data[selected_menu_num] in [self.TYPE_12WORD, self.TYPE_24WORD]:
            from seedsigner.views.seed_views import SeedMnemonicEntryView
            if button_data[selected_menu_num] == self.TYPE_12WORD:
                self.controller.storage.init_pending_mnemonic(num_words=12)
            else:
                self.controller.storage.init_pending_mnemonic(num_words=24)
            return Destination(SeedMnemonicEntryView)



class ToolsAddressExplorerAddressTypeView(View):
    RECEIVE = "Receive Addresses"
    CHANGE = "Change Addresses"


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

            if self.script_type == SettingsConstants.CUSTOM_DERIVATION:
                derivation_path = self.custom_derivation
            else:
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
        data = self.controller.address_explorer_data

        wallet_descriptor_display_name = None
        if "wallet_descriptor" in data:
            wallet_descriptor_display_name = data["wallet_descriptor"].brief_policy.replace(" (sorted)", "")

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
                self.loading_screen = LoadingScreenThread(text="Calculating addrs...")
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
                        raise Exception("Custom Derivation address explorer not yet implemented")
                
                elif "wallet_descriptor" in data:
                    descriptor: Descriptor = data["wallet_descriptor"]
                    if descriptor.is_basic_multisig:
                        for i in range(self.start_index, self.start_index + addrs_per_screen):
                            address = embit_utils.get_multisig_address(descriptor=descriptor, index=i, is_change=self.is_change, embit_network=data["embit_network"])
                            addresses.append(address)
                            data[addr_storage_key].append(address)

                    else:
                        raise Exception("Single sig descriptors not yet supported")
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
            button_data.append(f"{cur_index}:{address[:8]}...{address[end_digits:]}")

        button_data.append(("Next {}".format(addrs_per_screen), None, None, None, SeedSignerIconConstants.CHEVRON_RIGHT))

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="{} Addrs".format("Receive" if not self.is_change else "Change"),
            button_data=button_data,
            button_font_name=GUIConstants.FIXED_WIDTH_EMPHASIS_FONT_NAME,
            button_font_size=GUIConstants.BUTTON_FONT_SIZE + 4,
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
    def __init__(self, index: int, address: str, is_change: bool, start_index: int, parent_initial_scroll: int = 0):
        super().__init__()
        self.index = index
        self.address = address
        self.is_change = is_change
        self.start_index = start_index
        self.parent_initial_scroll = parent_initial_scroll

    
    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
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
    CHANGE_PIN = ("Change PIN")
    CHANGE_LABEL = ("Change Label")
    SATOCHIP = ("Satochip Functions")
    Satochip_DIY = ("DIY Tools")

    def run(self):
        button_data = [self.CHANGE_PIN, self.CHANGE_LABEL, self.SATOCHIP, self.Satochip_DIY]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Smartcard Tools",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.CHANGE_PIN:
            return Destination(ToolsSatochipChangePinView)
        
        elif button_data[selected_menu_num] == self.CHANGE_LABEL:
            return Destination(ToolsSatochipChangeLabelView)

        elif button_data[selected_menu_num] == self.SATOCHIP:
            return Destination(ToolsSatochipView)

        elif button_data[selected_menu_num] == self.Satochip_DIY:
            return Destination(ToolsSatochipDIYView)


class ToolsSatochipChangePinView(View):
    def run(self):
        
        Satochip_Connector = seedkeeper_utils.init_satochip(self)

        if not Satochip_Connector:
            return Destination(BackStackView)

        NewPin = seed_screens.SeedAddPassphraseScreen(title="New PIN").display()

        if NewPin == RET_CODE__BACK_BUTTON:
            return Destination(ToolsSmartcardMenuView)
        
        new_pin = list(NewPin.encode('utf8'))
        response, sw1, sw2 = Satochip_Connector.card_change_PIN(0, Satochip_Connector.pin, new_pin)
        if sw1 == 0x90 and sw2 == 0x00:
            print("Success: Pin Changed")
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"PIN Updated",
                show_back_button=False,
            )
        else:
            print("Failure: Pin Change Failed")
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
        
        Satochip_Connector = seedkeeper_utils.init_satochip(self)

        if not Satochip_Connector:
            return Destination(BackStackView)

        NewLabel = seed_screens.SeedAddPassphraseScreen(title="New Label").display()

        if NewLabel == RET_CODE__BACK_BUTTON:
            return Destination(ToolsSmartcardMenuView)

        """Sets a plain text label for the card (Optional)"""
        try:
            (response, sw1, sw2) = Satochip_Connector.card_set_label(NewLabel)
            if sw1 != 0x90 or sw2 != 0x00:
                print("ERROR: Set Label Failed")
                self.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text=f"Set Label Failed...",
                    show_back_button=True,
                )
            else:
                print("Device Label Updated")
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"Label Updated",
                    show_back_button=False,
                )
        except Exception as e:
            print(e)

        return Destination(MainMenuView)

class ToolsSatochipView(View):
    IMPORT_SEED = ("Import Seed")
    ENABLE_2FA = ("Enable 2FA")

    def run(self):
        button_data = [self.IMPORT_SEED, self.ENABLE_2FA]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Satochip",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.IMPORT_SEED:
            return Destination(ToolsSatochipImportSeedView)

        elif button_data[selected_menu_num] == self.ENABLE_2FA:
            return Destination(ToolsSatochipEnable2FAView)
        
class ToolsSatochipImportSeedView(View):
    SCAN_SEED = ("Scan a seed", SeedSignerIconConstants.QRCODE)
    SCAN_DESCRIPTOR = ("Scan wallet descriptor", SeedSignerIconConstants.QRCODE)
    TYPE_12WORD = ("Enter 12-word seed", FontAwesomeIconConstants.KEYBOARD)
    TYPE_24WORD = ("Enter 24-word seed", FontAwesomeIconConstants.KEYBOARD)

    def run(self):
        
        Satochip_Connector = seedkeeper_utils.init_satochip(self)

        if not Satochip_Connector:
            return Destination(BackStackView)

        seeds = self.controller.storage.seeds
        button_data = []
        for seed in seeds:
            button_str = seed.get_fingerprint(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
            button_data.append((button_str, SeedSignerIconConstants.FINGERPRINT))
        button_data = button_data + [self.SCAN_SEED, self.SCAN_DESCRIPTOR, self.TYPE_12WORD, self.TYPE_24WORD]
        
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

        print(seeds[selected_menu_num])

        if len(seeds) > 0 and selected_menu_num < len(seeds):
            # User selected one of the n seeds
            try:
                Satochip_Connector.card_bip32_import_seed(seeds[selected_menu_num].seed_bytes)
                print("Seed Successfully Imported")
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"Seed Imported",
                    show_back_button=False,
                )
            except Exception as e:
                print(e)
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

        elif button_data[selected_menu_num] == self.SCAN_DESCRIPTOR:
            from seedsigner.views.scan_views import ScanWalletDescriptorView
            return Destination(ScanWalletDescriptorView)

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
        key = urandom(20)
        print("2FA Key:", binascii.hexlify(key))

        Satochip_Connector = seedkeeper_utils.init_satochip(self)

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
            qr_encoder = EncodeQR(qr_type=QRType.GENERIC_STRING, generic_string=binascii.hexlify(key).decode())
            self.run_screen(
                QRDisplayScreen,
                qr_encoder=qr_encoder,
            )
            Satochip_Connector.card_set_2FA_key(key, 0)
            print("Success: 2FA Key Imported and Enabled")
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"2FA Enabled",
                show_back_button=False,
            )
        except Exception as e:
            print(e)
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=f"Enable 2FA Failed",
                show_back_button=False,
            )

        return Destination(MainMenuView)

class ToolsSatochipDIYView(View):
    BUILD_APPLETS = ("Build Applets")
    INSTALL_APPLET = ("Install Applet")
    UNINSTALL_APPLET = ("Uninstall Applet")

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

            commandString = "/mnt/diy/ant/bin/ant -f /mnt/microsd/javacard-build.xml -DJAVA_HOME=/mnt/diy/jdk"
        else:
            if not os.path.exists("/boot/javacard-build.xml"):
                os.system("sudo cp /home/pi/seedsigner/tools/javacard-build.xml.manual /boot/javacard-build.xml")

            if not os.path.exists("/boot/javacard-cap/"):
                os.system("sudo mkdir -p /boot/javacard-cap/")

            commandString = "sudo ant -f /boot/javacard-build.xml"

        data = run(commandString, capture_output=True, shell=True, text=True)

        print(data)

        self.loading_screen.stop()

        if(len(data.stderr) > 1):
            data.stderr = data.stderr.split("Total time:")[0]
            self.run_screen(
                WarningScreen,
                title="Failed",
                status_headline=None,
                text=data.stderr.replace("\n", " "),
                show_back_button=False,
            )
        else:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Applets Built",
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

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select Applet",
            is_button_text_centered=False,
            button_data=cap_files
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        applet_file = cap_files[selected_file_num]
        print("Selected:", applet_file)

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

        installed_applets = seedkeeper_utils.run_globalplatform(self,"-l -v", "Checking Installed Applets", None)

        if installed_applets:
            installed_applets = installed_applets.split('\n')

            installed_applets_aids = []
            installed_applets_list = []

            for line in installed_applets:
                if "PKG: " in line:
                    package_info = line.split()
                    print(package_info)
                    # Ignore system packages
                    if package_info[1] in ['A0000001515350', 'A00000016443446F634C697465', 'A0000000620204', 'A0000000620202', 'D27600012401']:
                        continue
                    
                    installed_applets_list.append(package_info[3][2:-2])
                    installed_applets_aids.append(package_info[1])

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
    FLASH_IMAGE = ("Flash Image")
    VERIFY_IMAGE = ("Verify MicroSD")
    WIPE_ZERO = ("Wipe (Zero)")
    WIPE_RANDOM = ("Wipe (Random)")

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
            return Destination(ToolsMicroSDVerifyView)

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

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select Image",
            is_button_text_centered=False,
            button_data=microsd_images
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        microsd_image = microsd_images[selected_file_num]
        print("Selected:", microsd_image)

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

            self.run_screen(
                WarningScreen,
                title="Notice",
                status_headline=None,
                text="Insert MicroSD to be Flashed",
                show_back_button=False,
            )

            self.loading_screen = LoadingScreenThread(text="Flashing MicroSD\n\n\n\n\n\n")
            self.loading_screen.start()

            data = run("dd if=/tmp/img.img of=/dev/mmcblk0", capture_output=True, shell=True, text=True)

            self.loading_screen.stop()

            data_stderr_split = data.stderr.split('\n')

            inNum = 1
            outNum = 0
            for errorLine in data_stderr_split:
                if "Records In" in errorLine:
                    inNum = errorLine.split("+")[0]
                    continue
                elif "Records Out" in errorLine:
                    outNum = errorLine.split("+")[0]
                    continue

            if inNum != outNum:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=data.stderr,
                    show_back_button=False,
                )
            else:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"MicroSD Flashed",
                    show_back_button=False,
                )

        else:
            os.system("cp /boot/microsd-images/" + microsd_image + " /tmp/img.img")
            os.system("sudo dd if=/tmp/img.img of=/dev/mmcblk0")

        return Destination(MainMenuView)

class ToolsMicroSDVerifyView(View):
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

        print(data)

        self.loading_screen.stop()

        checksum = data.stdout[:64]

        formatted_checksum = data.stdout[:16] + "\n" + data.stdout[16:32] + "\n" + data.stdout[32:48] + "\n" + data.stdout[48:64]

        self.run_screen(
            WarningScreen,
            title="Unfamilliar Checksum",
            status_headline=None,
            text=formatted_checksum,
            show_back_button=False,
        )

        return Destination(MainMenuView)
    
class ToolsMicroSDWipeZeroView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        self.loading_screen = LoadingScreenThread(text="Wiping MicroSD\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()

        self.run_screen(
            WarningScreen,
            title="Notice",
            status_headline=None,
            text="Insert MicroSD to be Wiped",
            show_back_button=False,
        )

        if platform.uname()[1] == "seedsigner-os":
            cmd = "dd if=/dev/zero of=/dev/mmcblk0 bs=1M count=1024"
        else:
            cmd = "sudo dd if=/dev/zero of=/dev/mmcblk0 bs=1M count=1024"

        data = run(cmd, capture_output=True, shell=True, text=True)

        self.loading_screen.stop()

        data_stderr_split = data.stderr.split('\n')

        inNum = 1
        outNum = 0
        for errorLine in data_stderr_split:
            if "Records In" in errorLine:
                inNum = errorLine.split("+")[0]
                continue
            elif "Records Out" in errorLine:
                outNum = errorLine.split("+")[0]
                continue

        if inNum != outNum:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=data.stderr,
                show_back_button=False,
            )
        else:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"MicroSD Wiped",
                show_back_button=False,
            )

        return Destination(MainMenuView)

class ToolsMicroSDWipeRandomView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        self.loading_screen = LoadingScreenThread(text="Wiping MicroSD\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()

        self.run_screen(
            WarningScreen,
            title="Notice",
            status_headline=None,
            text="Insert MicroSD to be Wiped",
            show_back_button=False,
        )

        if platform.uname()[1] == "seedsigner-os":
            cmd = "dd if=/dev/urandom of=/dev/mmcblk0 bs=1M count=1024"
        else:
            cmd = "sudo dd if=/dev/urandom of=/dev/mmcblk0 bs=1M count=1024"

        data = run(cmd, capture_output=True, shell=True, text=True)

        self.loading_screen.stop()

        data_stderr_split = data.stderr.split('\n')

        inNum = 1
        outNum = 0
        for errorLine in data_stderr_split:
            if "Records In" in errorLine:
                inNum = errorLine.split("+")[0]
                continue
            elif "Records Out" in errorLine:
                outNum = errorLine.split("+")[0]
                continue

        if inNum != outNum:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=data.stderr,
                show_back_button=False,
            )
        else:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"MicroSD Wiped",
                show_back_button=False,
            )

        return Destination(MainMenuView)