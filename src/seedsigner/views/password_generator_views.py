"""****************************************************************************
    Password Generator Views
****************************************************************************"""
import hashlib
import logging
import os
import secrets
import struct
import time
from pathlib import Path

from embit.bip32 import HDKey
from gettext import gettext as _

from seedsigner.gui.components import (
    FontAwesomeIconConstants,
    GUIConstants,
    SeedSignerIconConstants,
)
from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    LargeIconStatusScreen,
    WarningScreen,
    ErrorScreen,
    ToolsTextQRReviewTextScreen,
)
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.helpers.iso7816 import format_sw_error
from seedsigner.models.seed import Seed
from seedsigner.models.settings_definition import SettingsConstants
from .view import View, Destination, BackStackView, MainMenuView

logger = logging.getLogger(__name__)

# ============================================================================
# Shared constants for password types & BIP-85 apps
# ============================================================================

PASSWORD_TYPE_RANDOM = "random"
PASSWORD_TYPE_DICEWARE_EFF_SHORT = "diceware_eff_short"
PASSWORD_TYPE_DICEWARE_EFF_LONG = "diceware_eff_long"
PASSWORD_TYPE_DICEWARE_BIP39 = "diceware_bip39"
PASSWORD_TYPE_DICE_ROLLS = "dice_rolls"
PASSWORD_TYPE_HEX = "hex"
PASSWORD_TYPE_BASE64 = "base64"
PASSWORD_TYPE_BASE85 = "base85"

PASSWORD_WORD_SEPARATOR_NONE = "none"
PASSWORD_WORD_SEPARATOR_CAPITALISE = "capitalise"
PASSWORD_WORD_SEPARATOR_SPACE = "space"
PASSWORD_WORD_SEPARATOR_DOT = "dot"

PASSWORD_ENTROPY_CAMERA = "camera"
PASSWORD_ENTROPY_DICE = "dice"
PASSWORD_ENTROPY_BIP85 = "bip85"
PASSWORD_ENTROPY_HARDWARE_RNG = "hardware_rng"



# ============================================================================
class ToolsPasswordGeneratorTypeView(View):
    def run(self):
        options = [
            (ButtonOption("Custom"), PASSWORD_TYPE_RANDOM),
            (ButtonOption("Diceware-EFF Short"), PASSWORD_TYPE_DICEWARE_EFF_SHORT),
            (ButtonOption("Diceware-EFF Long"), PASSWORD_TYPE_DICEWARE_EFF_LONG),
            (ButtonOption("Diceware-BIP39"), PASSWORD_TYPE_DICEWARE_BIP39),
            (ButtonOption("Base85"), PASSWORD_TYPE_BASE85),
            (ButtonOption("Base64"), PASSWORD_TYPE_BASE64),
            (ButtonOption("Hex"), PASSWORD_TYPE_HEX),
            (ButtonOption("Dice Rolls"), PASSWORD_TYPE_DICE_ROLLS),
        ]
        button_data = [button for button, _ in options]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Password Type"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        password_type = options[selected_menu_num][1]
        if password_type == PASSWORD_TYPE_DICE_ROLLS:
            return Destination(
                ToolsPasswordDiceRollCountView,
                view_args=dict(
                    password_type=password_type,
                    strength_bits=64,
                    entropy_source=None,
                ),
            )
        return Destination(
            ToolsPasswordStrengthView,
            view_args=dict(password_type=password_type),
        )


class ToolsPasswordStrengthView(View):
    def __init__(self, password_type: str):
        super().__init__()
        self.password_type = password_type

    def run(self):
        options = [
            ButtonOption("64 bits", return_data=64),
            ButtonOption("128 bits", return_data=128),
            ButtonOption("256 bits", return_data=256),
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Password Strength"),
            is_button_text_centered=False,
            selected_button=1,
            button_data=options,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        strength_bits = options[selected_menu_num].return_data
        if self.password_type == PASSWORD_TYPE_RANDOM:
            return Destination(
                ToolsPasswordRandomOptionsView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=strength_bits,
                ),
            )
        return Destination(
            ToolsPasswordEntropySourceView,
            view_args=dict(
                password_type=self.password_type,
                strength_bits=strength_bits,
            ),
        )


class ToolsPasswordRandomOptionsView(View):
    def __init__(self, password_type: str, strength_bits: int):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits

    def _prompt_choice(self, title: str) -> bool | None:
        yes = ButtonOption("Yes")
        no = ButtonOption("No")
        selected = self.run_screen(
            ButtonListScreen,
            title=title,
            is_button_text_centered=True,
            button_data=[yes, no],
        )
        if selected == RET_CODE__BACK_BUTTON:
            return None
        return selected == 0

    def run(self):
        while True:
            lower = self._prompt_choice("Lowercase?")
            if lower is None:
                return Destination(BackStackView)
            upper = self._prompt_choice("Uppercase?")
            if upper is None:
                return Destination(BackStackView)
            digits = self._prompt_choice("Numbers?")
            if digits is None:
                return Destination(BackStackView)
            special = self._prompt_choice("Specials?")
            if special is None:
                return Destination(BackStackView)
            random_options = {
                "lower": lower,
                "upper": upper,
                "digits": digits,
                "special": special,
            }
            if any(random_options.values()):
                return Destination(
                    ToolsPasswordEntropySourceView,
                    view_args=dict(
                        password_type=self.password_type,
                        strength_bits=self.strength_bits,
                        random_options=random_options,
                    ),
                )
            self.run_screen(
                WarningScreen,
                title=_("Select Options"),
                status_headline=None,
                text=_("Choose at least one character set."),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )


class ToolsPasswordEntropySourceView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        random_options: dict | None = None,
        dice_sides: int | None = None,
        roll_count: int | None = None,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.dice_sides = dice_sides
        self.roll_count = roll_count

    def _hardware_rng_available(self) -> bool:
        if self.controller.hardware_rng_is_healthy:
            return True
        reason = self.controller.hardware_rng_failure_reason or _("System RNG health check failed.")
        self.run_screen(
            WarningScreen,
            title=_("System RNG Error"),
            status_headline=None,
            text=reason,
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
        return False

    def run(self):
        _clear_password_entropy_cache(self.controller)

        camera = ButtonOption("Camera")
        dice = ButtonOption("Dice")
        hardware_rng = ButtonOption("System RNG")
        bip85 = ButtonOption("BIP85")

        if self.password_type == PASSWORD_TYPE_DICE_ROLLS:
            button_data = [camera, hardware_rng, bip85]
        else:
            button_data = [camera, dice, hardware_rng, bip85]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Entropy Source"),
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        selected = button_data[selected_menu_num]
        if selected == bip85 and not _bip85_supported_password_type(self.password_type):
            self.run_screen(
                WarningScreen,
                title=_("Not Supported"),
                status_headline=None,
                text=_("BIP85 supports Diceware, Dice Rolls, Hex, Base64, and Base85."),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(
                ToolsPasswordEntropySourceView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                ),
            )

        if selected == camera:
            if self.password_type in {
                PASSWORD_TYPE_DICEWARE_EFF_SHORT,
                PASSWORD_TYPE_DICEWARE_EFF_LONG,
                PASSWORD_TYPE_DICEWARE_BIP39,
            }:
                return Destination(
                    ToolsImageEntropyLivePreviewView,
                    view_args=dict(
                        next_view=ToolsPasswordWordSeparatorView,
                        next_view_args=dict(
                            password_type=self.password_type,
                            strength_bits=self.strength_bits,
                            random_options=self.random_options,
                            entropy_source=PASSWORD_ENTROPY_CAMERA,
                        ),
                    ),
                )
            return Destination(
                ToolsImageEntropyLivePreviewView,
                view_args=dict(
                    next_view=ToolsPasswordGenerateView,
                    next_view_args=dict(
                        password_type=self.password_type,
                        strength_bits=self.strength_bits,
                        entropy_source=PASSWORD_ENTROPY_CAMERA,
                        random_options=self.random_options,
                        roll_count=self.roll_count,
                        dice_sides=self.dice_sides or 6,
                    ),
                ),
            )

        if selected == dice:
            if self.password_type == PASSWORD_TYPE_DICE_ROLLS and self.dice_sides is not None and self.roll_count is not None:
                return Destination(
                    ToolsPasswordDiceEntryView,
                    view_args=dict(
                        password_type=self.password_type,
                        random_options=self.random_options,
                        strength_bits=self.strength_bits,
                        total_rolls=self.roll_count,
                        word_count=None,
                        entropy_source=PASSWORD_ENTROPY_DICE,
                        dice_sides=self.dice_sides,
                    ),
                    skip_current_view=True,
                )
            return Destination(
                ToolsPasswordDiceRollCountView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    entropy_source=PASSWORD_ENTROPY_DICE,
                ),
            )

        if selected == hardware_rng:
            if not self._hardware_rng_available():
                return Destination(BackStackView)
            if _is_diceware_password_type(getattr(self, "password_type", None)):
                return Destination(
                    ToolsPasswordHardwareRngEntropyView,
                    view_args=dict(
                        password_type=self.password_type,
                        strength_bits=self.strength_bits,
                        random_options=self.random_options,
                    ),
                )
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    entropy_source=PASSWORD_ENTROPY_HARDWARE_RNG,
                    random_options=self.random_options,
                    roll_count=self.roll_count,
                    dice_sides=self.dice_sides or 6,
                ),
            )

        return Destination(
            ToolsPasswordBIP85GenerateView,
            view_args=dict(
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                random_options=self.random_options,
                dice_sides=self.dice_sides,
                roll_count=self.roll_count,
            ),
        )


class ToolsPasswordHardwareRngEntropyView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        random_options: dict | None = None,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}

    def run(self):
        if not self.controller.hardware_rng_is_healthy:
            self.run_screen(
                WarningScreen,
                title=_("System RNG Error"),
                status_headline=None,
                text=self.controller.hardware_rng_failure_reason or _("System RNG health check failed."),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        entropy_bytes = _derive_hardware_rng_entropy_bytes()
        _cache_password_entropy(
            self.controller,
            password_type=self.password_type,
            strength_bits=self.strength_bits,
            entropy_source=PASSWORD_ENTROPY_HARDWARE_RNG,
            word_count=_diceware_word_count(self.password_type, self.strength_bits),
            roll_data=None,
            entropy_bytes=entropy_bytes,
        )
        return Destination(
            ToolsPasswordWordSeparatorView,
            view_args=dict(
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                random_options=self.random_options,
                entropy_source=PASSWORD_ENTROPY_HARDWARE_RNG,
            ),
            skip_current_view=True,
        )


class ToolsPasswordWordSeparatorView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        random_options: dict | None = None,
        entropy_source: str | None = PASSWORD_ENTROPY_DICE,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.entropy_source = entropy_source

    def run(self):
        cached_entropy = _get_password_entropy_cache(self.controller)

        separator_options = [
            (ButtonOption("None"), PASSWORD_WORD_SEPARATOR_NONE),
            (ButtonOption("Capitalise"), PASSWORD_WORD_SEPARATOR_CAPITALISE),
            (ButtonOption("Space"), PASSWORD_WORD_SEPARATOR_SPACE),
            (ButtonOption("."), PASSWORD_WORD_SEPARATOR_DOT),
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Separator"),
            is_button_text_centered=False,
            selected_button=1,
            button_data=[button for button, _ in separator_options],
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            _clear_password_entropy_cache(self.controller)
            return Destination(
                ToolsPasswordEntropySourceView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                ),
                skip_current_view=True,
            )

        word_separator = separator_options[selected_menu_num][1]

        if cached_entropy and cached_entropy.get("password_type") == self.password_type \
            and cached_entropy.get("strength_bits") == self.strength_bits \
            and cached_entropy.get("entropy_source") == self.entropy_source:
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=self.entropy_source,
                    random_options=self.random_options,
                    strength_bits=self.strength_bits,
                    word_count=cached_entropy.get("word_count"),
                    word_separator=word_separator,
                    roll_data=cached_entropy.get("roll_data"),
                    entropy_bytes_override=cached_entropy.get("entropy_bytes"),
                ),
                skip_current_view=True,
            )

        return Destination(
            ToolsPasswordDiceRollCountView,
            view_args=dict(
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                random_options=self.random_options,
                word_separator=word_separator,
                entropy_source=self.entropy_source,
            ),
        )


class ToolsPasswordDiceRollCountView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        random_options: dict | None = None,
        word_separator: str = PASSWORD_WORD_SEPARATOR_NONE,
        entropy_source: str = PASSWORD_ENTROPY_DICE,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.word_separator = word_separator
        self.entropy_source = entropy_source

    def _prompt_dice_sides(self) -> int | None:
        side_options = [
            ButtonOption("6 sides", return_data=6),
            ButtonOption("10 sides", return_data=10),
            ButtonOption("20 sides", return_data=20),
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Dice Sides"),
            is_button_text_centered=False,
            selected_button=0,
            button_data=side_options,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return None
        return int(side_options[selected_menu_num].return_data)

    def _prompt_roll_count(self) -> int | None:
        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title=_("Number of Rolls")).display()
        if ret == RET_CODE__BACK_BUTTON:
            return None
        if not ret:
            return 0
        return int(ret)

    def run(self):
        if self.password_type in {
            PASSWORD_TYPE_DICEWARE_EFF_SHORT,
            PASSWORD_TYPE_DICEWARE_EFF_LONG,
            PASSWORD_TYPE_DICEWARE_BIP39,
        } and self.entropy_source in {
            PASSWORD_ENTROPY_CAMERA,
            PASSWORD_ENTROPY_HARDWARE_RNG,
        }:
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=self.entropy_source,
                    random_options=self.random_options,
                    strength_bits=self.strength_bits,
                    word_count=_diceware_word_count(self.password_type, self.strength_bits),
                    word_separator=self.word_separator,
                ),
                skip_current_view=True,
            )

        if self.password_type == PASSWORD_TYPE_DICE_ROLLS:
            dice_sides = self._prompt_dice_sides()
            if dice_sides is None:
                return Destination(BackStackView)

            roll_count = self._prompt_roll_count()
            if roll_count is None:
                return Destination(BackStackView)
            if roll_count < 1:
                self.run_screen(
                    WarningScreen,
                    title=_("Invalid Input"),
                    status_headline=None,
                    text=_("Number of rolls must be at least 1."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            if self.entropy_source is None:
                return Destination(
                    ToolsPasswordEntropySourceView,
                    view_args=dict(
                        password_type=self.password_type,
                        strength_bits=self.strength_bits,
                        random_options=self.random_options,
                        dice_sides=dice_sides,
                        roll_count=roll_count,
                    ),
                    skip_current_view=True,
                )

            if self.entropy_source == PASSWORD_ENTROPY_DICE:
                return Destination(
                    ToolsPasswordDiceEntryView,
                    view_args=dict(
                        password_type=self.password_type,
                        random_options=self.random_options,
                        strength_bits=self.strength_bits,
                        total_rolls=roll_count,
                        word_count=None,
                        word_separator=self.word_separator,
                        entropy_source=PASSWORD_ENTROPY_DICE,
                        dice_sides=dice_sides,
                    ),
                    skip_current_view=True,
                )

            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=self.entropy_source,
                    random_options=self.random_options,
                    strength_bits=self.strength_bits,
                    roll_count=roll_count,
                    word_count=None,
                    word_separator=self.word_separator,
                    dice_sides=dice_sides,
                ),
                skip_current_view=True,
            )

        word_count = None
        if self.password_type in {
            PASSWORD_TYPE_DICEWARE_EFF_SHORT,
            PASSWORD_TYPE_DICEWARE_EFF_LONG,
            PASSWORD_TYPE_DICEWARE_BIP39,
        }:
            word_count = _diceware_word_count(self.password_type, self.strength_bits)
            if self.password_type == PASSWORD_TYPE_DICEWARE_EFF_SHORT:
                total_rolls = word_count * 4
            elif self.password_type == PASSWORD_TYPE_DICEWARE_EFF_LONG:
                total_rolls = word_count * 5
            else:
                total_rolls = max(1, math.ceil(word_count * 11 / math.log2(6)))
        else:
            total_rolls = _dice_rolls_for_strength(self.strength_bits)
        return Destination(
            ToolsPasswordDiceEntryView,
            view_args=dict(
                password_type=self.password_type,
                random_options=self.random_options,
                strength_bits=self.strength_bits,
                total_rolls=total_rolls,
                word_count=word_count,
                word_separator=self.word_separator,
                entropy_source=self.entropy_source,
            ),
            skip_current_view=True,
        )


class ToolsPasswordDiceEntryView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        total_rolls: int,
        random_options: dict | None = None,
        word_count: int | None = None,
        word_separator: str = PASSWORD_WORD_SEPARATOR_NONE,
        entropy_source: str = PASSWORD_ENTROPY_DICE,
        dice_sides: int = 6,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.total_rolls = total_rolls
        self.random_options = random_options or {}
        self.word_count = word_count
        self.word_separator = word_separator
        self.entropy_source = entropy_source
        self.dice_sides = dice_sides

    def run(self):
        ret = ToolsDiceEntropyEntryScreen(
            return_after_n_chars=self.total_rolls,
        ).display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if not mnemonic_generation.dice_entropy_is_sufficient(ret):
            self.run_screen(
                ErrorScreen,
                title=_("Poor Entropy"),
                status_headline=None,
                text=_("Dice rolls didn't appear random enough. Please try again."),
            )
            return Destination(BackStackView)

        if _is_diceware_password_type(getattr(self, "password_type", None)):
            _cache_password_entropy(
                self.controller,
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                entropy_source=self.entropy_source,
                word_count=self.word_count,
                roll_data=ret,
                entropy_bytes=None,
            )
            return Destination(
                ToolsPasswordWordSeparatorView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    entropy_source=self.entropy_source,
                ),
                skip_current_view=True,
            )

        return Destination(
            ToolsPasswordGenerateView,
            view_args=dict(
                password_type=self.password_type,
                entropy_source=self.entropy_source,
                random_options=self.random_options,
                strength_bits=self.strength_bits,
                roll_data=ret,
                roll_count=self.total_rolls,
                word_count=self.word_count,
                word_separator=self.word_separator,
                dice_sides=self.dice_sides,
            ),
        )


class ToolsPasswordGenerateView(View):
    def __init__(
        self,
        password_type: str,
        entropy_source: str,
        strength_bits: int,
        random_options: dict | None = None,
        roll_data: bytes | str | None = None,
        roll_count: int | None = None,
        word_count: int | None = None,
        word_separator: str = PASSWORD_WORD_SEPARATOR_NONE,
        entropy_bytes_override: bytes | None = None,
        dice_sides: int = 6,
    ):
        super().__init__()
        self.password_type = password_type
        self.entropy_source = entropy_source
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.roll_data = roll_data
        self.roll_count = roll_count
        self.word_count = word_count
        self.word_separator = word_separator
        self.entropy_bytes_override = entropy_bytes_override
        self.dice_sides = dice_sides

    def _bip39_words_from_entropy(self, seed: bytes, word_count: int) -> list[str]:
        wordlist = Seed.get_wordlist(
            self.settings.get_value(SettingsConstants.SETTING__WORDLIST_LANGUAGE)
        )
        total_bits = word_count * 11
        num_bytes = math.ceil(total_bits / 8)
        data = password_generation.shake_stream(seed).read(num_bytes)
        bit_string = "".join(f"{byte:08b}" for byte in data)
        words = []
        for i in range(word_count):
            idx = int(bit_string[i * 11 : (i + 1) * 11], 2)
            # Create an independent copy to avoid holding a direct
            # reference to the shared global wordlist string.
            words.append("".join(wordlist[idx]))
        return words

    def _dice_length_for_charset(self, alphabet_size: int) -> int:
        return _strength_to_length(self.strength_bits, alphabet_size)

    def _diceware_rolls_from_entropy(self, entropy_seed: bytes) -> str:
        if self.word_count is None:
            raise ValueError("Word count is required for diceware")
        if self.password_type == PASSWORD_TYPE_DICEWARE_EFF_SHORT:
            sides = 6
            rolls_per_word = 4
        elif self.password_type == PASSWORD_TYPE_DICEWARE_EFF_LONG:
            sides = 6
            rolls_per_word = 5
        else:
            sides = 2048
            rolls_per_word = 1
        roll_count = self.word_count * rolls_per_word
        return password_generation.dice_rolls_from_seed(entropy_seed, sides, roll_count)

    def _diceware_words(self, entropy_bytes: bytes | None = None) -> list[str]:
        if self.password_type == PASSWORD_TYPE_DICEWARE_BIP39 and self.entropy_source in {
            PASSWORD_ENTROPY_CAMERA,
            PASSWORD_ENTROPY_HARDWARE_RNG,
            PASSWORD_ENTROPY_BIP85,
        }:
            if self.word_count is None:
                raise ValueError("Word count is required for words")
            return self._bip39_words_from_entropy(entropy_bytes, self.word_count)

        roll_data = self.roll_data
        if self.password_type in {PASSWORD_TYPE_DICEWARE_EFF_SHORT, PASSWORD_TYPE_DICEWARE_EFF_LONG} and self.entropy_source in {
            PASSWORD_ENTROPY_CAMERA,
            PASSWORD_ENTROPY_HARDWARE_RNG,
            PASSWORD_ENTROPY_BIP85,
        }:
            if entropy_bytes is None:
                raise ValueError("Entropy is required for diceware")
            roll_data = self._diceware_rolls_from_entropy(entropy_bytes)

        if self.password_type == PASSWORD_TYPE_DICEWARE_EFF_SHORT:
            return diceware.diceware_words_from_rolls(
                roll_data, diceware.eff_short_map(), 4
            )
        if self.password_type == PASSWORD_TYPE_DICEWARE_EFF_LONG:
            return diceware.diceware_words_from_rolls(
                roll_data, diceware.eff_large_map(), 5
            )

        word_count = self.word_count
        if word_count is None:
            entropy_bits = password_generation.dice_roll_entropy_bits(self.roll_count)
            word_count = int(entropy_bits // 11)
        if word_count < 1:
            raise ValueError("Not enough entropy for words")
        entropy_seed = entropy_bytes if entropy_bytes is not None else mnemonic_generation._hash_dice_rolls(roll_data)
        return self._bip39_words_from_entropy(entropy_seed, word_count)

    def run(self):
        entropy_bytes_override = getattr(self, "entropy_bytes_override", None)
        if entropy_bytes_override is not None:
            entropy_bytes = entropy_bytes_override
        elif self.entropy_source == PASSWORD_ENTROPY_CAMERA:
            entropy_bytes = _derive_camera_entropy_bytes(
                self.controller.image_entropy_preview_frames,
                self.controller.image_entropy_final_image,
            )
            self.controller.image_entropy_preview_frames = None
            self.controller.image_entropy_final_image = None
            if entropy_bytes is None:
                self.run_screen(
                    ErrorScreen,
                    title=_("Poor Entropy"),
                    status_headline=None,
                    text=_("Camera entropy didn't appear random enough. Please try again."),
                )
                return Destination(BackStackView)
        elif self.entropy_source == PASSWORD_ENTROPY_HARDWARE_RNG:
            if not self.controller.hardware_rng_is_healthy:
                self.run_screen(
                    WarningScreen,
                    title=_("System RNG Error"),
                    status_headline=None,
                    text=self.controller.hardware_rng_failure_reason or _("System RNG health check failed."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            entropy_bytes = _derive_hardware_rng_entropy_bytes()
        else:
            entropy_bytes = self.roll_data if self.entropy_source == PASSWORD_ENTROPY_BIP85 else mnemonic_generation._hash_dice_rolls(self.roll_data)

        if self.password_type in {
            PASSWORD_TYPE_DICEWARE_EFF_SHORT,
            PASSWORD_TYPE_DICEWARE_EFF_LONG,
            PASSWORD_TYPE_DICEWARE_BIP39,
        }:
            _cache_password_entropy(
                self.controller,
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                entropy_source=self.entropy_source,
                word_count=self.word_count,
                roll_data=self.roll_data if self.entropy_source == PASSWORD_ENTROPY_DICE else None,
                entropy_bytes=entropy_bytes if self.entropy_source != PASSWORD_ENTROPY_DICE else None,
            )

        try:
            if self.password_type in {
                PASSWORD_TYPE_DICEWARE_EFF_SHORT,
                PASSWORD_TYPE_DICEWARE_EFF_LONG,
                PASSWORD_TYPE_DICEWARE_BIP39,
            }:
                words = self._diceware_words(entropy_bytes=entropy_bytes)
                password = _format_word_password(words, self.word_separator)
            elif self.password_type == PASSWORD_TYPE_RANDOM:
                charset = _random_charset(self.random_options)
                if self.entropy_source == PASSWORD_ENTROPY_DICE:
                    length = self._dice_length_for_charset(len(charset))
                else:
                    length = _strength_to_length(self.strength_bits, len(charset))
                password = password_generation.random_string_from_charset(
                    entropy_bytes, length, charset
                )
            elif self.password_type == PASSWORD_TYPE_DICE_ROLLS:
                if self.roll_count is None:
                    raise ValueError("Roll count is required")
                rolls = password_generation.dice_roll_values_from_seed(
                    entropy_bytes,
                    sides=self.dice_sides,
                    roll_count=self.roll_count,
                    base=0,
                )
                password = ",".join(str(roll) for roll in rolls)
            elif self.password_type == PASSWORD_TYPE_HEX:
                if self.entropy_source == PASSWORD_ENTROPY_DICE:
                    length = self._dice_length_for_charset(16)
                    password = password_generation.hex_password_from_seed(entropy_bytes, length)
                elif self.entropy_source == PASSWORD_ENTROPY_BIP85:
                    num_bytes = _strength_to_length(self.strength_bits, 256)
                    password = password_generation.bip85_hex_password(entropy_bytes, num_bytes)
                else:
                    length = _strength_to_length(self.strength_bits, 16)
                    password = password_generation.hex_password_from_seed(entropy_bytes, length)
            elif self.password_type == PASSWORD_TYPE_BASE64:
                if self.entropy_source == PASSWORD_ENTROPY_DICE:
                    length = self._dice_length_for_charset(64)
                    password = password_generation.base64_password_from_seed(
                        entropy_bytes, length
                    )
                elif self.entropy_source == PASSWORD_ENTROPY_BIP85:
                    length = _strength_to_length(self.strength_bits, 64)
                    password = password_generation.bip85_base64_password(
                        entropy_bytes, length
                    )
                else:
                    length = _strength_to_length(self.strength_bits, 64)
                    password = password_generation.base64_password_from_seed(
                        entropy_bytes, length
                    )
            else:
                if self.entropy_source == PASSWORD_ENTROPY_DICE:
                    length = self._dice_length_for_charset(85)
                    password = password_generation.base85_password_from_seed(
                        entropy_bytes, length
                    )
                elif self.entropy_source == PASSWORD_ENTROPY_BIP85:
                    length = _strength_to_length(self.strength_bits, 85)
                    password = password_generation.bip85_base85_password(
                        entropy_bytes, length
                    )
                else:
                    length = _strength_to_length(self.strength_bits, 85)
                    password = password_generation.base85_password_from_seed(
                        entropy_bytes, length
                    )
        except ValueError as exc:
            self.run_screen(
                WarningScreen,
                title=_("Invalid Input"),
                status_headline=None,
                text=str(exc),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        return Destination(
            ToolsPasswordReviewView,
            view_args=dict(
                password=password,
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                random_options=self.random_options,
                entropy_source=self.entropy_source,
            ),
            skip_current_view=True,
        )


class ToolsPasswordBIP85GenerateView(View):
    def __init__(
        self,
        password_type: str,
        strength_bits: int,
        random_options: dict | None = None,
        dice_sides: int | None = None,
        roll_count: int | None = None,
    ):
        super().__init__()
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.dice_sides = dice_sides
        self.roll_count = roll_count

    def _prompt_dice_sides(self) -> int | None:
        side_options = [
            ButtonOption("6 sides", return_data=6),
            ButtonOption("10 sides", return_data=10),
            ButtonOption("20 sides", return_data=20),
        ]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Dice Sides"),
            is_button_text_centered=False,
            selected_button=0,
            button_data=side_options,
        )
        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return None
        return int(side_options[selected_menu_num].return_data)

    def _prompt_roll_count(self) -> int | None:
        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title=_("Number of Rolls")).display()
        if ret == RET_CODE__BACK_BUTTON:
            return None
        if not ret:
            return 0
        return int(ret)

    def run(self):
        from embit import bip85

        if len(self.controller.storage.seeds) == 0:
            self.run_screen(
                WarningScreen,
                title=_("WARNING"),
                status_headline=None,
                text=_("Load a seed before using BIP85."),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        if len(self.controller.storage.seeds) > 1:
            seed_buttons = []
            for seed in self.controller.storage.seeds:
                button_str = seed.get_fingerprint(
                    self.settings.get_value(SettingsConstants.SETTING__NETWORK)
                )
                seed_buttons.append(
                    ButtonOption(
                        button_str,
                        SeedSignerIconConstants.FINGERPRINT,
                        icon_color="blue",
                    )
                )
            selected_seed = self.run_screen(
                seed_screens.SeedSelectSeedScreen,
                title=_("Select Seed"),
                text=_("Choose seed for BIP85"),
                is_button_text_centered=False,
                button_data=seed_buttons,
            )
            if selected_seed == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            seed = self.controller.get_seed(selected_seed)
        else:
            seed = self.controller.get_seed(0)

        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title=_("BIP85 Index")).display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        index = int(ret)

        root = seed.get_root(self.settings.get_value(SettingsConstants.SETTING__NETWORK))

        if self.password_type in {
            PASSWORD_TYPE_DICEWARE_EFF_SHORT,
            PASSWORD_TYPE_DICEWARE_EFF_LONG,
            PASSWORD_TYPE_DICEWARE_BIP39,
        }:
            if self.password_type == PASSWORD_TYPE_DICEWARE_BIP39:
                sides = 2048
                rolls = _diceware_word_count(self.password_type, self.strength_bits)
            elif self.password_type == PASSWORD_TYPE_DICEWARE_EFF_SHORT:
                sides = 6
                rolls = _diceware_word_count(self.password_type, self.strength_bits) * 4
            else:
                sides = 6
                rolls = _diceware_word_count(self.password_type, self.strength_bits) * 5
            entropy = bip85.derive_entropy(root, BIP85_APP_DICE, [sides, rolls, index])
            _cache_password_entropy(
                self.controller,
                password_type=self.password_type,
                strength_bits=self.strength_bits,
                entropy_source=PASSWORD_ENTROPY_BIP85,
                word_count=_diceware_word_count(self.password_type, self.strength_bits),
                roll_data=None,
                entropy_bytes=entropy,
            )
            return Destination(
                ToolsPasswordWordSeparatorView,
                view_args=dict(
                    password_type=self.password_type,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    entropy_source=PASSWORD_ENTROPY_BIP85,
                ),
            )


        if self.password_type == PASSWORD_TYPE_DICE_ROLLS:
            sides = getattr(self, "dice_sides", None)
            if sides is None:
                sides = self._prompt_dice_sides()
                if sides is None:
                    return Destination(BackStackView)
            rolls = getattr(self, "roll_count", None)
            if rolls is None:
                rolls = self._prompt_roll_count()
                if rolls is None:
                    return Destination(BackStackView)
            if rolls < 1:
                self.run_screen(
                    WarningScreen,
                    title=_("Invalid Input"),
                    status_headline=None,
                    text=_("Number of rolls must be at least 1."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            entropy = bip85.derive_entropy(root, BIP85_APP_DICE, [sides, rolls, index])
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=PASSWORD_ENTROPY_BIP85,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    roll_data=entropy,
                    roll_count=rolls,
                    dice_sides=sides,
                ),
            )

        if self.password_type == PASSWORD_TYPE_HEX:
            num_bytes = _strength_to_length(self.strength_bits, 256)
            if num_bytes < 16 or num_bytes > 64:
                self.run_screen(
                    WarningScreen,
                    title=_("Invalid Length"),
                    status_headline=None,
                    text=_("BIP85 Hex supports 128 or 256 bits."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            entropy = bip85.derive_entropy(root, BIP85_APP_HEX, [num_bytes, index])
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=PASSWORD_ENTROPY_BIP85,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    roll_data=entropy,
                ),
            )
        elif self.password_type == PASSWORD_TYPE_BASE64:
            length = _strength_to_length(self.strength_bits, 64)
            if length < 20 or length > 86:
                self.run_screen(
                    WarningScreen,
                    title=_("Invalid Length"),
                    status_headline=None,
                    text=_("BIP85 Base64 needs 120+ bits."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            entropy = bip85.derive_entropy(root, BIP85_APP_BASE64, [length, index])
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=PASSWORD_ENTROPY_BIP85,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    roll_data=entropy,
                ),
            )
        else:
            length = _strength_to_length(self.strength_bits, 85)
            if length < 10 or length > 80:
                self.run_screen(
                    WarningScreen,
                    title=_("Invalid Length"),
                    status_headline=None,
                    text=_("BIP85 Base85 needs 64-512 bits."),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            entropy = bip85.derive_entropy(root, BIP85_APP_BASE85, [length, index])
            return Destination(
                ToolsPasswordGenerateView,
                view_args=dict(
                    password_type=self.password_type,
                    entropy_source=PASSWORD_ENTROPY_BIP85,
                    strength_bits=self.strength_bits,
                    random_options=self.random_options,
                    roll_data=entropy,
                ),
            )


def _save_password_to_seedkeeper(view: View, password: str) -> bool:
    from seedsigner.gui.screens.screen import LoadingScreenThread

    label = seed_screens.SeedAddPassphraseScreen(title=_("Password Name")).display()
    if "is_back_button" in label:
        return False

    Satochip_Connector = seedkeeper_utils.init_satochip(
        view, init_card_filter=["seedkeeper"]
    )
    if not Satochip_Connector:
        return False

    header = Satochip_Connector.make_header(
        "Password",
        "Plaintext export allowed",
        label["passphrase"],
    )
    secret_text_list = list(password.encode("utf-8"))
    secret_list = [len(secret_text_list)] + secret_text_list
    secret_dic = {"header": header, "secret_list": secret_list}

    try:
        fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
            Satochip_Connector, secret_dic
        )
    except Exception as e:
        view.run_screen(
            WarningScreen,
            title=_("Error"),
            status_headline=None,
            text=str(e),
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
        return False

    if not fits:
        view.run_screen(
            WarningScreen,
            title=_("Not Enough Space"),
            status_headline=None,
            text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
        return False

    try:
        loading = LoadingScreenThread(text=_("Saving Secret\n\n\n\n\n\n"))
        loading.start()
        Satochip_Connector.seedkeeper_import_secret(secret_dic)
        loading.stop()
        view.run_screen(
            LargeIconStatusScreen,
            title=_("Success"),
            status_headline=None,
            text=_("Password saved to Seedkeeper"),
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return True
    except UnexpectedSW12Error as e:
        loading.stop()
        if e.sw1 == 0x6A and e.sw2 == 0x84:
            err_text = _("Not enough space on Seedkeeper for password")
        else:
            err_text = format_sw_error(e.sw1, e.sw2)
        view.run_screen(
            WarningScreen,
            title=_("Error"),
            status_headline=None,
            text=err_text,
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
    except Exception as e:
        logger.info(e)
        loading.stop()
        view.run_screen(
            WarningScreen,
            title=_("Failed"),
            status_headline=None,
            text=_("Password save failed"),
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
    return False


class ToolsPasswordReviewView(View):
    def __init__(
        self,
        password: str,
        password_type: str | None = None,
        strength_bits: int | None = None,
        random_options: dict | None = None,
        entropy_source: str | None = None,
    ):
        super().__init__()
        self.password = password
        self.password_type = password_type
        self.strength_bits = strength_bits
        self.random_options = random_options or {}
        self.entropy_source = entropy_source

    def run(self):
        while True:
            edit = ButtonOption("Edit")
            next_button = ButtonOption("Next")
            button_data = [edit, next_button]
            selected_menu_num = self.run_screen(
                ToolsTextQRReviewTextScreen,
                textToEncode=self.password,
                title=_("Password"),
                button_data=button_data,
                show_back_button=True,
            )

            if selected_menu_num == RET_CODE__BACK_BUTTON:
                if _is_diceware_password_type(getattr(self, "password_type", None)):
                    return Destination(
                        ToolsPasswordWordSeparatorView,
                        view_args=dict(
                            password_type=self.password_type,
                            strength_bits=self.strength_bits,
                            random_options=self.random_options,
                            entropy_source=self.entropy_source,
                        ),
                        skip_current_view=True,
                    )
                return Destination(BackStackView)

            if button_data[selected_menu_num] == edit:
                ret_dict = ToolsTextQRTextEntryScreen(
                    textToEncode=self.password,
                    title=_("Password"),
                ).display()
                if "is_back_button" in ret_dict:
                    continue
                self.password = ret_dict["textToEncode"]
                continue

            return Destination(
                ToolsPasswordSaveView,
                view_args=dict(password=self.password),
            )


class ToolsPasswordSaveView(View):
    def __init__(self, password: str):
        super().__init__()
        self.password = password

    def run(self):
        show_qr = ButtonOption("Show as QR")
        seedkeeper = ButtonOption("Save to Seedkeeper")
        button_data = [show_qr, seedkeeper]
        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=_("Save Password"),
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=True,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == show_qr:
            from seedsigner.helpers.qr import QR
            num_modules = QR().qrsize(data=self.password)
            if num_modules <= 33:
                return Destination(
                    ToolsTextQRTranscribeModePromptView,
                    view_args=dict(text=self.password, num_modules=num_modules, return_to_home=True),
                )
            return Destination(
                ToolsTextQRFullScreenModeView,
                view_args=dict(text=self.password, return_to_home=True),
            )

        if _save_password_to_seedkeeper(self, self.password):
            return Destination(MainMenuView)
        return Destination(BackStackView)
