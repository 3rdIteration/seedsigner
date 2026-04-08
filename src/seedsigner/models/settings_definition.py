import os
from dataclasses import dataclass
from typing import Any, List

from seedsigner.helpers.l10n import mark_for_translation as _mft

import logging
logger = logging.getLogger(__name__)

try:
    from periphery import GPIO as _GPIO  # type: ignore  # noqa: F401
    USING_MOCK_GPIO = False
except ModuleNotFoundError:
    USING_MOCK_GPIO = True



class SettingsConstants:
    # Basic defaults
    OPTION__ENABLED = "E"
    OPTION__DISABLED = "D"
    OPTION__PROMPT = "P"
    OPTION__REQUIRED = "R"
    OPTIONS__ENABLED_DISABLED = [
        (OPTION__ENABLED, _mft("Enabled")),
        (OPTION__DISABLED, _mft("Disabled")),
    ]
    OPTIONS__ONLY_DISABLED = [
        (OPTION__DISABLED, _mft("Disabled")),
    ]
    OPTIONS__PROMPT_REQUIRED_DISABLED = [
        (OPTION__PROMPT, _mft("Prompt")),
        (OPTION__REQUIRED, _mft("Required")),
        (OPTION__DISABLED, _mft("Disabled")),
    ]
    OPTIONS__ENABLED_DISABLED_REQUIRED = OPTIONS__ENABLED_DISABLED +[
        (OPTION__REQUIRED, _mft("Required")),
    ]
    OPTIONS__ENABLED_DISABLED_PROMPT = OPTIONS__ENABLED_DISABLED + [
        (OPTION__PROMPT, _mft("Prompt")),
    ]
    ALL_OPTIONS = OPTIONS__ENABLED_DISABLED_PROMPT + [
        (OPTION__REQUIRED, _mft("Required")),
    ]

    # User-facing selection options
    COORDINATOR__BLUE_WALLET = "bw"
    COORDINATOR__NUNCHUK = "nun"
    COORDINATOR__SPARROW = "spa"
    COORDINATOR__SPECTER_DESKTOP = "spd"
    COORDINATOR__KEEPER = "kpr"
    ALL_COORDINATORS = [
        (COORDINATOR__BLUE_WALLET, "BlueWallet"),
        (COORDINATOR__NUNCHUK, "Nunchuk"),
        (COORDINATOR__SPARROW, "Sparrow"),
        (COORDINATOR__SPECTER_DESKTOP, "Specter Desktop"),
        (COORDINATOR__KEEPER, "Keeper"),
    ]

    # Over-specifying current and possible future locales to reduce/eliminate main repo
    # changes when adding/testing new languages.
    LOCALE__ARABIC = "ar"
    LOCALE__BENGALI = "bn"
    LOCALE__BULGARIAN = "bg"
    LOCALE__CATALAN = "ca"
    LOCALE__CHINESE_SIMPLIFIED = "zh_Hans_CN"
    LOCALE__CHINESE_TRADITIONAL = "zh_Hant_TW"
    LOCALE__CROATIAN = "hr"
    LOCALE__CZECH = "cs"
    LOCALE__DANISH = "da"
    LOCALE__DUTCH = "nl"
    LOCALE__EGYPTIAN = "ar_EG"
    LOCALE__ENGLISH = "en"
    LOCALE__ESTONIAN = "et"
    LOCALE__FINNISH = "fi"
    LOCALE__FRENCH = "fr"
    LOCALE__GAELIC = "gd"
    LOCALE__GERMAN = "de"
    LOCALE__GREEK = "el"
    LOCALE__GUJARATI = "gu"
    LOCALE__HAUSA = "ha"
    LOCALE__HEBREW = "he"
    LOCALE__HINDI = "hi"
    LOCALE__HUNGARIAN = "hu"
    LOCALE__INDONESIAN = "id"
    LOCALE__ITALIAN = "it"
    LOCALE__JAPANESE = "ja"
    LOCALE__JAVANESE = "jv"
    LOCALE__KOREAN = "ko"
    LOCALE__LAO = "lo"
    LOCALE__LATVIAN = "lv"
    LOCALE__LITHUANIAN = "lt"
    LOCALE__MALAY = "ms"
    LOCALE__MALTESE = "mt"
    LOCALE__MARATHI = "mr"
    LOCALE__NORWEGIAN = "no"
    LOCALE__PERSIAN = "fa"
    LOCALE__POLISH = "pl"
    LOCALE__PORTUGUESE_BR = "pt_BR"
    LOCALE__PORTUGUESE_PT = "pt_PT"
    LOCALE__PUNJABI = "pa"
    LOCALE__ROMANIAN = "ro"
    LOCALE__RUSSIAN = "ru"
    LOCALE__SLOVAK = "sk"
    LOCALE__SLOVENIAN = "sl"
    LOCALE__SPANISH = "es"
    LOCALE__SWEDISH = "sv"
    LOCALE__TAGALOG = "tl"
    LOCALE__TAMIL = "ta"
    LOCALE__TELUGU = "te"
    LOCALE__THAI = "th"
    LOCALE__TURKISH = "tr"
    LOCALE__UKRANIAN = "uk"
    LOCALE__URDU = "ur"
    LOCALE__VIETNAMESE = "vi"

    # Do not wrap for translation. Present each language in its native form (i.e. either
    # using its native chars or how they write it in Latin chars; e.g. Spanish is listed
    # and sorted as "Español").
    # Sort fully-vetted languages first, then beta languages, then the "placeholders /
    # coming soon" languages.
    # Sort by native form when written in Latin chars, otherwise sort by English name.
    # Include English name in parens for languages that don't use Latin chars.
    # Include region/country in parens for specific dialects (e.g. "Português (Brasil)").
    # Note that dicts preserve insertion order as of Python 3.7.
    ALL_LOCALES = {
        # --------- Fully supported languages -------------------------------------------
        LOCALE__CATALAN: "Català",
        LOCALE__GERMAN: "Deutsch",
        LOCALE__ENGLISH: "English",
        LOCALE__SPANISH: "Español",
        LOCALE__FRENCH: "Français",
        LOCALE__DUTCH: "Nederlands",

        # --------- Beta languages ------------------------------------------------------
        LOCALE__CHINESE_SIMPLIFIED: "(beta) 简体中文 (Chinese Simplified)",
        LOCALE__JAPANESE: "(beta) 日本語 (Japanese)",
        LOCALE__KOREAN: "(beta) 한국어 (Korean)",

        # --------- Placeholders / Coming soon ------------------------------------------
        # Commented out options require explicit additional font support.
        # -------------------------------------------------------------------------------
        # LOCALE__ARABIC: "العربية (Arabic)",
        # LOCALE__BENGALI: "বাংলা (Bengali)",
        LOCALE__BULGARIAN: "български (Bulgarian)",  # OpenSans includes cyrillic chars
        LOCALE__CZECH: "čeština",
        # LOCALE__CHINESE_TRADITIONAL: "繁體中文 (Chinese Traditional)",
        LOCALE__DANISH: "Dansk",
        LOCALE__ESTONIAN: "Eesti",
        # LOCALE__EGYPTIAN: "مصرى (Egyptian)",
        LOCALE__GAELIC: "Gaeilge",
        LOCALE__GREEK: "Ελληνικά (Greek)",  # OpenSans includes Greek chars
        # LOCALE__GUJARATI: "ગુજરાતી (Gujarati)",
        LOCALE__HAUSA: "Hausa",
        # LOCALE__HEBREW: "עברית (Hebrew)",
        # LOCALE__HINDI: "हिन्दी (Hindi)",
        LOCALE__CROATIAN: "Hrvatski",
        LOCALE__ITALIAN: "Italiano",
        LOCALE__INDONESIAN: "Indonesia",
        LOCALE__JAVANESE: "Jawa (Javanese)",
        # LOCALE__LAO: "ລາວ (Lao)",
        LOCALE__LATVIAN: "Latviešu",
        LOCALE__LITHUANIAN: "Lietuvių",
        LOCALE__HUNGARIAN: "Magyar",
        LOCALE__MALAY: "Melayu",
        LOCALE__MALTESE: "Malti",
        # LOCALE__MARATHI: "मराठी (Marathi)",
        LOCALE__NORWEGIAN: "Norsk",
        # LOCALE__PERSIAN: "فارسی (Persian)",
        LOCALE__POLISH: "Polski",
        LOCALE__PORTUGUESE_BR: "Português (Brasil)",
        LOCALE__PORTUGUESE_PT: "Português (Portugal)",
        # LOCALE__PUNJABI: "ਪੰਜਾਬੀ (Punjabi)",
        LOCALE__ROMANIAN: "Română",
        LOCALE__RUSSIAN: "русский (Russian)",  # OpenSans includes cyrillic chars
        LOCALE__SLOVAK: "Slovenčina",
        LOCALE__SLOVENIAN: "Slovenščina",
        LOCALE__FINNISH: "Suomi",
        LOCALE__SWEDISH: "Svenska",
        LOCALE__TAGALOG: "Tagalog",
        # LOCALE__TAMIL: "தமிழ் (Tamil)",
        # LOCALE__TELUGU: "తెలుగు (Telugu)",
        # LOCALE__THAI: "ไทย (Thai)",
        LOCALE__TURKISH: "Türkçe",
        LOCALE__UKRANIAN: "українська (Ukranian)",   # OpenSans includes cyrillic chars
        # LOCALE__URDU: "اردو (Urdu)",
        LOCALE__VIETNAMESE: "Tiếng Việt (Vietnamese)",
    }

    @classmethod
    def get_detected_languages(cls) -> list[tuple[str, str]]:
        """
        Return a list of tuples of language codes and their native names.

        Scans the filesystem to autodiscover which language codes are onboard.
        """
        # Will normally be the launch dir (where main.py is located)...
        cwd = os.getcwd()

        # ...except when running the tests which happens one dir higher
        if "src" not in cwd:
            cwd = os.path.join(cwd, "src")

        # Pre-load English since there's no "en" entry in the translations folder; also
        # it should always appear first in the list anyway.
        detected_languages = [(cls.LOCALE__ENGLISH, cls.ALL_LOCALES[cls.LOCALE__ENGLISH])]

        locales_present = set()
        for root, dirs, files in os.walk(os.path.join(cwd, "seedsigner", "resources", "seedsigner-translations", "l10n")):
            for file in [f for f in files if f.endswith(".mo")]:
                # `root` will be [...]seedsigner/resources/seedsigner-translations/l10n/pt_BR/LC_MESSAGES
                locales_present.add(root.split(f"l10n{ os.sep }")[1].split(os.sep)[0])

        for locale in cls.ALL_LOCALES.keys():
            if locale in locales_present:
                detected_languages.append((locale, cls.ALL_LOCALES[locale]))

        return detected_languages


    BTC_DENOMINATION__BTC = "btc"
    BTC_DENOMINATION__SATS = "sats"
    BTC_DENOMINATION__THRESHOLD = "thr"
    BTC_DENOMINATION__BTCSATSHYBRID = "hyb"
    ALL_BTC_DENOMINATIONS = [
        (BTC_DENOMINATION__BTC, _mft("BTC")),
        (BTC_DENOMINATION__SATS, _mft("sats")),
        (BTC_DENOMINATION__THRESHOLD, _mft("Threshold at 0.01")),
        (BTC_DENOMINATION__BTCSATSHYBRID, _mft("BTC | sats hybrid")),
    ]

    # Camera rotation constants
    CAMERA_ROTATION__0 = 0
    CAMERA_ROTATION__90 = 90
    CAMERA_ROTATION__180 = 180
    CAMERA_ROTATION__270 = 270
    ALL_CAMERA_ROTATIONS = [
        (CAMERA_ROTATION__0, _mft("0°")),
        (CAMERA_ROTATION__90, _mft("90°")),
        (CAMERA_ROTATION__180, _mft("180°")),
        (CAMERA_ROTATION__270, _mft("270°")),
    ]

    CAMERA_DEVICE__0 = 0
    CAMERA_DEVICE__1 = 1
    CAMERA_DEVICE__2 = 2
    CAMERA_DEVICE__3 = 3
    ALL_CAMERA_DEVICES = [
        (CAMERA_DEVICE__0, _mft("Camera 0")),
        (CAMERA_DEVICE__1, _mft("Camera 1")),
        (CAMERA_DEVICE__2, _mft("Camera 2")),
        (CAMERA_DEVICE__3, _mft("Camera 3")),
    ]

    # Hardware config settings
    HARDWARE__RPI_40 = "RPI_40"
    HARDWARE__RPI_26 = "RPI_26"
    HARDWARE__LUCKFOX_22 = "FOX_22"
    HARDWARE__LUCKFOX_40 = "FOX_40"
    HARDWARE__LUCKFOX_PI = "FOX_PI"


    # QR code constants
    DENSITY__LOW = "L"
    DENSITY__MEDIUM = "M"
    DENSITY__HIGH = "H"
    # TRANSLATOR_NOTE: QR code density option: Low, Medium, High
    density_low = _mft("Low")
    # TRANSLATOR_NOTE: QR code density option: Low, Medium, High
    density_medium = _mft("Medium")
    # TRANSLATOR_NOTE: QR code density option: Low, Medium, High
    density_high = _mft("High")
    ALL_DENSITIES = [
        (DENSITY__LOW, density_low),
        (DENSITY__MEDIUM, density_medium),
        (DENSITY__HIGH, density_high),
    ]

    # Seed-related constants
    MAINNET = "M"
    TESTNET = "T"
    REGTEST = "R"
    ALL_NETWORKS = [
        (MAINNET, _mft("Mainnet")),
        (TESTNET, _mft("Testnet")),
        (REGTEST, _mft("Regtest"))
    ]

    #Smartcard Related Constants
    SMARTCARD_INTERFACE_USB = "usb"
    SMARTCARD_INTERFACE_PN532 = "pn532"
    SMARTCARD_INTERFACE_SEC1210 = "sec1210"
    SMARTCARD_INTERFACE_PHOENIX = "phoenix-usb"
    ALL_SMARTCARD_INTERFACES = [
        (SMARTCARD_INTERFACE_USB, "USB PC/SC Reader"),
        (SMARTCARD_INTERFACE_PN532, "PN532 via GPIO"),
        (SMARTCARD_INTERFACE_SEC1210, "SEC1210 via GPIO"),
        (SMARTCARD_INTERFACE_PHOENIX, "Phoenix via USB")
    ]

    # Smartcard PIN attempt limits
    SCARD_PIN_ATTEMPTS_MIN = 2
    SCARD_PIN_ATTEMPTS_MAX = 10
    ALL_SCARD_PIN_ATTEMPTS = [(i, str(i)) for i in range(SCARD_PIN_ATTEMPTS_MIN, SCARD_PIN_ATTEMPTS_MAX + 1)]
    DEFAULT_SCARD_PIN_ATTEMPTS = 5

    # Satochip signing behavior
    SATOCHIP_TIMEOUT_MIN = 0.25
    SATOCHIP_TIMEOUT_MAX = 1

    ALL_SATOCHIP_TIMEOUTS = [
        (i, f"{i:g}s")
        for i in [x * 0.25 for x in range(int(SATOCHIP_TIMEOUT_MIN / 0.25), int(SATOCHIP_TIMEOUT_MAX / 0.25) + 1)]
    ]
    DEFAULT_SATOCHIP_TIMEOUT = 0.5

    SATOCHIP_MSG_TIMEOUT_MIN = 0.5
    SATOCHIP_MSG_TIMEOUT_MAX = 2

    ALL_SATOCHIP_MSG_TIMEOUTS = [
        (i / 4, f"{i / 4:g}s")
        for i in range(int(SATOCHIP_MSG_TIMEOUT_MIN * 4), int(SATOCHIP_MSG_TIMEOUT_MAX * 4) + 1)
    ]
    DEFAULT_SATOCHIP_MSG_TIMEOUT = 1.25

    SATOCHIP_PRE_DUMMY_MAX_MIN = 0
    SATOCHIP_PRE_DUMMY_MAX_MAX = 12
    ALL_SATOCHIP_PRE_DUMMY_MAX = [
        (i, str(i))
        for i in range(SATOCHIP_PRE_DUMMY_MAX_MIN, SATOCHIP_PRE_DUMMY_MAX_MAX + 1)
    ]
    DEFAULT_SATOCHIP_PRE_DUMMY_MAX = 6

    SATOCHIP_POST_DUMMY_MAX_MIN = 0
    SATOCHIP_POST_DUMMY_MAX_MAX = 12
    ALL_SATOCHIP_POST_DUMMY_MAX = [
        (i, str(i))
        for i in range(
            SATOCHIP_POST_DUMMY_MAX_MIN, SATOCHIP_POST_DUMMY_MAX_MAX + 1
        )
    ]
    DEFAULT_SATOCHIP_POST_DUMMY_MAX = 6

    SATOCHIP_IN_TX_DUMMY_MAX_MIN = 1
    SATOCHIP_IN_TX_DUMMY_MAX_MAX = 5
    ALL_SATOCHIP_IN_TX_DUMMY_MAX = [
        (i, str(i))
        for i in range(SATOCHIP_IN_TX_DUMMY_MAX_MIN, SATOCHIP_IN_TX_DUMMY_MAX_MAX + 1)
    ]
    DEFAULT_SATOCHIP_IN_TX_DUMMY_MAX = 3

    SATOCHIP_DUMMY_PROB_MIN = 0
    SATOCHIP_DUMMY_PROB_MAX = 100
    ALL_SATOCHIP_DUMMY_PROB = [
        (i, f"{i}%") for i in range(SATOCHIP_DUMMY_PROB_MIN, SATOCHIP_DUMMY_PROB_MAX + 1, 5)
    ]
    DEFAULT_SATOCHIP_DUMMY_PROB = 50

    @classmethod
    def map_network_to_embit(cls, network) -> str:
        # Note these are `embit` constants; do not wrap for translation
        if network == SettingsConstants.MAINNET:
            return "main"
        elif network == SettingsConstants.TESTNET:
            return "test"
        if network == SettingsConstants.REGTEST:
            return "regtest"
    
    PERSISTENT_SETTINGS__SD_INSERTED__HELP_TEXT = _mft("Store Settings on SD card")
    PERSISTENT_SETTINGS__SD_REMOVED__HELP_TEXT = _mft("Insert SD card to enable")

    # Wipe timer constants (minutes)
    WIPE_TIMER__DISABLED = 0
    WIPE_TIMER__FIVE_MINUTES = 5
    WIPE_TIMER__TEN_MINUTES = 10
    WIPE_TIMER__FIFTEEN_MINUTES = 15
    WIPE_TIMER__THIRTY_MINUTES = 30
    ALL_WIPE_TIMERS = [
        (WIPE_TIMER__DISABLED, _mft("Disabled")),
        (WIPE_TIMER__FIVE_MINUTES, _mft("5 minutes")),
        (WIPE_TIMER__TEN_MINUTES, _mft("10 minutes")),
        (WIPE_TIMER__FIFTEEN_MINUTES, _mft("15 minutes")),
        (WIPE_TIMER__THIRTY_MINUTES, _mft("30 minutes")),
    ]

    SINGLE_SIG = "ss"
    MULTISIG = "ms"
    ALL_SIG_TYPES = [
        (SINGLE_SIG, _mft("Single Sig")),
        (MULTISIG, _mft("Multisig")),
    ]

    LEGACY_P2PKH = "leg"
    NATIVE_SEGWIT = "nat"
    NESTED_SEGWIT = "nes"
    TAPROOT = "tr"
    CUSTOM_DERIVATION = "cus"
    ALL_SCRIPT_TYPES = [
        (NATIVE_SEGWIT, _mft("Native Segwit")),
        (NESTED_SEGWIT, _mft("Nested Segwit")),
        (LEGACY_P2PKH, _mft("Legacy")),
        (TAPROOT, _mft("Taproot")),
        (CUSTOM_DERIVATION, _mft("Custom Derivation")),
    ]

    WORDLIST_LANGUAGE__ENGLISH = "en"
    WORDLIST_LANGUAGE__CHINESE_SIMPLIFIED = "zh_Hans_CN"
    WORDLIST_LANGUAGE__CHINESE_TRADITIONAL = "zh_Hant_TW"
    WORDLIST_LANGUAGE__FRENCH = "fr"
    WORDLIST_LANGUAGE__ITALIAN = "it"
    WORDLIST_LANGUAGE__JAPANESE = "jp"
    WORDLIST_LANGUAGE__KOREAN = "kr"
    WORDLIST_LANGUAGE__PORTUGUESE = "pt"
    ALL_WORDLIST_LANGUAGES = [
        (WORDLIST_LANGUAGE__ENGLISH, "English"),
        # (WORDLIST_LANGUAGE__CHINESE_SIMPLIFIED, "简体中文"),
        # (WORDLIST_LANGUAGE__CHINESE_TRADITIONAL, "繁體中文"),
        # (WORDLIST_LANGUAGE__FRENCH, "Français"),
        # (WORDLIST_LANGUAGE__ITALIAN, "Italiano"),
        # (WORDLIST_LANGUAGE__JAPANESE, "日本語"),
        # (WORDLIST_LANGUAGE__KOREAN, "한국어"),
        # (WORDLIST_LANGUAGE__PORTUGUESE, "Português"),
    ]

    # Individual SettingsEntry attr_names
    # Note: attr_names are internal constants; do not wrap for translation
    SETTING__LOCALE = "locale"
    SETTING__WORDLIST_LANGUAGE = "wordlist_language"
    SETTING__PERSISTENT_SETTINGS = "persistent_settings"
    SETTING__COORDINATORS = "coordinators"
    SETTING__BTC_DENOMINATION = "denomination"
    SETTING__SMARTCARD_INTERFACES = "smartcard_interfaces"
    SETTING__CACHE_SCARD_PIN = "cache_scard_pin"
    SETTING__SCARD_PIN_ATTEMPTS = "scard_pin_attempts"
    SETTING__SMARTCARD_SUPPORT = "smartcard_support"
    SETTING__WIPE_TIMER = "wipe_timer"

    SETTING__DISPLAY_CONFIGURATION = "display_config"
    SETTING__DISPLAY_COLOR_INVERTED = "color_inverted"

    SETTING__NETWORK = "network"
    SETTING__QR_DENSITY = "qr_density"
    SETTING__XPUB_EXPORT = "xpub_export"
    SETTING__SIG_TYPES = "sig_types"
    SETTING__SCRIPT_TYPES = "script_types"
    SETTING__ACCOUNT_PROMPT = "account_prompt"
    SETTING__SEED_WORD_LENGTHS = "seed_word_lengths"
    SETTING__XPUB_DETAILS = "xpub_details"
    SETTING__PASSPHRASE = "passphrase"
    SETTING__CAMERA_ROTATION = "camera_rotation"
    SETTING__CAMERA_DEVICE = "camera_device"
    SETTING__COMPACT_SEEDQR = "compact_seedqr"
    SETTING__BIP85_CHILD_SEEDS = "bip85_child_seeds"
    SETTING__SLIP39_SEEDS = "slip39_seeds"
    SETTING__AEZEED_SEEDS = "aezeed_seeds"
    SETTING__SLIP39_EXTENDABLE = "slip39_extendable"
    SETTING__ELECTRUM_SEEDS = "electrum_seeds"
    SETTING__BITBOX_BACKUP = "bitbox_backup"
    SETTING__PASSPORT_BACKUP = "passport_backup"
    SETTING__TAPSIGNER_BACKUP = "tapsigner_backup"
    SETTING__MESSAGE_SIGNING = "message_signing"
    SETTING__PRIVACY_WARNINGS = "privacy_warnings"
    SETTING__DIRE_WARNINGS = "dire_warnings"
    SETTING__QR_BRIGHTNESS_TIPS = "qr_brightness_tips"
    SETTING__PARTNER_LOGOS = "partner_logos"
    SETTING__PLAINTEXTQR = "plaintextqr"
    SETTING__ENCRYPTED_QR = "encrypted_qr"
    SETTING__AMBIGUOUS_QR = "ambiguous_qr_preference"
    SETTING__ENCRYPTION_MODE = "version"
    SETTING__ENCRYPTION_ITER = "pbkdf2_iterations"
    SETTING__WIF_KEYS = "wif_keys"
    SETTING__BIP38_KEYS = "bip38_keys"
    SETTING__GPG_KEY_TYPES = "gpg_key_types"

    SETTING__SATOCHIP_SIGN_TIMEOUT = "satochip_sign_timeout"
    SETTING__SATOCHIP_MSG_SIGN_TIMEOUT = "satochip_msg_sign_timeout"
    SETTING__SATOCHIP_MAX_PRE_DUMMIES = "satochip_max_pre_dummies"
    SETTING__SATOCHIP_MAX_POST_DUMMIES = "satochip_max_post_dummies"
    SETTING__SATOCHIP_MAX_IN_TX_DUMMIES = "satochip_max_in_tx_dummies"
    SETTING__SATOCHIP_DUMMY_PROBABILITY = "satochip_dummy_probability"

    SETTING__DEBUG = "debug"


    # Hardware config settings
    DISPLAY_CONFIGURATION__ST7789__240x240 = "st7789_240x240"  # default; original Waveshare 1.3" display hat
    DISPLAY_CONFIGURATION__ST7789__320x240 = "st7789_320x240"    # natively portrait dimensions; we apply a 90° rotation
    DISPLAY_CONFIGURATION__ILI9341__320x240 = "ili9341_320x240"  # natively portrait dimensions; we apply a 90° rotation
    DISPLAY_CONFIGURATION__ILI9486__480x320 = "ili9486_480x320"  # natively portrait dimensions; we apply a 90° rotation
    DISPLAY_CONFIGURATION__DESKTOP__240x240 = "desktop_240x240"  # pygame-based desktop simulation
    DISPLAY_CONFIGURATION__DESKTOP__320x240 = "desktop_320x240"
    if USING_MOCK_GPIO:
        ALL_DISPLAY_CONFIGURATIONS = [
            (DISPLAY_CONFIGURATION__ST7789__240x240, "st7789 240x240"),
            (DISPLAY_CONFIGURATION__ST7789__320x240, "st7789 320x240"),
            (DISPLAY_CONFIGURATION__ILI9341__320x240, "ili9341 320x240 (beta)"),
            (DISPLAY_CONFIGURATION__DESKTOP__240x240, "desktop 240x240"),
            (DISPLAY_CONFIGURATION__DESKTOP__320x240, "desktop 320x240"),
            # (DISPLAY_CONFIGURATION__ILI9486__320x480, "ili9486 480x320"),  # TODO: Enable when ili9486 driver performance is improved
        ]
    else:
        ALL_DISPLAY_CONFIGURATIONS = [
            (DISPLAY_CONFIGURATION__ST7789__240x240, "st7789 240x240"),
            (DISPLAY_CONFIGURATION__ST7789__320x240, "st7789 320x240"),
            (DISPLAY_CONFIGURATION__ILI9341__320x240, "ili9341 320x240 (beta)"),
            # (DISPLAY_CONFIGURATION__ILI9486__320x480, "ili9486 480x320"),  # TODO: Enable when ili9486 driver performance is improved
        ]


    # Hidden settings
    SETTING__QR_BRIGHTNESS = "qr_background_color"


    # Structural constants
    # TODO: Not using these for display purposes yet (ever?)
    CATEGORY__SYSTEM = "system"
    CATEGORY__DISPLAY = "display"
    CATEGORY__WALLET = "wallet"
    CATEGORY__FEATURES = "features"

    VISIBILITY__GENERAL = "general"
    VISIBILITY__ADVANCED = "advanced"
    VISIBILITY__HARDWARE = "hardware"
    VISIBILITY__DEVELOPER = "developer"
    VISIBILITY__HIDDEN = "hidden"   # For data-only (e.g. custom_derivation)

    # TODO: Is there really a difference between ENABLED and PROMPT?
    TYPE__ENABLED_DISABLED = "enabled_disabled"
    TYPE__ENABLED_DISABLED_PROMPT = "enabled_disabled_prompt"
    TYPE__ENABLED_DISABLED_PROMPT_REQUIRED = "enabled_disabled_prompt_required"
    TYPE__SELECT_1 = "select_1"
    TYPE__MULTISELECT = "multiselect"
    TYPE__FREE_ENTRY = "free_entry"

    ALL_ENABLED_DISABLED_TYPES = [
        TYPE__ENABLED_DISABLED,
        TYPE__ENABLED_DISABLED_PROMPT,
        TYPE__ENABLED_DISABLED_PROMPT_REQUIRED,
    ]

    # Electrum seed constants
    ELECTRUM_SEED_STANDARD = "01"
    ELECTRUM_SEED_SEGWIT = "100"
    ELECTRUM_SEED_2FA = "101"
    ELECTRUM_PBKDF2_ROUNDS=2048

    # Label strings
    LABEL__BIP39_PASSPHRASE = _mft("BIP-39 Passphrase")
    LABEL__AEZEED_PASSPHRASE = _mft("Aezeed Passphrase")
    # TRANSLATOR_NOTE: Terminology used by Electrum seeds; equivalent to bip39 passphrase
    custom_extension = _mft("Custom Extension")
    LABEL__CUSTOM_EXTENSION = custom_extension

    # Encryption constants
    ENCRYPTION_MODE_ECB   = "AES-ECB"
    ENCRYPTION_MODE_CBC   = "AES-CBC"
    ENCRYPTION_MODE_CTR   = "AES-CTR"
    ENCRYPTION_MODE_GCM   = "AES-GCM"
    ENCRYPTION_MODE_ECBV1 = "AES-ECB v1"
    ENCRYPTION_MODE_CBCV1 = "AES-CBC v1"
    ENCRYPTION_MODE       = ENCRYPTION_MODE_GCM
    ENCRYPTION_ITERATIONS = 10
    AMBIGUOUS_QR_PROMPT  = "prompt"
    AMBIGUOUS_QR_COMPACT = "compactseedqr"
    AMBIGUOUS_QR_ENCRYPTED = "encryptedseedqr"
    ALL_AMBIGUOUS_QR_OPTIONS = [
        (AMBIGUOUS_QR_COMPACT, _mft("Prefer CompactSeedQR")),
        (AMBIGUOUS_QR_ENCRYPTED, _mft("Prefer EncryptedQR")),
        (AMBIGUOUS_QR_PROMPT, _mft("Ask each time")),
    ]
    ALL_ENCRYPTION_MODES = [
        ENCRYPTION_MODE_ECB,
        ENCRYPTION_MODE_CBC,
        ENCRYPTION_MODE_CTR,
        ENCRYPTION_MODE_GCM,
    ]

    ALL_SEED_WORD_LENGTHS = [
        (12, "12 words"),
        (15, "15 words"),
        (18, "18 words"),
        (21, "21 words"),
        (24, "24 words"),
    ]

    # GPG key type constants
    GPG_KEY_TYPE__ED25519 = "ed25519"
    GPG_KEY_TYPE__P256 = "p256"
    GPG_KEY_TYPE__P384 = "p384"
    GPG_KEY_TYPE__P521 = "p521"
    GPG_KEY_TYPE__BRAINPOOL_P256 = "brainpoolp256r1"
    GPG_KEY_TYPE__BRAINPOOL_P384 = "brainpoolp384r1"
    GPG_KEY_TYPE__BRAINPOOL_P512 = "brainpoolp512r1"
    GPG_KEY_TYPE__RSA2048 = "rsa2048"
    GPG_KEY_TYPE__RSA3072 = "rsa3072"
    GPG_KEY_TYPE__RSA4096 = "rsa4096"
    GPG_KEY_TYPE__SECP256K1 = "secp256k1"

    ALL_GPG_KEY_TYPES = [
        (GPG_KEY_TYPE__ED25519, "ECC Ed25519"),
        (GPG_KEY_TYPE__P256, "ECC NIST P-256"),
        (GPG_KEY_TYPE__P384, "ECC NIST P-384"),
        (GPG_KEY_TYPE__P521, "ECC NIST P-521"),
        (GPG_KEY_TYPE__BRAINPOOL_P256, "ECC Brainpool P-256"),
        (GPG_KEY_TYPE__BRAINPOOL_P384, "ECC Brainpool P-384"),
        (GPG_KEY_TYPE__BRAINPOOL_P512, "ECC Brainpool P-512"),
        (GPG_KEY_TYPE__RSA2048, "RSA 2048"),
        (GPG_KEY_TYPE__RSA3072, "RSA 3072"),
        (GPG_KEY_TYPE__RSA4096, "RSA 4096"),
        (GPG_KEY_TYPE__SECP256K1, "ECC secp256k1"),
    ]

    # Default GPG key types match the "Generate New" menu
    DEFAULT_GPG_KEY_TYPES = [
        GPG_KEY_TYPE__ED25519,
        GPG_KEY_TYPE__P256,
        GPG_KEY_TYPE__BRAINPOOL_P256,
        GPG_KEY_TYPE__RSA2048,
        GPG_KEY_TYPE__RSA3072,
        GPG_KEY_TYPE__RSA4096,
        GPG_KEY_TYPE__SECP256K1,
    ]


@dataclass
class SettingsEntry:
    """
        Defines all the parameters for a single settings entry.

        * category: Mostly for organizational purposes when displaying options in the
            SettingsQR UI. Potentially an additional sub-level breakout in the menus
            on the device itself, too.
        
        * selection_options: May be specified as a List(Any) or List(tuple(Any, str)).
            The tuple form is to provide a human-readable display_name. Probably all
            entries should shift to using the tuple form.
    """
    # TODO: Handle multi-language `display_name` and `help_text`
    category: str
    attr_name: str
    display_name: str
    abbreviated_name: str = None
    visibility: str = SettingsConstants.VISIBILITY__GENERAL
    type: str = SettingsConstants.TYPE__ENABLED_DISABLED
    help_text: str = None
    selection_options: list[tuple[str | int], str] = None
    default_value: Any = None

    def __post_init__(self):
        if self.type == SettingsConstants.TYPE__ENABLED_DISABLED:
            self.selection_options = SettingsConstants.OPTIONS__ENABLED_DISABLED

        elif self.type == SettingsConstants.TYPE__ENABLED_DISABLED_PROMPT:
            self.selection_options = SettingsConstants.OPTIONS__ENABLED_DISABLED_PROMPT

        elif self.type == SettingsConstants.TYPE__ENABLED_DISABLED_PROMPT_REQUIRED:
            self.selection_options = SettingsConstants.ALL_OPTIONS

        # Account for List[tuple] and tuple formats as default_value        
        if type(self.default_value) == list and type(self.default_value[0]) == tuple:
            self.default_value = [v[0] for v in self.default_value]
        elif type(self.default_value) == tuple:
            self.default_value = self.default_value[0]


    @property
    def selection_options_display_names(self) -> List[str]:
        if type(self.selection_options[0]) == tuple:
            return [v[1] for v in self.selection_options]
        else:
            # Always return a copy so the original can't be altered
            return list(self.selection_options)


    def get_selection_option_value(self, i: int):
        """ Returns the value of the selection option at index `i` """
        value = self.selection_options[i]
        if type(value) == tuple:
            value = value[0]
        return value

    
    def get_selection_option_display_name_by_value(self, value) -> str:
        for option in self.selection_options:
            if type(option) == tuple:
                option_value = option[0]
                display_name = option[1]
            else:
                option_value = option
                display_name = option
            if option_value == value:
                return _mft(display_name)


    def get_selection_option_value_by_display_name(self, display_name: str):
        for option in self.selection_options:
            if type(option) == tuple:
                option_value = option[0]
                option_display_name = option[1]
            else:
                option_value = option
                option_display_name = option
            if option_display_name == display_name:
                return option_value


    def to_dict(self) -> dict:
        if self.selection_options:
            selection_options = []
            for option in self.selection_options:
                if type(option) == tuple:
                    value = option[0]
                    display_name = option[1]
                else:
                    display_name = option
                    value = option
                selection_options.append({
                    "display_name": display_name,
                    "value": value
                })
        else:
            selection_options = None

        return {
            "category": self.category,
            "attr_name": self.attr_name,
            "abbreviated_name": self.abbreviated_name,
            "display_name": self.display_name,
            "visibility": self.visibility,
            "type": self.type,
            "help_text": self.help_text,
            "selection_options": selection_options,
            "default_value": self.default_value,
        }



class SettingsDefinition:
    """
        Master list of all settings, their possible options, their defaults, on-device
        display strings, and enriched SettingsQR UI options.

        Used to auto-build the Settings UI menuing with no repetitive boilerplate code.

        Defines the on-disk persistent storage structure and can read that format back
        and validate the values.

        Used to generate a master json file that documents all these params which can
        then be read in by the SettingsQR UI to auto-generate the necessary html inputs.
    """
    # Increment if there are any breaking changes; write migrations to bridge from
    # incompatible prior versions.
    version: int = 1

    settings_entries: List[SettingsEntry] = [
        # General options

        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                      attr_name=SettingsConstants.SETTING__LOCALE,
                      abbreviated_name="lang",
                      display_name=_mft("Language"),
                      type=SettingsConstants.TYPE__SELECT_1,
                      selection_options=SettingsConstants.get_detected_languages(),
                      default_value=SettingsConstants.LOCALE__ENGLISH),

        # TODO: Support other bip-39 wordlist languages! Until then, type == HIDDEN
        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                      attr_name=SettingsConstants.SETTING__WORDLIST_LANGUAGE,
                      abbreviated_name="wordlist_lang",
                      display_name=_mft("Mnemonic language"),
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__HIDDEN,
                      selection_options=SettingsConstants.ALL_WORDLIST_LANGUAGES,
                      default_value=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH),

        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                      attr_name=SettingsConstants.SETTING__PERSISTENT_SETTINGS,
                      abbreviated_name="persistent",
                      display_name=_mft("Persistent settings"),
                      help_text=SettingsConstants.PERSISTENT_SETTINGS__SD_INSERTED__HELP_TEXT,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__WALLET,
                      attr_name=SettingsConstants.SETTING__COORDINATORS,
                      abbreviated_name="coords",
                      display_name=_mft("Coordinator software"),
                      type=SettingsConstants.TYPE__MULTISELECT,
                      selection_options=SettingsConstants.ALL_COORDINATORS,
                      default_value=[
                          SettingsConstants.COORDINATOR__BLUE_WALLET,
                          SettingsConstants.COORDINATOR__NUNCHUK,
                          SettingsConstants.COORDINATOR__SPARROW,
                          SettingsConstants.COORDINATOR__SPECTER_DESKTOP,
                      ]),

        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                      attr_name=SettingsConstants.SETTING__BTC_DENOMINATION,
                      abbreviated_name="denom",
                      display_name=_mft("Denomination display"),
                      type=SettingsConstants.TYPE__SELECT_1,
                      selection_options=SettingsConstants.ALL_BTC_DENOMINATIONS,
                      default_value=SettingsConstants.BTC_DENOMINATION__THRESHOLD),

        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                    attr_name=SettingsConstants.SETTING__SMARTCARD_INTERFACES,
                    abbreviated_name="screaders",
                    display_name="Smartcard Interfaces",
                    type=SettingsConstants.TYPE__MULTISELECT,
                    visibility=SettingsConstants.VISIBILITY__HARDWARE,
                    selection_options=SettingsConstants.ALL_SMARTCARD_INTERFACES,
                    default_value=[
                        opt[0]
                        for opt in SettingsConstants.ALL_SMARTCARD_INTERFACES
                        if opt[0] != SettingsConstants.SMARTCARD_INTERFACE_PHOENIX
                    ]),

        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                    attr_name=SettingsConstants.SETTING__CACHE_SCARD_PIN,
                    abbreviated_name="cachepin",
                    display_name="Cache Smartcard Pin",
                    type=SettingsConstants.TYPE__SELECT_1,
                    selection_options=SettingsConstants.OPTIONS__ENABLED_DISABLED,
                    default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                    attr_name=SettingsConstants.SETTING__SCARD_PIN_ATTEMPTS,
                    abbreviated_name="pintries",
                    display_name=_mft("Smartcard PIN Attempts"),
                    type=SettingsConstants.TYPE__SELECT_1,
                    selection_options=SettingsConstants.ALL_SCARD_PIN_ATTEMPTS,
                    default_value=SettingsConstants.DEFAULT_SCARD_PIN_ATTEMPTS),

        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                    attr_name=SettingsConstants.SETTING__WIPE_TIMER,
                    abbreviated_name="wipe",
                    display_name=_mft("Wipe Timer"),
                    type=SettingsConstants.TYPE__SELECT_1,
                    selection_options=SettingsConstants.ALL_WIPE_TIMERS,
                    default_value=SettingsConstants.WIPE_TIMER__DISABLED),

        # Advanced options
        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__NETWORK,
                      display_name=_mft("Bitcoin network"),
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_NETWORKS,
                      default_value=SettingsConstants.MAINNET),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__QR_DENSITY,
                      display_name=_mft("QR code density"),
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_DENSITIES,
                      default_value=SettingsConstants.DENSITY__MEDIUM),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__XPUB_EXPORT,
                      display_name=_mft("Xpub export"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SIG_TYPES,
                      abbreviated_name="sigs",
                      display_name=_mft("Sig types"),
                      type=SettingsConstants.TYPE__MULTISELECT,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_SIG_TYPES,
                      default_value=SettingsConstants.ALL_SIG_TYPES),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SCRIPT_TYPES,
                      abbreviated_name="scripts",
                      display_name=_mft("Script types"),
                      type=SettingsConstants.TYPE__MULTISELECT,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_SCRIPT_TYPES,
                      default_value=[SettingsConstants.NATIVE_SEGWIT, SettingsConstants.NESTED_SEGWIT, SettingsConstants.TAPROOT]),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SEED_WORD_LENGTHS,
                      abbreviated_name="seedlen",
                      display_name=_mft("Seed word lengths"),
                      type=SettingsConstants.TYPE__MULTISELECT,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_SEED_WORD_LENGTHS,
                      default_value=[12, 24]),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__XPUB_DETAILS,
                      display_name=_mft("Show xpub details"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__ACCOUNT_PROMPT,
                      display_name=_mft("BIP32 account prompt"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__PASSPHRASE,
                      display_name=_mft("BIP-39 passphrase"),
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.OPTIONS__ENABLED_DISABLED_REQUIRED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__CAMERA_ROTATION,
                      abbreviated_name="camera",
                      display_name=_mft("Camera rotation"),
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_CAMERA_ROTATIONS,
                      default_value=SettingsConstants.CAMERA_ROTATION__180),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__COMPACT_SEEDQR,
                      display_name=_mft("Compact SeedQR"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__PLAINTEXTQR,
                      display_name="PlaintextQR",
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__ENCRYPTED_QR,
                      display_name="EncryptedQR",
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__ENCRYPTION_MODE,
                      display_name="Encryption Mode",
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_ENCRYPTION_MODES,
                      default_value=SettingsConstants.ENCRYPTION_MODE),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__ENCRYPTION_ITER,
                      display_name="Encryption Iter.(PBKDF2)",
                      type=SettingsConstants.TYPE__FREE_ENTRY,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.ENCRYPTION_ITERATIONS),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__AMBIGUOUS_QR,
                      display_name=_mft("Ambiguous QR"),
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_AMBIGUOUS_QR_OPTIONS,
                      default_value=SettingsConstants.AMBIGUOUS_QR_PROMPT),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__WIF_KEYS,
                      display_name="WIF keys",
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__BIP38_KEYS,
                      display_name="BIP38 keys",
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__GPG_KEY_TYPES,
                      abbreviated_name="gpgkeys",
                      display_name=_mft("GPG key types"),
                      type=SettingsConstants.TYPE__MULTISELECT,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_GPG_KEY_TYPES,
                      default_value=SettingsConstants.DEFAULT_GPG_KEY_TYPES),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__BIP85_CHILD_SEEDS,
                      abbreviated_name="bip85",
                      display_name=_mft("BIP-85 child seeds"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SLIP39_SEEDS,
                      abbreviated_name="slip39",
                      display_name=_mft("SLIP39 seeds"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__AEZEED_SEEDS,
                      abbreviated_name="aezeed",
                      display_name=_mft("Aezeed seeds"),
                      help_text=_mft("LND-compatible, 24 words"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SLIP39_EXTENDABLE,
                      abbreviated_name="slip39ext",
                      display_name=_mft("Extendable SLIP39 shares"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__ELECTRUM_SEEDS,
                      abbreviated_name="electrum",
                      display_name=_mft("Electrum seeds"),
                      help_text=_mft("Native Segwit only"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__BITBOX_BACKUP,
                      abbreviated_name="bitbox",
                      display_name=_mft("BitBox02 backups"),
                      visibility=SettingsConstants.VISIBILITY__HIDDEN,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__PASSPORT_BACKUP,
                      abbreviated_name="passport",
                      display_name=_mft("Passport backups"),
                      visibility=SettingsConstants.VISIBILITY__HIDDEN,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__TAPSIGNER_BACKUP,
                      abbreviated_name="tapsigner",
                      display_name=_mft("TAPSIGNER backups"),
                      visibility=SettingsConstants.VISIBILITY__HIDDEN,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__MESSAGE_SIGNING,
                      display_name=_mft("Message signing"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SMARTCARD_SUPPORT,
                      abbreviated_name="smartcard",
                      display_name=_mft("Smartcard support"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__PRIVACY_WARNINGS,
                      abbreviated_name="priv_warn",
                      display_name=_mft("Show privacy warnings"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__DIRE_WARNINGS,
                      abbreviated_name="dire_warn",
                      display_name=_mft("Show dire warnings"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__QR_BRIGHTNESS_TIPS,
                      display_name=_mft("Show QR brightness tips"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__PARTNER_LOGOS,
                      abbreviated_name="partners",
                      display_name=_mft("Show partner logos"),
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      default_value=SettingsConstants.OPTION__ENABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT,
                      abbreviated_name="satotime",
                      display_name="Satochip tx sign timeout",
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_SATOCHIP_TIMEOUTS,
                      default_value=SettingsConstants.DEFAULT_SATOCHIP_TIMEOUT),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SATOCHIP_MSG_SIGN_TIMEOUT,
                      abbreviated_name="satomsig",
                      display_name="Satochip message sign timeout",
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_SATOCHIP_MSG_TIMEOUTS,
                      default_value=SettingsConstants.DEFAULT_SATOCHIP_MSG_TIMEOUT),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SATOCHIP_MAX_PRE_DUMMIES,
                      abbreviated_name="satopre",
                      display_name="Satochip pre-sign dummies",
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_SATOCHIP_PRE_DUMMY_MAX,
                      default_value=SettingsConstants.DEFAULT_SATOCHIP_PRE_DUMMY_MAX),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SATOCHIP_MAX_POST_DUMMIES,
                      abbreviated_name="satopost",
                      display_name="Satochip post-sign dummies",
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_SATOCHIP_POST_DUMMY_MAX,
                      default_value=SettingsConstants.DEFAULT_SATOCHIP_POST_DUMMY_MAX),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SATOCHIP_MAX_IN_TX_DUMMIES,
                      abbreviated_name="satointx",
                      display_name="Satochip in-tx dummies",
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_SATOCHIP_IN_TX_DUMMY_MAX,
                      default_value=SettingsConstants.DEFAULT_SATOCHIP_IN_TX_DUMMY_MAX),

        SettingsEntry(category=SettingsConstants.CATEGORY__FEATURES,
                      attr_name=SettingsConstants.SETTING__SATOCHIP_DUMMY_PROBABILITY,
                      abbreviated_name="satoprob",
                      display_name="Satochip dummy prob",
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__ADVANCED,
                      selection_options=SettingsConstants.ALL_SATOCHIP_DUMMY_PROB,
                      default_value=SettingsConstants.DEFAULT_SATOCHIP_DUMMY_PROB),


        # Hardware config
        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                      attr_name=SettingsConstants.SETTING__DISPLAY_CONFIGURATION,
                      abbreviated_name="disp_conf",
                      # TRANSLATOR_NOTE: Hardware settings option to specify the screen driver (e.g. st7789 vs ili9341)
                      display_name=_mft("Display type"),
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__HARDWARE,
                      selection_options=SettingsConstants.ALL_DISPLAY_CONFIGURATIONS,
                      default_value=SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240),

        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                      attr_name=SettingsConstants.SETTING__DISPLAY_COLOR_INVERTED,
                      abbreviated_name="rgb_inv",
                      # TRANSLATOR_NOTE: Hardware settings option to invert how the screen driver displays colors.
                      display_name=_mft("Invert colors"),
                      type=SettingsConstants.TYPE__ENABLED_DISABLED,
                      visibility=SettingsConstants.VISIBILITY__HARDWARE,
                      default_value=SettingsConstants.OPTION__DISABLED),

        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                      attr_name=SettingsConstants.SETTING__CAMERA_DEVICE,
                      abbreviated_name="cam_dev",
                      display_name=_mft("Camera source"),
                      type=SettingsConstants.TYPE__SELECT_1,
                      visibility=SettingsConstants.VISIBILITY__HARDWARE,
                      selection_options=SettingsConstants.ALL_CAMERA_DEVICES,
                      default_value=SettingsConstants.CAMERA_DEVICE__0),


        # Developer options
        # TODO: No real Developer options needed yet. Disable for now.
        # SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
        #               attr_name=SettingsConstants.SETTING__DEBUG,
        #               display_name="Debug",
        #               visibility=SettingsConstants.VISIBILITY__DEVELOPER,
        #               default_value=SettingsConstants.OPTION__DISABLED),
        
        # "Hidden" settings with no UI interaction
        SettingsEntry(category=SettingsConstants.CATEGORY__SYSTEM,
                      attr_name=SettingsConstants.SETTING__QR_BRIGHTNESS,
                      abbreviated_name="qr_brightness",
                      display_name=_mft("QR background color"),
                      type=SettingsConstants.TYPE__FREE_ENTRY,
                      visibility=SettingsConstants.VISIBILITY__HIDDEN,
                      default_value=62),
    ]


    @classmethod
    def get_settings_entries(cls, visibility: str = SettingsConstants.VISIBILITY__GENERAL) -> List[SettingsEntry]:
        entries = []
        for entry in cls.settings_entries:
            if entry.visibility == visibility:
                if entry.attr_name == SettingsConstants.SETTING__CAMERA_DEVICE:
                    try:
                        from seedsigner.hardware.camera import Camera

                        entry.selection_options = Camera.list_cameras()
                    except Exception:
                        pass
                entries.append(entry)
        return entries
    

    @classmethod
    def get_settings_entry(cls, attr_name) -> SettingsEntry:
        for entry in cls.settings_entries:
            if entry.attr_name == attr_name:
                return entry


    @classmethod
    def get_settings_entry_by_abbreviated_name(cls, abbreviated_name: str) -> SettingsEntry:
        for entry in cls.settings_entries:
            if abbreviated_name in [entry.abbreviated_name, entry.attr_name]:
                return entry


    @classmethod
    def get_defaults(cls) -> dict:
        as_dict = {}
        for entry in SettingsDefinition.settings_entries:
            if type(entry.default_value) == list:
                # Must copy the default_value list, otherwise we'll inadvertently change
                # defaults when updating these attrs
                as_dict[entry.attr_name] = list(entry.default_value)
            else:
                as_dict[entry.attr_name] = entry.default_value
        return as_dict


    @classmethod
    def to_dict(cls) -> dict:
        output = {
            "settings_entries": [],
        }
        for settings_entry in cls.settings_entries:
            output["settings_entries"].append(settings_entry.to_dict())
        
        return output



if __name__ == "__main__":
    import json
    import os

    hostname = os.uname()[1]
  
    if hostname == "seedsigner-os":
        output_file = "/mnt/microsd/settings_definition.json"
    else:
        output_file = "settings_definition.json"
    
    with open(output_file, 'w') as json_file:
        json.dump(SettingsDefinition.to_dict(), json_file, indent=4)
