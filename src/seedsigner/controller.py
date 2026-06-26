import logging
import os
import time
import traceback
from gettext import gettext as _
from pathlib import Path

from embit.descriptor import Descriptor
from PIL.Image import Image

from seedsigner.gui.toast import BaseToastOverlayManagerThread
from seedsigner.models.encryptedqr import EncryptedQRStorage
from seedsigner.models.settings import Settings
from seedsigner.models.singleton import Singleton
from seedsigner.models.threads import BaseThread
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.screensaver import ScreensaverScreen
from seedsigner.views.view import Destination
from seedsigner.hardware.rng_monitor import HardwareRngHealthMonitor, HardwareRngMonitorThread
from seedsigner.hardware.io_config import get_hardware_pin_mapping, get_hardware_profile_label


logger = logging.getLogger(__name__)


def _get_system_type_and_variant(runtime_profile: str, hardware_profile: str | None) -> tuple[str, str]:
    system_type_map = {
        "desktop": "Desktop",
        "rpi_26": "Raspberry Pi",
        "rpi_40": "Raspberry Pi",
        "luckfox_22": "Luckfox Pico",
        "luckfox_40": "Luckfox Pico",
        "luckfox_pi": "Luckfox Pico",
    }
    system_type = system_type_map.get(runtime_profile, "Unknown")

    model_path = "/proc/device-tree/model"
    try:
        with open(model_path, "r", encoding="utf-8") as model_file:
            model = model_file.read().strip().replace("\x00", "")
            if model:
                return system_type, model
    except Exception:
        pass

    if hardware_profile:
        hardware_label = get_hardware_profile_label(hardware_profile)
        if hardware_label:
            return system_type, hardware_label

    return system_type, "Unknown"



class BackStack(list[Destination]):
    def __repr__(self):
        if len(self) == 0:
            return "[]"
        out = "[\n"
        for index, destination in reversed(list(enumerate(self))):
            out += f"    {index:2d}: {destination}\n"
        out += "]"
        return out
            


class StopFlowBasedTest(Exception):
    """
        This is a special exception that is only raised by the test suite to stop the
        Controller's main loop. It should not be raised by any other code.
    """
    pass



class FlowBasedTestException(Exception):
    """
        This is a special exception that is only raised by the test suite.
        It should not be raised by any other code.
    """
    pass



class BackgroundImportThread(BaseThread):
    def run(self):
        from importlib import import_module

        # import seedsigner.hardware.buttons # slowly imports GPIO along the way

        def time_import(module_name):
            last = time.time()
            import_module(module_name)
            # print(time.time() - last, module_name)

        time_import('embit')

        time_import('seedsigner.models.encryptedqr')
        from seedsigner.models.encryptedqr import EncryptedQRStorage
        Controller.get_instance()._storage2 = EncryptedQRStorage()

        # Get MainMenuView ready to respond quickly
        time_import('seedsigner.views.scan_views')

        time_import('seedsigner.views.tools_views')

        time_import('seedsigner.views.settings_views')

        time_import('seedsigner.views.keycard_views')


class WipeTimerThread(BaseThread):
    def run(self):
        from seedsigner.hardware.buttons import HardwareButtons
        controller = Controller.get_instance()
        buttons = HardwareButtons.get_instance()
        while self.keep_running:
            wipe_minutes = controller.settings.get_value(SettingsConstants.SETTING__WIPE_TIMER)
            if wipe_minutes and wipe_minutes != SettingsConstants.WIPE_TIMER__DISABLED:
                controller.wipe_timer_ms = wipe_minutes * 60 * 1000
                cur = int(time.time() * 1000)
                if controller.wipe_timer_ms and cur - buttons.last_input_time > controller.wipe_timer_ms:
                    controller.handle_wipe_timeout()
                    buttons.update_last_input_time()
            time.sleep(1)


class Controller(Singleton):
    """
        The Controller is a globally available singleton that maintains SeedSigner state.

        It only makes sense to ever have a single Controller instance so it is
        implemented here as a singleton. One departure from the typical singleton pattern
        is the addition of a `configure_instance()` call to pass run-time settings into
        the Controller.

        Any code that needs to interact with the one and only Controller can just run:
        ```
        from seedsigner.controller import Controller
        controller = Controller.get_instance()
        ```
        Note: In many/most cases you'll need to do the Controller import within a method
        rather than at the top in order avoid circular imports.
    """
    
    VERSION = "Keycard-Edition-0.1.3"
    # Branding shown on the opening splash (see views/screensaver.py). Kept as
    # plain brand strings (not translated), consistent with VERSION.
    PRODUCT_NAME = "KeyCard Signer"
    PRODUCT_TAGLINE = "A SeedSigner fork for smartcards"

    # Declare class member vars with type hints to enable richer IDE support throughout
    # the code.
    _storage2: EncryptedQRStorage = None
    settings: Settings = None

    # TODO: Refactor these flow-related attrs that survive across multiple Screens.
    # TODO: Should all in-memory flow-related attrs get wiped on MainMenuView?
    psbt = None
    psbt_seed = None
    psbt_parser = None
    psbt_sign_with_satochip: bool = False
    psbt_from_microsd: bool = False
    psbt_microsd_save_path: Path | None = None
    psbt_microsd_seed_warning_shown: bool = False
    sign_message_with_satochip: bool = False

    unverified_address = None

    multisig_wallet_descriptor: Descriptor = None

    image_entropy_preview_frames: list[Image] = None
    image_entropy_final_image: Image = None

    address_explorer_data: dict = None

    # Per-instance Keycard wallets cache: ``{aid_hex: list[str]}`` of
    # EIP-55 addresses already derived for the active Keycard instance,
    # used by Tools > Keycard > View wallets to avoid re-deriving on
    # pagination. Cleared when the wipe timer fires; per-AID entries are
    # invalidated when the user switches/deletes an instance.
    keycard_wallets_data: dict = None

    # Session cache of how many Keycard instances are on the inserted card
    # (``None`` = unknown / re-probe) and a once-per-boot flag for the
    # Manage Instances explainer. See ``get_instance`` for details.
    keycard_instance_count: int = None
    keycard_instances_intro_shown: bool = False

    # Card-specific, self-calibrated NV cost (bytes) of one Keycard instance,
    # measured as the free-NV delta around an INSTALL in the create flow. ``None``
    # = not measured yet → fall back to the conservative constant. Drives the
    # "≈N more fit" estimate. Cleared on card swap (different card may differ).
    keycard_measured_instance_nv: int = None
    # Sibling of the above for transient-RAM (free_volatile) cost, measured as
    # the free-volatile delta around an INSTALL. ``None`` = not measured.
    keycard_measured_instance_volatile: int = None
    # Set True when an INSTALL [for install] failed with a memory-class SW this
    # session — the card itself proved it's full, so trust that over any
    # estimate: the "≈N more fit" estimate is then forced to 0. Card-specific →
    # cleared on card swap.
    keycard_install_full: bool = False

    sign_message_data: dict = None
    gpg_keys_imported: bool = False
    gpg_pending_message: str = None
    # TODO: end refactor section

    Satochip_Connector = None
    Satochip_PIN = None
    Satochip_Last_UID_SHA1 = None
    GPG_Admin_PIN = None
    tools_common_card_filter: list[str] = None
    javacard_keys: dict | None = None

    # Destination placeholder for when we need to jump out to a side flow but intend to
    # return navigation to the main flow (e.g. PSBT flow, load multisig descriptor,
    # then resume PSBT flow).
    FLOW__PSBT = "psbt"
    FLOW__VERIFY_MULTISIG_ADDR = "multisig_addr"
    FLOW__VERIFY_SINGLESIG_ADDR = "singlesig_addr"
    FLOW__ADDRESS_EXPLORER = "address_explorer"
    FLOW__SIGN_MESSAGE = "sign_message"
    FLOW__GPG_MESSAGE = "gpg_message"
    resume_main_flow: str = None

    back_stack: BackStack = None
    screensaver: ScreensaverScreen = None
    toast_notification_thread: BaseToastOverlayManagerThread = None
    wipe_timer_thread: BaseThread = None
    rng_monitor_thread: BaseThread = None
    hardware_rng_monitor: HardwareRngHealthMonitor = None
    wipe_timer_ms: int = None
    auto_wiped: bool = False

    # Card-view detection used by the centralized card-removed redirect.
    # When a removal fires while the top of the back_stack is one of
    # these views, the next destination is force-replaced with
    # MainMenuView (the existing CardRemovedToast is the visible cue).
    _CARD_VIEW_MODULES = frozenset({
        "seedsigner.views.keycard_views",
    })
    _CARD_VIEW_CLASSNAMES = frozenset({
        "CardsMenuView",
        "CardsFactoryResetView",
        "CardsInstallAppletView",
    })
    _CARD_VIEW_CLASSNAME_PREFIXES = (
        "ToolsSeedkeeper",
    )
    # Deliberate card-swap prompts: the user is explicitly told to pull the
    # card mid-flow (Seedkeeper backup "Both"/"Another card", and the
    # import-from-Seedkeeper chain). On these screens a card-removed
    # redirect-to-Home (and its "Card removed" toast) would abort the swap and
    # make the 2nd backup/import impossible. The secret wipe still fires — it's
    # separate and never touches the pending seed, which survives the swap by
    # design (see the error-vs-user-exit wipe rule).
    _CARD_VIEW_REDIRECT_EXEMPT_CLASSNAMES = frozenset({
        "ToolsKeycardSeedkeeperSwapInsertView",
        "ToolsKeycardImportSeedkeeperInsertView",
        "ToolsKeycardImportSeedkeeperReinsertView",
    })
    _pending_card_removed_redirect: bool = False


    @classmethod
    def get_instance(cls):
        # This is the only way to access the one and only instance
        if cls._instance:
            return cls._instance
        else:
            # Instantiate the one and only Controller instance
            return cls.configure_instance()
    

    @classmethod
    def reset_instance(cls):
        """
            Currently used by the screenshot generator, but could potentially be used to
            wipe and reset the state of the device.
        """
        cls._instance = None
        cls.configure_instance()


    @classmethod
    def configure_instance(cls):
        from seedsigner.gui.renderer import Renderer
        from seedsigner.hardware.microsd import MicroSD
        from seedsigner.hardware.battery_hat import BatteryHat

        # Must be called before the first get_instance() call
        if cls._instance:
            raise Exception("Instance already configured")

        # Instantiate the one and only Controller instance
        controller = cls.__new__(cls)
        cls._instance = controller

        # models
        controller.settings = Settings.get_instance()
        hardware_profile = Settings.get_platform_default_hardware_config()
        runtime_profile = Settings.RUNTIME_PROFILE
        system_type, system_variant = _get_system_type_and_variant(runtime_profile, hardware_profile)
        logger.info(
            "Startup hardware: type=%s variant=%s runtime_profile=%s hardware_profile=%s display=%s",
            system_type,
            system_variant,
            runtime_profile,
            hardware_profile,
            controller.settings.get_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION, default_if_none=True),
        )
        if hardware_profile:
            pin_mapping = get_hardware_pin_mapping(hardware_profile)
            logger.info(
                "Startup GPIO map (%s): display=%s buttons=%s camera=%s",
                hardware_profile,
                pin_mapping.get("display"),
                pin_mapping.get("buttons"),
                pin_mapping.get("camera"),
            )
        
        controller.microsd = MicroSD.get_instance()
        controller.microsd.start_detection()

        controller.battery_hat = BatteryHat.get_instance()
        if controller.battery_hat.initialize():
            controller.battery_hat.process_discharge_log()
            controller.battery_hat.load_discharge_curve()
            controller.battery_hat.start()

        # Store one working psbt in memory
        controller.psbt = None
        controller.psbt_parser = None
        controller.psbt_sign_with_satochip = False
        controller.psbt_from_microsd = False
        controller.psbt_microsd_save_path = None
        controller.psbt_microsd_seed_warning_shown = False
        controller.sign_message_with_satochip = False

        # Keycard session state. ``keycard_pairings`` caches decrypted
        # pairings keyed by ``instance_uid`` for the boot so a user can
        # swap between paired cards without re-entering the pairing
        # password. ``keycard_pairing`` (singular) is a back-compat shim
        # that surfaces the most-recently-seen pairing.
        controller.keycard_pairings = {}
        # AID → instance_uid mapping captured at SELECT time. Cleared by
        # ``forget_pairing_for`` for that UID.
        controller.keycard_aid_to_uid = {}
        # User-assigned instance names keyed by ``instance_uid`` (bytes).
        # Names live in a plaintext microSD file (``helpers.keycard.
        # instance_names``) keyed by ``fingerprint(instance_uid)``; this dict
        # is just a per-session read-through cache (``None`` = "no name, don't
        # re-read disk"). Display is by AID, resolved to a UID via
        # ``keycard_aid_to_uid`` (populated by SELECT), then to a name on first
        # render; it falls back to the ``Inst N`` label when the UID or name is
        # unknown. Card-specific, so cleared on card swap.
        controller.keycard_instance_names = {}
        # ``keycard_ephemeral_secrets`` caches the 32-byte pairing
        # secret (NOT the pairing key) for cards that use v3.2 ephemeral
        # pairing. The on-card key is wiped on every applet deselect, so
        # we PAIR fresh on each session using the cached secret. Nothing
        # ever reaches disk for ephemeral pairings.
        controller.keycard_ephemeral_secrets = {}
        # ``keycard_pins`` caches verified PINs as ``bytearray`` keyed
        # by ``instance_uid`` for the boot, so card operations after the
        # first VERIFY_PIN don't re-prompt. Wiped on swap (CardMonitor),
        # bad PIN (SW=0x63CX), unpair, and ``handle_wipe_timeout``.
        controller.keycard_pins = {}
        # ``last_authenticated_keycard_uid`` is the instance_uid of the card we
        # last opened an unlocked (PIN-verified) session with. It is the
        # reader-independent signal for a card/instance swap: open_unlocked_session
        # compares the freshly-SELECTed uid against it and scrubs the previous
        # card's secrets when they differ. Deliberately distinct from
        # ``last_keycard_uid`` (which enumeration / name resolution mutate, so it
        # would false-positive). Cleared together with the PIN cache.
        controller.last_authenticated_keycard_uid = None
        controller.last_keycard_uid = None
        controller.eth_sign_request = None
        controller.eth_signature = None
        # Multi-instance support: which applet AID we SELECT for
        # Keycard operations this session. Defaults to the Status
        # published AID; the Manage Instances flow updates it.
        from seedsigner.helpers.keycard.commands import APPLET_AID as _DEFAULT_KEYCARD_AID
        controller.active_keycard_aid = _DEFAULT_KEYCARD_AID
        # Cached count of Keycard applet instances on the inserted card. Drives
        # both whether "Switch instance" shows (only meaningful with >1) and
        # whether menu titles carry the ``Inst N`` suffix (dropped when exactly
        # one). ``None`` means "unknown" — the entry and the label stay visible.
        # On menu entry it is filled by a FAST cleartext probe
        # (``keycard_views._probe_keycard_instance_count``) that SELECTs every
        # valid slot and returns the exact count (including one); the create /
        # delete / switch flows still refresh it authoritatively. It is reset to
        # ``None`` whenever the card may have changed (see
        # ``wipe_card_session_secrets``).
        controller.keycard_instance_count = None
        # Session-only UX gate: show the Manage Instances explainer once
        # per boot, then go straight to the menu. NOT security state, so
        # it is deliberately not reset on card removal.
        controller.keycard_instances_intro_shown = False
        # Transient state for the post-init Setup chain (Generate / Import →
        # backup → LOAD_KEY → optional Seedkeeper save). Mnemonic words are
        # stored as ``"".join(WORDLIST[i])`` copies so wiping them does NOT
        # corrupt the shared BIP-39 wordlist (CLAUDE.md "Secure wipe and
        # shared wordlist safety"). Both are wiped on flow exit and on
        # ``MainMenuView`` entry.
        controller.pending_keycard_mnemonic = None
        controller.pending_keycard_passphrase = None
        # Address cache for "View wallets". Initialised here so the
        # attribute is always a dict by the time any view touches it.
        controller.keycard_wallets_data = {}
        # Subscribers for PC/SC card-event fan-out. Populated by code
        # that needs to react to insert/remove (e.g. the centralized
        # card-removed redirect, CardInsertedToast).
        controller._card_inserted_listeners = []
        controller._card_removed_listeners = []

        # Configure the Renderer
        Renderer.configure_instance()

        controller.back_stack = BackStack()

        background_import_thread = BackgroundImportThread()
        background_import_thread.start()

        controller.wipe_timer_thread = WipeTimerThread()
        controller.wipe_timer_thread.start()

        controller.hardware_rng_monitor = HardwareRngHealthMonitor()
        controller.rng_monitor_thread = HardwareRngMonitorThread(controller.hardware_rng_monitor)
        controller.rng_monitor_thread.start()

        # Background PC/SC card-event listener. Wipes cached PINs the
        # moment a card is removed so a yank cannot leak the PIN
        # through a session that's still alive.
        from seedsigner.helpers.card_monitor import start_card_monitor
        controller.card_monitor_observer = start_card_monitor(controller)

        # Centralized "card removed while in a card view → MainMenu"
        # redirect. Registered once, fans out via the main loop.
        controller._pending_card_removed_redirect = False
        controller.register_card_removed_listener(controller._on_card_removed_redirect)

        return cls._instance


    @property
    def camera(self):
        from .hardware.camera import Camera
        return Camera.get_instance()

    @property
    def screensaver_activation_ms(self) -> float:
        """Idle-time threshold (ms) before the screensaver kicks in.

        Backed by :attr:`SettingsConstants.SETTING__SCREENSAVER_TIMEOUT`
        — the user controls this from Settings ▸ System ▸ Screensaver.
        ``0`` disables the screensaver entirely; we return positive
        infinity so the comparison in ``HardwareButtons.wait_for`` never
        fires.
        """
        try:
            minutes = self.settings.get_value(
                SettingsConstants.SETTING__SCREENSAVER_TIMEOUT
            )
        except Exception:
            minutes = 2
        if minutes is None or minutes <= 0:
            return float("inf")
        return minutes * 60 * 1000


    # ---- Keycard pairing cache helpers ----

    def get_pairing_for(self, instance_uid):
        """Return the cached PairingInfo for ``instance_uid`` or None."""
        if instance_uid is None:
            return None
        return self.keycard_pairings.get(bytes(instance_uid))

    def set_pairing_for(self, instance_uid, pairing) -> None:
        """Cache (or overwrite) the pairing for ``instance_uid``."""
        if instance_uid is None:
            return
        self.keycard_pairings[bytes(instance_uid)] = pairing
        self.last_keycard_uid = bytes(instance_uid)

    def remember_aid_for_uid(self, aid, instance_uid) -> None:
        """Record the AID→UID mapping observed at SELECT time."""
        if aid is None or instance_uid is None:
            return
        self.keycard_aid_to_uid[bytes(aid)] = bytes(instance_uid)

    def get_uid_for_aid(self, aid):
        if aid is None:
            return None
        return self.keycard_aid_to_uid.get(bytes(aid))

    # ---- Keycard instance names ----

    def set_instance_name_for(self, instance_uid, name) -> None:
        """Cache the resolved name for ``instance_uid`` (``None`` = no name).

        We store ``None`` rather than dropping the key so a later lazy-load
        treats it as "already known" and does not re-read the microSD.
        """
        if instance_uid is None:
            return
        self.keycard_instance_names[bytes(instance_uid)] = name or None

    def get_instance_name_for(self, instance_uid):
        if instance_uid is None:
            return None
        return self.keycard_instance_names.get(bytes(instance_uid))

    def get_instance_name_for_aid(self, aid):
        """Resolve a display name by AID, lazy-loading from the microSD.

        The session AID→UID map (``keycard_aid_to_uid``, populated by every
        SELECT and by enumeration) gives us the UID; the name itself is read
        once from the ``instance_names`` JSON file and cached (including
        ``None``) so titles don't hit the card on every render. When the AID's
        UID is unknown we return ``None`` (caller shows ``Inst N``) — we must
        NOT guess via ``last_keycard_uid``, which is the *globally* last-
        SELECTed UID and may belong to a different instance (that bled one
        instance's name onto another).
        """
        if aid is None:
            return None
        uid = self.get_uid_for_aid(aid)
        if uid is None:
            return None
        key = bytes(uid)
        if key not in self.keycard_instance_names:
            try:
                from seedsigner.helpers.keycard import instance_names
                self.keycard_instance_names[key] = instance_names.get_name(key)
            except Exception:
                logger.exception("instance name lookup failed")
                self.keycard_instance_names[key] = None
        return self.keycard_instance_names[key]

    def forget_pairing_for(self, instance_uid) -> None:
        if instance_uid is None:
            return
        self.keycard_pairings.pop(bytes(instance_uid), None)
        # The name lives in (and is read from) the pairing blob, so it must
        # not outlive the pairing it describes.
        self.keycard_instance_names.pop(bytes(instance_uid), None)
        uid_b = bytes(instance_uid)
        for aid_key, mapped_uid in list(self.keycard_aid_to_uid.items()):
            if mapped_uid == uid_b:
                self.keycard_aid_to_uid.pop(aid_key, None)
        # Also drop any ephemeral secret for this UID — callers using
        # forget_pairing_for() expect the card to have *no* cached
        # auth state of any kind after the call.
        self.forget_ephemeral_secret_for(instance_uid)
        # Unpair removes the card's pairing slot; the cached PIN is no
        # longer reachable until the user re-pairs, so drop it too.
        self.forget_pin_for(instance_uid)
        if self.last_keycard_uid == bytes(instance_uid):
            self.last_keycard_uid = None

    def forget_all_pairings(self) -> None:
        self.keycard_pairings.clear()
        self.keycard_aid_to_uid.clear()
        self.keycard_instance_names.clear()
        for uid in list(self.keycard_ephemeral_secrets.keys()):
            self.forget_ephemeral_secret_for(uid)
        self.forget_all_pins()
        self.last_keycard_uid = None

    # ---- Keycard PIN cache ----

    def get_pin_for(self, instance_uid):
        """Return the cached PIN bytearray for ``instance_uid`` or None."""
        if instance_uid is None:
            return None
        return self.keycard_pins.get(bytes(instance_uid))

    def set_pin_for(self, instance_uid, pin) -> None:
        """Cache an independent copy of ``pin`` for ``instance_uid``.

        The cached buffer is a fresh ``bytearray``, so callers can wipe
        their own buffer afterwards without destroying the cache.
        """
        if instance_uid is None or pin is None:
            return
        key = bytes(instance_uid)
        existing = self.keycard_pins.get(key)
        if isinstance(existing, bytearray):
            for i in range(len(existing)):
                existing[i] = 0
        self.keycard_pins[key] = bytearray(pin)

    def forget_pin_for(self, instance_uid) -> None:
        if instance_uid is None:
            return
        existing = self.keycard_pins.pop(bytes(instance_uid), None)
        if isinstance(existing, bytearray):
            for i in range(len(existing)):
                existing[i] = 0

    def forget_all_pins(self) -> None:
        for uid in list(self.keycard_pins.keys()):
            self.forget_pin_for(uid)
        # Derived addresses are only valid under an authenticated PIN session.
        # Dropping all PINs must drop all cached View-wallets addresses so the
        # next derivation runs against whichever PIN is entered next (incl. the
        # duress PIN -> on-card decoy wallet). Without this, locking / removing /
        # returning Home would re-prompt for a PIN but still show the previous
        # PIN's addresses, defeating the duress wallet. See Threat model in
        # CLAUDE.md.
        if self.keycard_wallets_data is not None:
            self.keycard_wallets_data.clear()
        # The "last authenticated card" marker is PIN-session-scoped: once all
        # PINs are gone it is meaningless, and clearing it keeps the swap-detector
        # in open_unlocked_session from a redundant wipe on the next operation.
        self.last_authenticated_keycard_uid = None

    # ---- Satochip / SeedKeeper session ----

    # ---- CardMonitor callbacks (PC/SC events) ----

    def wipe_card_session_secrets(self) -> None:
        """Defensive wipe of cached card secrets (PINs, Satochip session).

        Called immediately on every PC/SC ``removed`` event — never
        debounced, even when the event later turns out to be a contact-
        bounce glitch. The cost of a spurious wipe is one extra PIN
        re-entry; the cost of skipping a real wipe is leaking secrets
        across cards. Safe from any thread, never raises.
        """
        try:
            self.forget_all_pins()
        except Exception:
            logger.exception("forget_all_pins failed in wipe_card_session_secrets")
        try:
            self.forget_satochip_session()
        except Exception:
            logger.exception("forget_satochip_session failed in wipe_card_session_secrets")
        # The inserted card may have been removed/swapped — a cached name (not
        # a secret, but card-specific) must not render against a different card.
        try:
            self.keycard_instance_names.clear()
        except Exception:
            logger.exception("clearing keycard_instance_names failed in wipe_card_session_secrets")
        # The AID→UID map and ``last_keycard_uid`` are likewise card-specific:
        # a swapped card reuses the same AIDs with different UIDs, so a stale
        # mapping would resolve the new card's instance to the old card's name.
        try:
            self.keycard_aid_to_uid.clear()
            self.last_keycard_uid = None
        except Exception:
            logger.exception("clearing keycard_aid_to_uid failed in wipe_card_session_secrets")
        # The inserted card may have been removed/swapped — the cached
        # instance count is no longer trustworthy. Force a re-probe on the
        # next top Keycard menu render.
        self.keycard_instance_count = None
        # Per-instance NV/RAM calibration and the "card is full" marker are all
        # card-specific (a different card may have a different footprint and may
        # not be full), so drop them on swap.
        self.keycard_measured_instance_nv = None
        self.keycard_measured_instance_volatile = None
        self.keycard_install_full = False

    def _is_card_view(self, view_cls) -> bool:
        """True iff ``view_cls`` belongs to the card-views subtree.

        Used by the card-removed redirect to decide whether to snap
        back to MainMenu. See class-level ``_CARD_VIEW_*`` allowlists.
        """
        if view_cls is None:
            return False
        if view_cls.__module__ in self._CARD_VIEW_MODULES:
            return True
        name = view_cls.__name__
        if name in self._CARD_VIEW_CLASSNAMES:
            return True
        if name.startswith(self._CARD_VIEW_CLASSNAME_PREFIXES):
            return True
        return False

    def _top_is_card_swap_view(self) -> bool:
        """True iff the top-of-stack view is one of the deliberate card-swap
        prompts (see ``_CARD_VIEW_REDIRECT_EXEMPT_CLASSNAMES``).

        Used to suppress both the card-removed redirect-to-Home and its toast
        on screens that *instruct* the user to pull the card mid-flow.
        """
        if not self.back_stack:
            return False
        view_cls = getattr(self.back_stack[-1], "View_cls", None)
        name = getattr(view_cls, "__name__", None)
        return name in self._CARD_VIEW_REDIRECT_EXEMPT_CLASSNAMES

    def _on_card_removed_redirect(self, *_args, **_kwargs) -> None:
        """Card-removed listener that forces a return to MainMenu.

        Fires on the CardMonitor thread; must be fast and exception-safe.
        Sets a flag the main loop honors after the active view returns,
        and trips ``trigger_override`` so any screen blocked on input
        wakes up.
        """
        if not self.back_stack:
            return
        top = self.back_stack[-1]
        if not self._is_card_view(getattr(top, "View_cls", None)):
            return
        # Deliberate card-swap prompts must NOT snap to Home — the user is
        # mid-swap. Returning early skips both the flag and trigger_override,
        # so the blocked WarningScreen keeps waiting for "Continue".
        if self._top_is_card_swap_view():
            return
        self._pending_card_removed_redirect = True
        try:
            from seedsigner.hardware.buttons import HardwareButtons
            HardwareButtons.get_instance().trigger_override()
        except Exception:
            pass

    def dispatch_card_removed_event(self, reader_name=None) -> None:
        """User-visible side of a card-removed event: toast + listener fan-out.

        Run **after** a short debounce in :mod:`seedsigner.helpers.card_monitor`
        so spurious removed/inserted bounces (common on contactless and loose
        USB readers) don't surface a confusing "Card removed" toast during a
        normal insertion. The wipe is handled separately by
        :meth:`wipe_card_session_secrets` and is **not** debounced.
        """
        # On a deliberate card-swap prompt the removal is expected and
        # instructed by the screen itself — suppress the redundant toast.
        # (The redirect listener self-suppresses in _on_card_removed_redirect.)
        if not self._top_is_card_swap_view():
            try:
                from seedsigner.gui.toast import CardRemovedToast
                self.activate_toast(CardRemovedToast())
            except Exception:
                logger.exception("CardRemovedToast dispatch failed")
        self._notify_card_listeners(self._card_removed_listeners)

    def on_card_removed(self, reader_name=None) -> None:
        """Adapter that wipes and dispatches in one shot, no debounce.

        The CardMonitor itself uses the split entry points
        (:meth:`wipe_card_session_secrets` immediately, then
        :meth:`dispatch_card_removed_event` via a debouncer). This
        adapter exists for callers outside the monitor (tests, manual
        invocations) and preserves the original synchronous semantics.
        """
        self.wipe_card_session_secrets()
        self.dispatch_card_removed_event(reader_name)

    def on_card_inserted(self, atr: bytes, reader_name=None) -> None:
        """Card-inserted event from the background PC/SC monitor.

        Fires ``CardInsertedToast`` when ``SETTING__AUTO_PIN_ON_INSERT``
        is enabled, then dispatches the event to any registered
        ``card_inserted`` listeners. ATR is NOT logged (fingerprint risk).
        """
        try:
            enabled = Settings.get_instance().get_value(
                SettingsConstants.SETTING__AUTO_PIN_ON_INSERT
            )
        except Exception:
            enabled = SettingsConstants.OPTION__DISABLED
        if enabled == SettingsConstants.OPTION__ENABLED:
            try:
                from seedsigner.gui.toast import CardInsertedToast
                kind = self.identify_inserted_card_kind(atr)
                self.activate_toast(CardInsertedToast(kind=kind))
            except Exception:
                logger.exception("CardInsertedToast dispatch failed")
        self._notify_card_listeners(self._card_inserted_listeners, atr, reader_name)

    # ---- Card-event listener registry ---------------------------------

    def register_card_inserted_listener(self, fn) -> None:
        """Subscribe to PC/SC card-inserted events.

        Listeners run on the pyscard monitor thread; keep callbacks fast
        and exception-safe. Use ``unregister_card_inserted_listener`` on
        teardown to avoid leaking references.
        """
        self._card_inserted_listeners.append(fn)

    def unregister_card_inserted_listener(self, fn) -> None:
        try:
            self._card_inserted_listeners.remove(fn)
        except ValueError:
            pass

    def register_card_removed_listener(self, fn) -> None:
        self._card_removed_listeners.append(fn)

    def unregister_card_removed_listener(self, fn) -> None:
        try:
            self._card_removed_listeners.remove(fn)
        except ValueError:
            pass

    def _notify_card_listeners(self, listeners, *args) -> None:
        for fn in list(listeners):
            try:
                fn(*args)
            except Exception:
                logger.exception("card-event listener raised; continuing")

    def identify_inserted_card_kind(self, atr: bytes) -> str:
        """Best-effort label for ``on_card_inserted`` toasts.

        Phase 5 stays generic ("Card") because reliable ATR-based
        identification across the heterogeneous Java Card population
        is impractical. Phase 6 will replace this with a SELECT-probe
        that produces "Keycard" / "Satochip" / "SeedKeeper" / "Blank".
        """
        return "Card"

    def forget_satochip_session(self) -> None:
        """Drop the cached Satochip/SeedKeeper PIN and disconnect the
        active connector, leaving the controller in the same state as
        a fresh boot for subsequent ``init_satochip`` calls.

        Called on card-removed events (CardMonitor), the wipe-timer,
        and explicit "lock" actions in the UI.
        """
        existing = getattr(self, "Satochip_PIN", None)
        if isinstance(existing, list):
            for i in range(len(existing)):
                existing[i] = 0
        elif isinstance(existing, bytearray):
            for i in range(len(existing)):
                existing[i] = 0
        self.Satochip_PIN = None
        self.Satochip_Last_UID_SHA1 = None
        connector = getattr(self, "Satochip_Connector", None)
        if connector is not None:
            try:
                connector.card_disconnect()
            except Exception:
                pass
        self.Satochip_Connector = None

    # ---- Ephemeral (v3.2) pairing-secret cache ----

    def get_ephemeral_secret_for(self, instance_uid):
        if instance_uid is None:
            return None
        return self.keycard_ephemeral_secrets.get(bytes(instance_uid))

    def set_ephemeral_secret_for(self, instance_uid, secret: bytes) -> None:
        if instance_uid is None:
            return
        if not isinstance(secret, (bytes, bytearray)) or len(secret) != 32:
            raise ValueError("pairing secret must be 32 bytes")
        # Drop any persistent pairing for this UID so the lookup order
        # doesn't accidentally fall through to it on a v3.2 card that
        # was previously persistent-paired.
        self.keycard_pairings.pop(bytes(instance_uid), None)
        self.keycard_ephemeral_secrets[bytes(instance_uid)] = bytes(secret)
        self.last_keycard_uid = bytes(instance_uid)

    def has_any_keycard_auth(self) -> bool:
        """True when at least one card has cached auth state for this boot.

        Used by entry-point views (Generate key, Import seed, Sign ETH,
        Pair-with-wallet) to decide whether to bounce the user to the
        Pair view first. Counts both persistent pairings and v3.2
        ephemeral secrets — either is enough to authenticate against
        the right card.
        """
        return bool(self.keycard_pairings) or bool(self.keycard_ephemeral_secrets)

    def forget_ephemeral_secret_for(self, instance_uid) -> None:
        if instance_uid is None:
            return
        existing = self.keycard_ephemeral_secrets.pop(bytes(instance_uid), None)
        if isinstance(existing, (bytes, bytearray)):
            # Best-effort wipe before letting the GC collect the bytes
            # object. Python interns short bytes literals, but a freshly
            # allocated 32-byte secret won't be shared, so this is
            # meaningful even if not ironclad.
            try:
                buf = bytearray(existing)
                for i in range(len(buf)):
                    buf[i] = 0
            except Exception:
                pass
        if self.last_keycard_uid == bytes(instance_uid):
            self.last_keycard_uid = None

    @property
    def keycard_pairing(self):
        """Back-compat singular: pairing for the most-recently-seen card."""
        if self.last_keycard_uid is None:
            return None
        return self.keycard_pairings.get(self.last_keycard_uid)

    @keycard_pairing.setter
    def keycard_pairing(self, value):
        # Setting to None or a value without a known UID can't update the
        # dict cleanly, so just clear the "active" pointer.
        if value is None:
            self.last_keycard_uid = None
            return
        # Best-effort: store under last_keycard_uid if known, else under a
        # placeholder key. Callers that touch this setter are legacy paths
        # we expect to phase out; new code should use set_pairing_for().
        if self.last_keycard_uid is not None:
            self.keycard_pairings[self.last_keycard_uid] = value


    class _StubStorage:
        """Placeholder shim left over from the deleted on-device seed
        manager. Some SeedKeeper / DIY views still reach for
        ``controller.storage.seeds`` etc.; expose an empty list and
        harmless no-ops so those paths fall through cleanly until the
        SeedKeeper rewrite lands.
        """
        seeds: list = []

        def init_pending_mnemonic(self, *args, **kwargs):
            return None

        def update_pending_mnemonic(self, *args, **kwargs):
            return None

        def finalize_pending_seed(self, *args, **kwargs):
            return None

        def clear_pending_seed(self, *args, **kwargs):
            return None

    storage = _StubStorage()


    @property
    def storage2(self):
        while not self._storage2:
            time.sleep(0.001)
        return self._storage2


    @property
    def hardware_rng_is_healthy(self) -> bool:
        if not self.hardware_rng_monitor:
            return False
        return self.hardware_rng_monitor.is_healthy()


    @property
    def hardware_rng_failure_reason(self) -> str | None:
        if not self.hardware_rng_monitor:
            return "System RNG monitor unavailable"
        return self.hardware_rng_monitor.failure_reason()


    # Legacy ``get_seed`` / ``discard_seed`` deleted with the on-device
    # seed management. Keycard / SeedKeeper flows manage key material
    # via their own card-side state.


    def pop_prev_from_back_stack(self):
        if len(self.back_stack) > 0:
            # Pop the top View (which is the current View_cls)
            self.back_stack.pop()

            if len(self.back_stack) > 0:
                # One more pop back gives us the actual "back" View_cls
                return self.back_stack.pop()
        return Destination(None)
    

    def clear_back_stack(self):
        self.back_stack = BackStack()


    def start(self, initial_destination: Destination = None, skip_startup_interstitials: bool = False) -> None:
        """
            The main loop of the application.

            * initial_destination: The first View to run. If None, the MainMenuView is
            used. Only used by the test suite.
        """
        from seedsigner.views import MainMenuView, BackStackView
        from seedsigner.views.screensaver import OpeningSplashView
        from seedsigner.models.settings_definition import SettingsConstants
        from seedsigner.views.desktop_warning import DesktopWarningView
        from seedsigner.views.developer_os_warning import DeveloperOSWarningView
        from seedsigner.helpers.seedsigner_os import is_seedsigner_os_dev_build
        from seedsigner.gui.toast import RemoveSDCardToastManagerThread

        if not skip_startup_interstitials:
            # Stealth boot: when enabled, run the games console first. Its
            # run() blocks until the user inputs the configured unlock combo
            # (or triggers the panic-exit). Bitcoin/Keycard flows continue
            # exactly as before once it returns. See AGENTS.md >
            # "Stealth boot mode" for the full design.
            try:
                stealth_setting = self.settings.get_value(
                    SettingsConstants.SETTING__STEALTH_BOOT
                )
            except Exception:
                stealth_setting = SettingsConstants.OPTION__DISABLED
            if stealth_setting == SettingsConstants.OPTION__ENABLED:
                try:
                    from seedsigner.stealth.console import StealthConsole
                    StealthConsole().run()
                except Exception:
                    logger.exception("stealth boot game failed; falling through")

            OpeningSplashView().run()

            # Flow tests start from an expected first interactive screen (usually MainMenu).
            # Skip startup warning interstitials under pytest to keep deterministic routing.
            if "PYTEST_CURRENT_TEST" not in os.environ:
                if is_seedsigner_os_dev_build():
                    DeveloperOSWarningView().run()
                if self.settings.get_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION).startswith("desktop"):
                    DesktopWarningView().run()

        """ Class references can be stored as variables in python!

            This loop receives a View class to execute and stores it in the `View_cls`
            var along with any input arguments in the `init_args` dict.

            The `View_cls` is instantiated with `init_args` passed in and then run(). It
            returns either a new View class to execute next or None.

            Example:
                class MyView(View)
                    def run(self, some_arg, other_arg):
                        logger.info(other_arg)

                class OtherView(View):
                    def run(self):
                        return (MyView, dict(some_arg=1, other_arg="hello"))

            When `OtherView` is instantiated and run, we capture its return values:

                (View_cls, init_args) = OtherView().run()

            And then we can instantiate and run that View class:

                View_cls(**init_args).run()
        """
        try:
            if initial_destination:
                next_destination = initial_destination
            else:
                next_destination = Destination(MainMenuView)
            
            # Skip the "remove SD card" tip on Luckfox, where removable media
            # handling and expected workflows differ from SeedSigner OS defaults.
            if Settings.RUNTIME_PROFILE not in {"luckfox_22", "luckfox_40", "luckfox_pi", "desktop"}:
                # Set up our one-time toast notification tip to remove the SD card
                self.activate_toast(RemoveSDCardToastManagerThread())

            while True:
                # Destination(None) is a special case; render the Home screen
                if next_destination.View_cls is None:
                    next_destination = Destination(MainMenuView)

                if next_destination.View_cls == MainMenuView:
                    # Home always wipes the back_stack
                    self.clear_back_stack()
                    
                    # Home always wipes the back_stack/state of temp vars
                    self.resume_main_flow = None
                    # self.multisig_wallet_descriptor = None
                    self.unverified_address = None
                    self.address_explorer_data = None
                    self.psbt = None
                    self.psbt_parser = None
                    self.psbt_seed = None
                    self.psbt_sign_with_satochip = False
                    self.sign_message_with_satochip = False

                    # Clear camera entropy data so it cannot be used to
                    # reconstruct seeds after the flow completes.
                    self.image_entropy_preview_frames = None
                    self.image_entropy_final_image = None

                    # Clear the whole Smartcard session if caching PIN is disabled (Same as removing the card)
                    if Settings.get_instance().get_value(SettingsConstants.SETTING__CACHE_SCARD_PIN) != "E":
                        self.forget_satochip_session()
                        # Keycard PIN cache obeys the same setting so the
                        # two card families have symmetric semantics.
                        self.forget_all_pins()

                    # Always drop any cached OpenPGP admin PIN when returning home
                    self.GPG_Admin_PIN = None
                
                logger.info(f"\nback_stack: {self.back_stack}")

                try:
                    # Instantiate the View class and run it
                    logger.info(f"Executing {next_destination}")
                    next_destination = next_destination.run()

                except StopFlowBasedTest:
                    # This is a special exception that is only raised by the test suite
                    # to stop the Controller loop and exit the test.
                    return

                except FlowBasedTestException as e:
                    # This is a special exception that is only raised by the test suite.
                    # Re-raise so the test suite can handle it.
                    raise e

                except Exception as e:
                    # Display user-friendly error screen w/debugging info
                    import traceback
                    traceback.print_exc()
                    next_destination = self.handle_exception(e)

                if not next_destination:
                    # Should only happen during dev when you hit an unimplemented option
                    from seedsigner.views.view import NotYetImplementedView
                    next_destination = Destination(NotYetImplementedView)

                # Card-removed redirect: if a card was pulled while the
                # user was anywhere in the cards subtree, override the
                # view's return value and snap back to MainMenu. The
                # existing CardRemovedToast is the visible cue; this
                # only handles navigation.
                if self._pending_card_removed_redirect:
                    self._pending_card_removed_redirect = False
                    next_destination = Destination(MainMenuView, clear_history=True)

                if next_destination.skip_current_view:
                    # Remove the current View from history; it's forwarding us straight
                    # to the next View so it should be as if this View never happened.
                    current_view = self.back_stack.pop()
                    logger.info(f"Skipping current view: {current_view}")

                # Hang on to this reference...
                clear_history = next_destination.clear_history

                if next_destination.View_cls == BackStackView:
                    # "Back" arrow was clicked; load the previous view
                    next_destination = self.pop_prev_from_back_stack()

                # ...now apply it, if needed
                if clear_history:
                    self.clear_back_stack()

                # The next_destination up always goes on the back_stack, even if it's the
                #   one we just popped.
                # Do not push a "new" destination if it is the same as the current one on
                # the top of the stack.
                if len(self.back_stack) == 0 or self.back_stack[-1] != next_destination:
                    logger.info(f"Appending next destination: {next_destination}")
                    self.back_stack.append(next_destination)
                else:
                    logger.info(f"NOT appending {next_destination}")

        finally:
            from seedsigner.gui.renderer import Renderer
            if self.is_screensaver_running:
                self.screensaver.stop()
            
            if self.toast_notification_thread and self.toast_notification_thread.is_alive():
                self.toast_notification_thread.stop()

            if hasattr(self, "battery_hat") and self.battery_hat.is_alive():
                self.battery_hat.stop()

            if self.wipe_timer_thread and self.wipe_timer_thread.is_alive():
                self.wipe_timer_thread.stop()

            observer = getattr(self, "card_monitor_observer", None)
            if observer is not None:
                from seedsigner.helpers.card_monitor import stop_card_monitor
                stop_card_monitor(observer)
                self.card_monitor_observer = None

            if self.rng_monitor_thread and self.rng_monitor_thread.is_alive():
                self.rng_monitor_thread.stop()

            # Clear the screen when exiting
            logger.info("Clearing screen, exiting")
            Renderer.get_instance().display_blank_screen()


    @property
    def is_screensaver_running(self):
        return self.screensaver is not None and self.screensaver.is_running


    def start_screensaver(self):
        # If a toast is running, tell it to give up the Renderer.lock; it will then
        # block until the screensaver is done, at which point the toast can re-acquire
        # the Renderer.lock and resume where it left off.
        if self.toast_notification_thread and self.toast_notification_thread.is_alive():
            logger.info(f"Controller: settings toggle_render_lock for {self.toast_notification_thread.__class__.__name__}")
            self.toast_notification_thread.toggle_renderer_lock()

        logger.info("Controller: Starting screensaver")
        if not self.screensaver:
            # Do a lazy/late import and instantiation to reduce Controller initial startup time
            from seedsigner.views.screensaver import ScreensaverScreen
            from seedsigner.hardware.buttons import HardwareButtons
            self.screensaver = ScreensaverScreen(HardwareButtons.get_instance())
        
        # Start the screensaver, but it will block until it can acquire the Renderer.lock.
        self.screensaver.start()
        logger.info("Controller: Screensaver started")
    

    def reset_screensaver_timeout(self):
        """
        Reset the screensaver's timeout starting point to right now (i.e. make it think
        that zero time has elapsed since the last user interaction).
        """
        from seedsigner.hardware.buttons import HardwareButtons
        HardwareButtons.get_instance().update_last_input_time()


    def activate_toast(self, toast_manager_thread: BaseToastOverlayManagerThread):
        """
        Ensures that the Controller has explicit control over which processes get to
        claim the Renderer.lock and which need to (potentially) release it.
        """
        if self.is_screensaver_running:
            # New toast notifications break out of the Screensaver
            logger.info("Controller: stopping screensaver")
            self.screensaver.stop()

        if self.toast_notification_thread and self.toast_notification_thread.is_alive():
            # Can only run one toast at a time
            logger.info(f"Controller: stopping {self.toast_notification_thread.__class__.__name__}")
            self.toast_notification_thread.stop()
        
        self.toast_notification_thread = toast_manager_thread
        logger.info(f"Controller: starting {self.toast_notification_thread.__class__.__name__}")
        self.toast_notification_thread.start()


    def handle_wipe_timeout(self):
        from seedsigner.gui.toast import InfoToast
        from seedsigner.views import MainMenuView
        from seedsigner.hardware.buttons import HardwareButtons

        logger.info("Controller: wipe timer triggered; wiping data")

        # Wipe sensitive in-memory data
        if self._storage2:
            self._storage2.clear_encryptedqr()

        self.psbt = None
        self.psbt_parser = None
        self.psbt_seed = None
        self.multisig_wallet_descriptor = None
        self.unverified_address = None
        self.resume_main_flow = None
        self.forget_satochip_session()
        # Wipe cached Keycard PINs; pairings are intentionally kept so
        # the user can resume after a wipe-timer trigger by entering
        # the PIN again, without re-pairing.
        self.forget_all_pins()
        # Drop any cached Keycard wallet addresses; harmless to recompute
        # but no reason to keep them around once the user is wiped out.
        if self.keycard_wallets_data is not None:
            self.keycard_wallets_data.clear()

        # Return to main menu
        self.clear_back_stack()
        self.back_stack.append(Destination(MainMenuView))

        self.auto_wiped = True

        # Notify user
        self.activate_toast(InfoToast(label_text=_("Data wiped after inactivity")))

        # Ensure any running screens break out of wait loops
        HardwareButtons.get_instance().trigger_override()


    def handle_exception(self, e) -> Destination:
        """
            Displays a user-friendly error screen and includes debugging info to help
            devs diagnose what went wrong.

            Shows:
                * Exception type
                * python file, line num, method name
                * Exception message
        """
        from seedsigner.views.view import UnhandledExceptionView
        logger.exception(e)

        # The final exception output line is:
        # "foo.bar.ExceptionType: The exception message"
        # So we extract the Exception type and trim off any "foo.bar." namespacing:
        last_line = traceback.format_exc().splitlines()[-1]
        exception_type = last_line.split(":")[0].split(".")[-1]

        # Extract the error message, if there is one
        if ":" in last_line:
            exception_msg = last_line.split(":")[1]
        else:
            exception_msg = ""

        # Scan for the last debugging line that includes a line number reference
        line_info = None
        for i in range(len(traceback.format_exc().splitlines()) - 1, 0, -1):
            traceback_line = traceback.format_exc().splitlines()[i]
            if ", line " in traceback_line:
                line_info = traceback_line.split("/")[-1].replace("\"", "").replace("line ", "")
                break
        
        error = [
            exception_type,
            line_info,
            exception_msg,
        ]
        return Destination(UnhandledExceptionView, view_args={"error": error}, clear_history=True)
