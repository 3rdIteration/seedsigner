from gettext import gettext as _
from seedsigner.helpers.l10n import mark_for_translation as _mft

from binascii import hexlify
from dataclasses import dataclass

from embit import bip32
import logging
import time

from seedsigner.models.psbt_parser import InvalidPSBTError, PSBTParser, RejectCode, RiskWarning
from seedsigner.models.settings import SettingsConstants
from seedsigner.gui.components import FontAwesomeIconConstants, GUIConstants, SeedSignerIconConstants
from seedsigner.gui.screens.screen import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    ButtonOption,
    WarningScreen,
    DireWarningScreen,
    QRDisplayScreen,
    LargeIconStatusScreen,
)
from seedsigner.views.view import BackStackView, MainMenuView, NotYetImplementedView, View, Destination
from seedsigner.hardware.microsd import MicroSD

logger = logging.getLogger(__name__)



class PSBTSelectSeedView(View):
    SCAN_SEED = ButtonOption("Scan a seed", SeedSignerIconConstants.QRCODE)
    SATOCHIP = ButtonOption("Use Satochip card", SeedSignerIconConstants.FINGERPRINT)
    KEYCARD = ButtonOption("Use Keycard", SeedSignerIconConstants.FINGERPRINT)
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

        def ensure_microsd_seed_warning() -> bool:
            if not getattr(self.controller, "psbt_from_microsd", False):
                return True
            if getattr(self.controller, "psbt_microsd_seed_warning_shown", False):
                return True
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return False
            self.controller.psbt_microsd_seed_warning_shown = True
            return True

        # Note: we can't just autoroute to the PSBT Overview because we might have a
        # multisig where we want to sign with more than one key on this device.
        if not self.controller.psbt:
            # Shouldn't be able to get here
            raise Exception("No transaction currently loaded")

        if self.controller.psbt_seed:
             if PSBTParser.has_matching_input_fingerprint(psbt=self.controller.psbt, seed=self.controller.psbt_seed, network=self.settings.get_value(SettingsConstants.SETTING__NETWORK)):
                 # skip the seed prompt if a seed was previously selected and has matching input fingerprint
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

        if (
            self.settings.get_value(SettingsConstants.SETTING__SATOCHIP_SUPPORT)
            == SettingsConstants.OPTION__ENABLED
        ):
            button_data.append(self.SATOCHIP)
        if (
            self.settings.get_value(SettingsConstants.SETTING__KEYCARD_SUPPORT)
            == SettingsConstants.OPTION__ENABLED
        ):
            button_data.append(self.KEYCARD)
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
            if getattr(self.controller, "psbt_from_microsd", False):
                self.controller.psbt_from_microsd = False
                self.controller.psbt_microsd_save_path = None
                self.controller.psbt_microsd_seed_warning_shown = False
            return Destination(BackStackView)

        if len(seeds) > 0 and selected_menu_num < len(seeds):
            # User selected one of the n seeds
            if not ensure_microsd_seed_warning():
                return Destination(PSBTSelectSeedView)
            self.controller.psbt_seed = seeds[selected_menu_num]
            return Destination(PSBTOverviewView)

        # The remaining flows are a sub-flow; resume PSBT flow once the seed is loaded.
        self.controller.resume_main_flow = Controller.FLOW__PSBT

        if button_data[selected_menu_num] == self.SCAN_SEED:
            if not ensure_microsd_seed_warning():
                return Destination(PSBTSelectSeedView)
            from seedsigner.views.scan_views import ScanSeedQRView
            return Destination(ScanSeedQRView)

        elif button_data[selected_menu_num] == self.SCAN_WIF:
            if not ensure_microsd_seed_warning():
                return Destination(PSBTSelectSeedView)
            from seedsigner.views.scan_views import ScanWIFQRView
            return Destination(ScanWIFQRView)

        elif button_data[selected_menu_num] == self.SCAN_BIP38:
            if not ensure_microsd_seed_warning():
                return Destination(PSBTSelectSeedView)
            from seedsigner.views.scan_views import ScanBIP38QRView
            return Destination(ScanBIP38QRView)

        elif button_data[selected_menu_num] in [self.SATOCHIP, self.KEYCARD]:
            from seedsigner.helpers import seedkeeper_utils
            from embit.bip32 import HDKey

            card_choice = button_data[selected_menu_num]
            if card_choice == self.KEYCARD:
                backend_preference = "keycard"
                card_label = "Keycard"
                self.controller.smartcard_backend_preference = "keycard"
            else:
                backend_preference = "pysatochip"
                card_label = "Satochip"
                self.controller.smartcard_backend_preference = "pysatochip"

            init_kwargs = {"init_card_filter": ["satochip"]}
            if backend_preference is not None:
                init_kwargs["backend_preference"] = backend_preference
            connector = seedkeeper_utils.init_satochip(self, **init_kwargs)
            if not connector:
                return Destination(PSBTSelectSeedView, clear_history=True)

            # A card with 2FA enabled cannot sign from SeedSigner (no phone-app code flow).
            if seedkeeper_utils.satochip_2fa_blocks_signing(self, connector):
                return Destination(PSBTSelectSeedView, clear_history=True)

            psbt = self.controller.psbt
            is_multisig_psbt = False
            try:
                if psbt and psbt.inputs:
                    first_input = psbt.inputs[0]
                    if first_input.witness_utxo:
                        script_pubkey = first_input.witness_utxo.script_pubkey
                    elif first_input.non_witness_utxo:
                        script_pubkey = first_input.script_pubkey
                    else:
                        script_pubkey = None

                    if script_pubkey is not None:
                        policy = PSBTParser._get_policy(first_input, script_pubkey, psbt.xpubs, None)
                        is_multisig_psbt = isinstance(policy, dict) and "m" in policy
            except Exception as exc:
                logger.debug("Unable to determine PSBT policy", exc_info=exc)

            if is_multisig_psbt:
                try:
                    parser = PSBTParser(psbt)
                    parser.parse()
                except Exception as e:
                    logger.exception("Failed to parse PSBT with %s data", card_label)
                    self.run_screen(
                        WarningScreen,
                        title="Failed",
                        status_headline=None,
                        text=str(e),
                    )
                    return Destination(PSBTSelectSeedView, clear_history=True)

                self.controller.psbt_parser = parser
                self.controller.psbt_seed = None
                self.controller.psbt_sign_with_satochip = True
                return Destination(PSBTOverviewView)

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
            loading_stopped = False
            try:
                try:
                    account_xpub = connector.card_bip32_get_xpub(account_path_str, xtype, is_mainnet)
                    master_xpub = connector.card_bip32_get_xpub("", xtype, is_mainnet)
                except Exception as e:
                    logger.exception("Failed to export xpub from %s card", card_label)
                    loading.stop()
                    loading_stopped = True
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
                except InvalidPSBTError as e:
                    # A deliberate refusal. Card signing gets the same screens as
                    # seed signing -- see REJECT_PRESENTATION.
                    logger.info("Refusing psbt from %s: %s (%s)", card_label, e, e.code)
                    self.controller.psbt_parser = None
                    self.controller.psbt_sign_with_satochip = False
                    loading.stop()
                    loading_stopped = True
                    return refusal_destination(e)
                except Exception as e:
                    logger.exception("Failed to parse PSBT with %s data", card_label)
                    loading.stop()
                    loading_stopped = True
                    self.run_screen(
                        WarningScreen,
                        title="Failed",
                        status_headline=None,
                        text=str(e),
                    )
                    return Destination(PSBTSelectSeedView, clear_history=True)

                card_fingerprints = {hexlify(master_fp).decode()}
                try:
                    card_fingerprints.add(hexlify(root_key.child(0).fingerprint).decode())
                except Exception:
                    pass

                psbt_fingerprints = set(PSBTParser.get_input_fingerprints(self.controller.psbt))
                if not card_fingerprints.intersection(psbt_fingerprints):
                    logger.warning(
                        "%s fingerprint mismatch: card %s vs psbt %s",
                        card_label,
                        sorted(card_fingerprints),
                        sorted(psbt_fingerprints),
                    )
                    self.controller.psbt_parser = None
                    self.controller.psbt_sign_with_satochip = False
                    loading.stop()
                    loading_stopped = True
                    self.run_screen(
                        WarningScreen,
                        title=_("Fingerprint mismatch"),
                        status_icon_name=SeedSignerIconConstants.WARNING,
                        status_headline=_("Card cannot sign PSBT"),
                        text=_(
                            "Card fingerprint ({}) not in PSBT signers."
                        ).format(sorted(card_fingerprints)[0]),
                    )
                    return Destination(PSBTSelectSeedView, clear_history=True)
            finally:
                if not loading_stopped:
                    loading.stop()

            self.controller.psbt_seed = None
            self.controller.psbt_sign_with_satochip = True
            return Destination(PSBTOverviewView)

        elif button_data[selected_menu_num] in [self.TYPE_12WORD, self.TYPE_15WORD, self.TYPE_18WORD, self.TYPE_21WORD, self.TYPE_24WORD]:
            if not ensure_microsd_seed_warning():
                return Destination(PSBTSelectSeedView)
            from seedsigner.views.seed_views import SeedMnemonicEntryView
            self.controller.storage.init_pending_mnemonic(num_words=button_data[selected_menu_num].return_data)
            return Destination(SeedMnemonicEntryView)

        elif button_data[selected_menu_num] == self.TYPE_ELECTRUM:
            if not ensure_microsd_seed_warning():
                return Destination(PSBTSelectSeedView)
            from seedsigner.views.seed_views import SeedElectrumMnemonicStartView
            return Destination(SeedElectrumMnemonicStartView)

        elif button_data[selected_menu_num] == self.TYPE_WIF:
            if not ensure_microsd_seed_warning():
                return Destination(PSBTSelectSeedView)
            return Destination(PSBTWIFEntryView)

        elif button_data[selected_menu_num] == self.TYPE_BIP38:
            if not ensure_microsd_seed_warning():
                return Destination(PSBTSelectSeedView)
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

@dataclass
class RejectPresentation:
    """
    How one RejectCode is shown to the user, and where the flow goes afterwards.

    Every refusal used to render as the same generic "Invalid PSBT" warning carrying
    the parser's technical message. That is still the default -- `screen` is None and
    the parser's message is the body -- but a code that deserves its own severity,
    headline, or exit route gets an entry here instead of a special case in the flow.

    * screen / title / headline / text / icon / color / button: what is drawn. `text`
      of None means "use the parser's own message", which is right where the message
      names a specific offending value and wrong where fixed prose reads better.
    * tip: appended to the message, for refusals the user can actually act on.
    * clear_psbt: whether the psbt itself is discarded. False only for
      SEED_CANNOT_SIGN, which is a seed/psbt mismatch rather than a bad psbt.
    * clear_history: whether the redirect INTO this screen wipes the back stack, so
      BACK cannot walk into a half-parsed psbt. False only where the user is meant to
      step back into the flow they came from.
    * destination_name: which View to land on once the screen is dismissed. Named as a
      string because the table sits above the Views it points at.
    """
    screen: type = None
    title: str = "Invalid PSBT"
    headline: str = None
    text: str = None
    icon: str = None
    color: str = None
    button_label: str = "Done"
    tip: str = None
    clear_psbt: bool = True
    clear_history: bool = True
    destination_name: str = "MainMenuView"


# Keyed by RejectCode. Anything absent renders with RejectPresentation() defaults, so
# adding a code to the parser never leaves the flow without a screen.
#
# Budget: the warning screen's text box fits five lines at the body font, and TextArea
# renders past the bottom edge rather than raising, so an overlong message silently
# draws over the button. Message + tip must stay within that for the longest realistic
# values AND a verbose translation. tests/test_psbt_refusal_screens.py pins this.
REJECT_PRESENTATION = {
    # TRANSLATOR_NOTE: Points the user at the setting that controls this check
    RejectCode.CHANGE_INDEX_TOO_FAR: RejectPresentation(tip=_mft("See Change Gap Limit in Settings.")),

    RejectCode.FORGED_OUTPUT_OWNERSHIP: RejectPresentation(
        screen=DireWarningScreen,
        # TRANSLATOR_NOTE: Title of the screen shown when a psbt lies about owning an output
        title=_mft("Suspicious Transaction"),
        headline=_mft("Likely an Attack!"),
        text=_mft("The transaction's change/self-transfer outputs are not going back to your wallet."),
        button_label=_mft("Discard transaction"),
    ),

    RejectCode.FORGED_INPUT_OWNERSHIP: RejectPresentation(
        screen=WarningScreen,
        # TRANSLATOR_NOTE: Title of the screen shown when a psbt misstates who owns an input
        title=_mft("Transaction Problem"),
        text=_mft("This transaction incorrectly claims that its input(s) belong to this seed."),
        button_label=_mft("Discard transaction"),
    ),

    RejectCode.SEED_CANNOT_SIGN: RejectPresentation(
        # An informational mismatch, not a warning, so it uses the neutral info icon and
        # color rather than WarningScreen's alarming yellow edges.
        # TODO: give this its own InfoScreen (LargeIconStatusScreen with the INFO icon
        # and color baked in) rather than customizing the base screen at each call site.
        screen=LargeIconStatusScreen,
        # TRANSLATOR_NOTE: Title of the screen shown when the chosen seed can't sign the psbt
        title=_mft("Seed Can't Sign"),
        text=_mft("None of the inputs in this transaction are controlled by this seed."),
        icon=SeedSignerIconConstants.INFO,
        color=GUIConstants.INFO_COLOR,
        button_label=_mft("Select a different seed"),
        # The user is choosing a different seed for this psbt, not starting over, so the
        # psbt is kept and only the seed and its parser are cleared.
        clear_psbt=False,
        clear_history=False,
        destination_name="PSBTSelectSeedView",
    ),
}



class PSBTRefusalView(View):
    """
    Renders one refused psbt, per REJECT_PRESENTATION, and routes onward.

    Reached by redirect from PSBTOverviewView, so each refusal is a real View: it can be
    screenshotted, its strings extracted for translation, and its routing asserted in a
    flow test. Subclasses below fix `code` so the named cases can be referred to
    directly.
    """
    code: str = None

    def __init__(self, code: str = None, message: str = None):
        super().__init__()
        self.code = code if code is not None else self.code
        self.message = message
        self.presentation = REJECT_PRESENTATION.get(self.code, RejectPresentation())


    def run(self):
        p = self.presentation

        if p.text is not None:
            text = _(p.text)
        else:
            # The parser's own message, which names the offending value.
            text = self.message or _("This transaction could not be verified.")
            if p.tip:
                # Single newline, not a blank line: the warning screen's text box fits
                # about five lines and a blank one costs a whole line.
                text += "\n" + _(p.tip)

        kwargs = dict(
            title=_(p.title),
            status_headline=_(p.headline) if p.headline else None,
            text=text,
            button_data=[ButtonOption(p.button_label)],
            show_back_button=False,
        )
        if p.icon:
            kwargs["status_icon_name"] = p.icon
        if p.color:
            kwargs["status_color"] = p.color

        self.run_screen(p.screen or WarningScreen, **kwargs)

        if p.clear_psbt:
            self.controller.psbt = None
        self.controller.psbt_parser = None
        self.controller.psbt_seed = None
        # Whichever signer was selected, it isn't signing this psbt.
        self.controller.psbt_sign_with_satochip = False

        # Named rather than referenced directly so the table can sit above the Views it
        # points at. test_every_reject_code_has_a_reachable_destination resolves them all.
        return Destination(globals()[p.destination_name], clear_history=True)



class PSBTOutputOwnershipClaimFailedView(PSBTRefusalView):
    """
    An output claims a key this seed does not derive -- how a fake change output is
    dressed up as the user's own. Shows a dire warning and discards the psbt.
    """
    code = RejectCode.FORGED_OUTPUT_OWNERSHIP
    DISCARD = ButtonOption("Discard transaction")



class PSBTInputOwnershipClaimFailedView(PSBTRefusalView):
    """
    An input claims a key this seed does not derive. Unsignable rather than dangerous,
    so a plain warning; the psbt is still discarded.
    """
    code = RejectCode.FORGED_INPUT_OWNERSHIP
    DISCARD = ButtonOption("Discard transaction")



class PSBTSeedCannotSignView(PSBTRefusalView):
    """
    This seed can't sign any of the psbt's inputs. Routes back to seed selection, keeping
    the psbt, so the user can pick another.
    """
    code = RejectCode.SEED_CANNOT_SIGN
    SELECT_DIFFERENT_SEED = ButtonOption("Select a different seed")


# The named subclasses above, keyed by the code each one fixes. A code without one is
# rendered by PSBTRefusalView itself; give a code its own subclass when it is worth
# naming in a flow test or a screenshot, and it lands here automatically.
REFUSAL_VIEWS = {cls.code: cls for cls in PSBTRefusalView.__subclasses__()}


def refusal_destination(error: InvalidPSBTError) -> Destination:
    """Where a refused psbt goes: the View for its code, carrying its message."""
    presentation = REJECT_PRESENTATION.get(error.code, RejectPresentation())
    return Destination(
        REFUSAL_VIEWS.get(error.code, PSBTRefusalView),
        view_args=dict(code=error.code, message=str(error)),
        # Set clear_history to disable returning via BACK button
        clear_history=presentation.clear_history,
    )



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
                from seedsigner.controller import Controller as _Controller
                self.controller.psbt_parser = PSBTParser(
                    self.controller.psbt,
                    seed=self.controller.psbt_seed,
                    network=self.settings.get_value(SettingsConstants.SETTING__NETWORK),
                    reference_time=getattr(self.controller, "psbt_source_time", None),
                    block_anchor=(_Controller.RELEASE_BLOCK_HEIGHT, _Controller.RELEASE_BLOCK_TIME),
                )
            except InvalidPSBTError as e:
                # A deliberate refusal, not a crash: the psbt is parseable but unsafe to
                # present, or not this seed's to sign. Redirect to the View that renders
                # this code -- see REJECT_PRESENTATION.
                logger.info("Refusing psbt: %s (%s)", e, e.code)
                self.set_redirect(refusal_destination(e))
                return
            finally:
                self.loading_screen.stop()


    def run(self):
        from seedsigner.gui.screens.psbt_screens import PSBTOverviewScreen

        psbt_parser = self.controller.psbt_parser

        change_data = psbt_parser.change_data
        """
            change_data = [
                {
                    'address': 'bc1q............', 
                    'amount': 397621401, 
                    'claimed_fingerprints': ['22bde1a9', '73c5da0a'], 
                    'claimed_derivation_paths': ['m/48h/1h/0h/2h/1/0', 'm/48h/1h/0h/2h/1/0']
                }, {},
            ]
        """
        num_change_outputs = 0
        num_self_transfer_outputs = 0
        for change_output in change_data:
            # PSBTParser has already rejected any derivation a wallet could not
            # scan for, so all that's left here is which branch it sits on.
            path_ints = bip32.parse_path(change_output["claimed_derivation_paths"][0])
            if PSBTParser.is_change_branch(path_ints):
                num_change_outputs += 1
            else:
                num_self_transfer_outputs += 1

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

        if psbt_parser.risk_warnings - RiskWarning.INFORMATIONAL:
            return Destination(PSBTRiskWarningView)

        # expecting p2sh (legacy multisig) and p2pkh to have no policy set
        # skip change warning and psbt math view
        if psbt_parser.policy == None:
            return Destination(PSBTUnsupportedScriptTypeWarningView)
        
        elif psbt_parser.change_amount == 0:
            return Destination(PSBTNoChangeWarningView)

        else:
            return Destination(PSBTMathView)



class PSBTRiskWarningView(View):
    """
        Everything PSBTParser flagged for review: conditions that don't make the
        transaction invalid, but that a user would not want to approve without
        being told.
    """
    # Most severe first; iteration order is the display order.
    RISK_TEXT = {
        # TRANSLATOR_NOTE: Shown when the miner fee is a large share of what's being spent
        RiskWarning.HIGH_FEE: _mft("The fee is an unusually large share of this transaction."),
        # TRANSLATOR_NOTE: The fee per byte is high compared to recent blocks.
        RiskWarning.HIGH_FEE_RATE: _mft("The fee rate is high compared to recent blocks."),
        RiskWarning.DUST_OUTPUT: _mft("One output is below the dust threshold and may be unspendable."),
        RiskWarning.FUTURE_LOCKTIME: _mft("This transaction cannot confirm until a future date."),
        # TRANSLATOR_NOTE: The transaction is locked years beyond when it was created.
        RiskWarning.LOCKTIME_FAR_FUTURE: _mft("This transaction is locked for years and cannot confirm until then."),
        # TRANSLATOR_NOTE: BIP-68 relative timelock; the delay runs from when the
        # input confirmed, so no fixed date can be shown.
        RiskWarning.RELATIVE_TIMELOCK: _mft("An input is time-locked and cannot be spent yet."),
        RiskWarning.RBF: _mft("This transaction is marked replaceable (RBF)."),
    }

    def run(self):
        psbt_parser: PSBTParser = self.controller.psbt_parser
        if not psbt_parser:
            # Should not be able to get here
            return Destination(MainMenuView)

        messages = []
        for code in self.RISK_TEXT:
            if code not in psbt_parser.risk_warnings or code in RiskWarning.INFORMATIONAL:
                continue
            messages.append(_(self.RISK_TEXT[code]))

        selected_menu_num = self.run_screen(
            WarningScreen,
            # TRANSLATOR_NOTE: Headline above a list of things to check before approving
            status_headline=_("Review Carefully!"),
            text="\n\n".join(messages),
            button_data=[ButtonOption("Continue")],
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if psbt_parser.policy == None:
            return Destination(
                PSBTUnsupportedScriptTypeWarningView,
                skip_current_view=True,  # Prevent going BACK to WarningViews
            )

        elif psbt_parser.change_amount == 0:
            return Destination(
                PSBTNoChangeWarningView,
                skip_current_view=True,  # Prevent going BACK to WarningViews
            )

        return Destination(
            PSBTMathView,
            skip_current_view=True,  # Prevent going BACK to WarningViews
        )



class PSBTUnsupportedScriptTypeWarningView(View):
    def run(self):
        selected_menu_num = self.run_screen(
            WarningScreen,
            status_headline=_("Unsupported Script Type!"),
            text=_("Transaction has unsupported input script type, please verify your change addresses."),
            button_data=[ButtonOption("Continue")],
        )
        
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
        selected_menu_num = self.run_screen(
            WarningScreen,
            # TRANSLATOR_NOTE: User will receive no change back; the inputs to this transaction are fully spent
            status_headline=_("Full Spend!"),
            text=_("This transaction spends its entire input value. No change is coming back to your wallet."),
            button_data=[ButtonOption("Continue")],
        )

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
            # An OP_RETURN carrying value is value leaving the wallet with no
            # recipient. Counting it as spend is what makes
            # inputs - spend - fee == change hold on screen; left out, the
            # burned amount silently disappears into the arithmetic.
            spend_amount=psbt_parser.spend_amount + psbt_parser.op_return_amount,
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
            button_data.append(ButtonOption("Next recipient"))
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
    SKIP_VERIFICATION = ButtonOption("Skip verification")
    VERIFY_MULTISIG = ButtonOption("Verify multisig change")

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
                'claimed_fingerprints': ['22bde1a9', '73c5da0a'], 
                'claimed_derivation_paths': ['m/48h/1h/0h/2h/1/0', 'm/48h/1h/0h/2h/1/0']
            }
        """

        # Single-sig verification is easy. We expect to find a single fingerprint
        # and derivation path.
        claimed_fingerprints = change_data.get("claimed_fingerprints") or []
        claimed_derivation_paths = change_data.get("claimed_derivation_paths") or []

        if self.controller.psbt_seed:
            seed_fingerprint = self.controller.psbt_seed.get_fingerprint(
                self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            )
        else:
            master_fp = getattr(psbt_parser, "master_fingerprint", None)
            seed_fingerprint = hexlify(master_fp).decode() if master_fp else None

        if seed_fingerprint:
            if seed_fingerprint not in claimed_fingerprints:
                # TODO: Something is wrong with this psbt(?). Reroute to warning?
                return Destination(NotYetImplementedView)
            index = claimed_fingerprints.index(seed_fingerprint)
        else:
            index = 0 if claimed_fingerprints else None
            if index is not None:
                seed_fingerprint = claimed_fingerprints[index]

        claimed_derivation_path = ""
        if index is not None and index < len(claimed_derivation_paths):
            claimed_derivation_path = claimed_derivation_paths[index]

        # 'm/84h/1h/0h/1/0' would be a change addr while 'm/84h/1h/0h/0/0' is a self-receive.
        # Safe to read from the claim here: PSBTParser has already refused any path whose
        # prefix does not match one the inputs demonstrate, so an output that reaches this
        # point sits where this wallet actually keeps its keys.
        if claimed_derivation_path:
            path_ints = bip32.parse_path(claimed_derivation_path)
        else:
            path_ints = []
        is_change_derivation_path = PSBTParser.is_change_branch(path_ints)
        derivation_path_addr_index = path_ints[-1] & 0x7FFFFFFF if path_ints else 0

        if is_change_derivation_path:
            # TRANSLATOR_NOTE: The amount you're receiving back from the transaction
            title = _("Your Change")
        else:
            title = _("Self-Transfer")
            self.VERIFY_MULTISIG.button_label = _("Verify multisig addr")
        # if psbt_parser.num_change_outputs > 1:
        #     title += f" (#{self.change_address_num + 1})"

        is_change_addr_verified = False
        if psbt_parser.is_multisig:
            print("isMultisig")
            # if the known-good multisig descriptor is already onboard:
            if self.controller.multisig_wallet_descriptor:
                is_change_addr_verified = psbt_parser.verify_multisig_output(
                    self.controller.multisig_wallet_descriptor,
                    change_num=self.change_address_num,
                )
                if not is_change_addr_verified:
                    self.controller.multisig_wallet_descriptor = None
                    self.run_screen(
                        WarningScreen,
                        title=_("Descriptor mismatch"),
                        status_icon_name=SeedSignerIconConstants.WARNING,
                        status_headline=_("Descriptor cleared"),
                        text=_(
                            "Loaded multisig wallet descriptor does not match this PSBT. "
                            "Load the correct descriptor or skip verification to continue."
                        ),
                        show_back_button=False,
                        button_data=[ButtonOption(_("OK"))],
                    )
                    return Destination(
                        PSBTChangeDetailsView,
                        view_args={"change_address_num": self.change_address_num},
                        skip_current_view=True,
                    )

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
            fingerprint=seed_fingerprint or "",
            derivation_path=claimed_derivation_path or "",
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
    """
    Reached when a change or self-transfer output fails address verification. Shows a dire
    warning and discards the psbt to the main menu.
    """
    def __init__(self, is_change: bool = True, is_multisig: bool = False):
        super().__init__()
        self.is_change = is_change
        self.is_multisig = is_multisig


    def run(self):
        if self.is_multisig:
            # TRANSLATOR_NOTE: Variable is either "change" or "self-transfer".
            text = _("Transaction's {} address could not be verified from wallet descriptor.").format(_("change") if self.is_change else _("self-transfer"))
        else:
            # TRANSLATOR_NOTE: Variable is either "change" or "self-transfer".
            text = _("Transaction's {} address could not be generated from your seed.").format(_("change") if self.is_change else _("self-transfer"))
        
        self.run_screen(
            DireWarningScreen,
            title=_("Suspicious Transaction"),
            status_headline=_("Address Verification Failed"),
            text=text,
            button_data=[ButtonOption("Discard transaction")],
            show_back_button=False,
        )

        # We're done with this PSBT. Route back to MainMenuView, which clears all ephemeral
        # data (except in-memory seeds).
        # Set clear_history to disable returning via BACK button.
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
    APPROVE_PSBT = ButtonOption("Approve transaction")


    @staticmethod
    def _locktime_text(psbt_parser: PSBTParser) -> str:
        """
        A one-line, human-readable nLockTime for the approval screen, or None
        when no locktime is actually in force.

        nLockTime comes in two encodings and only one of them was ever visible.
        A timestamp locktime is compared against the clock and warned about; a
        block-height locktime was not checked at all, so an attacker who wanted a
        long lock simply used the height form and nothing was shown. Both forms
        delay confirmation identically, so both are stated here.

        Heights are converted to an approximate date rather than displayed raw:
        "locked until block 1,000,000" is not something a user can act on without
        knowing the current tip, which the device does not have. The conversion
        anchors on Controller.RELEASE_BLOCK_HEIGHT and assumes 10-minute blocks.

        This states rather than judges. The device has no RTC, so it cannot tell
        whether a date is in the future, and a stale anchor means the estimate can
        drift. A user making a payment today can tell that "~Mar 2031" is wrong;
        a heuristic with no trustworthy clock cannot.
        """
        from seedsigner.controller import Controller
        from seedsigner.models.psbt_parser import LOCKTIME_TIMESTAMP_THRESHOLD

        if psbt_parser is None or not psbt_parser.locktime_is_enforced:
            # Consensus ignores nLockTime unless some input is non-final.
            return None

        locktime = psbt_parser.locktime
        if not locktime:
            return None

        if locktime >= LOCKTIME_TIMESTAMP_THRESHOLD:
            # Already a unix timestamp; no estimation needed.
            when = time.gmtime(locktime)
            exact = True
        else:
            estimated = (
                Controller.RELEASE_BLOCK_TIME
                + (locktime - Controller.RELEASE_BLOCK_HEIGHT) * Controller.SECONDS_PER_BLOCK
            )
            if estimated <= 0:
                return None
            when = time.gmtime(estimated)
            exact = False

        stamp = time.strftime("%b %Y", when)
        if exact:
            # TRANSLATOR_NOTE: Inserts a month and year, e.g. "Locked until Mar 2031"
            return _("Locked until {}").format(stamp)
        # TRANSLATOR_NOTE: Inserts an approximate month and year derived from a
        # block height, e.g. "Locked until ~Mar 2031"
        return _("Locked until ~{}").format(stamp)


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
            button_data=[self.APPROVE_PSBT],
            # Informational, so it never blocked the flow and was therefore never
            # shown at all. State it on the approval screen instead.
            is_rbf=(psbt_parser is not None
                    and RiskWarning.RBF in psbt_parser.risk_warnings),
            locktime_text=self._locktime_text(psbt_parser),
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        sig_cnt = PSBTParser.sig_count(psbt)
        logger.info(
            "PSBTFinalize: approve selected; signer_mode=%s initial_sig_count=%d inputs=%d",
            "card" if self.controller.psbt_sign_with_satochip else "seed",
            sig_cnt,
            len(getattr(psbt, "inputs", []) or []),
        )

        connector = None
        if self.controller.psbt_sign_with_satochip:
            from seedsigner.helpers import seedkeeper_utils
            connector = seedkeeper_utils.init_satochip(self, init_card_filter=["satochip"])
            if not connector:
                logger.info("PSBTFinalize: card connector init failed; returning to finalize screen")
                return Destination(PSBTFinalizeView)
            logger.info(
                "PSBTFinalize: card connector ready backend=%s card_type=%s uid=%s",
                "keycard" if getattr(connector, "is_keycard_backend", False) else "pysatochip",
                getattr(connector, "card_type", "unknown"),
                getattr(connector, "UID_SHA1", "unknown"),
            )

        from seedsigner.gui.screens.screen import LoadingScreenThread
        loading = LoadingScreenThread(text=_("Signing PSBT..."))
        loading.start()
        try:
            sign_result = None
            if self.controller.psbt_sign_with_satochip:
                is_keycard = getattr(connector, "is_keycard_backend", False)
                # Track retry state on the controller so we can increase timeout across retries
                retry_timeout = getattr(self.controller, "_psbt_sign_retry_timeout", None)
                if is_keycard:
                    from seedsigner.helpers.keycard_signer import sign_psbt_with_keycard
                    sign_result = sign_psbt_with_keycard(psbt, connector, timeout=retry_timeout)
                else:
                    from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip
                    sign_result = sign_psbt_with_satochip(psbt, connector, timeout=retry_timeout)
                added = sign_result.signed_count
                logger.info(
                    "PSBTFinalize: card signer reported signed=%d timed_out=%s",
                    added, sign_result.timed_out,
                )
            else:
                psbt.sign_with(psbt_parser.root)
            if isinstance(self.controller.psbt_seed, WIFKey):
                tx = finalize_psbt(psbt)
                self.controller.signed_tx_hex = tx.serialize().hex() if tx else None
                logger.info(
                    "PSBTFinalize: WIF finalize result tx_present=%s hex_len=%s",
                    tx is not None,
                    len(self.controller.signed_tx_hex) if self.controller.signed_tx_hex else 0,
                )
            else:
                self.controller.signed_tx_hex = None

            trimmed_psbt = PSBTParser.trim(psbt)
            trimmed_sig_cnt = PSBTParser.sig_count(trimmed_psbt)
            logger.info(
                "PSBTFinalize: post-sign trimmed_sig_count=%d delta=%d",
                trimmed_sig_cnt,
                trimmed_sig_cnt - sig_cnt,
            )

            try:
                tx_preview = finalize_psbt(trimmed_psbt)
                logger.info(
                    "PSBTFinalize: finalize_psbt(trimmed) tx_present=%s",
                    tx_preview is not None,
                )
            except Exception as e:
                logger.info("PSBTFinalize: finalize_psbt(trimmed) raised=%s", e)
        except Exception:
            if self.controller.psbt_sign_with_satochip:
                logger.exception("Failed to sign PSBT with Satochip")
                return Destination(PSBTFinalizeView)
            raise
        finally:
            loading.stop()

        if sig_cnt == PSBTParser.sig_count(trimmed_psbt):
            logger.info(
                "PSBTFinalize: no new signatures detected; routing=%s",
                "PSBTFinalizeView" if self.controller.psbt_sign_with_satochip else "PSBTSigningErrorView",
            )
            # Clean up retry state regardless of path taken
            if hasattr(self.controller, "_psbt_sign_retry_timeout"):
                delattr(self.controller, "_psbt_sign_retry_timeout")

            if self.controller.psbt_sign_with_satochip:
                # If a timeout occurred during signing, offer to retry with higher timeout
                if sign_result and sign_result.timed_out:
                    is_keycard = getattr(connector, "is_keycard_backend", False)
                    current_timeout = (
                        self.settings.get_value(SettingsConstants.SETTING__KEYCARD_SIGN_TIMEOUT)
                        if is_keycard
                        else self.settings.get_value(SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT)
                    )
                    card_label = "Keycard" if is_keycard else "Satochip"

                    selected = self.run_screen(
                        WarningScreen,
                        title=_("Signing Timeout"),
                        status_headline=None,
                        text=(
                            f"{card_label} signing timed out at {current_timeout}s.\n\n"
                            "Retry with a higher timeout?"
                        ),
                        button_data=[ButtonOption("Retry (higher timeout)"), ButtonOption("Cancel")],
                    )

                    if selected == 0:
                        # Increase timeout by one step and retry
                        new_timeout = current_timeout + 0.75
                        self.controller._psbt_sign_retry_timeout = new_timeout
                        logger.info(
                            "PSBTFinalize: user chose to retry with timeout=%.2fs", new_timeout
                        )
                        return Destination(PSBTFinalizeView)

                return Destination(PSBTFinalizeView)
            return Destination(PSBTSigningErrorView)

        logger.info("PSBTFinalize: signatures added; routing=PSBTSignedQRDisplayView")
        self.controller.psbt = trimmed_psbt
        self.controller.psbt_sign_with_satochip = False
        return Destination(PSBTSignedQRDisplayView)



class PSBTSignedQRDisplayView(View):
    def run(self):
        from seedsigner.models.encode_qr import UrPsbtQrEncoder, GenericStringEncoder
        from seedsigner.models.wif import WIFKey
        from seedsigner.gui.screens.screen import LoadingScreenThread

        save_path = getattr(self.controller, "psbt_microsd_save_path", None)
        if save_path:
            signed_path = save_path.with_name(save_path.name + ".signed")
            try:
                signed_path.parent.mkdir(parents=True, exist_ok=True)
                signed_path.write_bytes(self.controller.psbt.serialize())
                try:
                    display_path = str(signed_path.relative_to(MicroSD.get_microsd_dir()))
                except ValueError:
                    display_path = signed_path.name
                self.run_screen(
                    LargeIconStatusScreen,
                    title=_("Success"),
                    status_headline=None,
                    text=_("Saved as {}.").format(display_path),
                    show_back_button=False,
                    button_data=[ButtonOption(_("Continue"))],
                )
            except Exception as e:
                logger.exception("Failed to save signed PSBT", exc_info=e)
                self.run_screen(
                    WarningScreen,
                    title=_("Error"),
                    status_headline=None,
                    text=_("Failed to save PSBT: {}").format(str(e)),
                    show_back_button=False,
                    button_data=[ButtonOption(_("OK"))],
                )
            finally:
                self.controller.psbt_microsd_save_path = None
                self.controller.psbt_from_microsd = False
                self.controller.psbt_microsd_seed_warning_shown = False

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
    SELECT_DIFF_SEED = ButtonOption("Select different seed")
    
    def run(self):
        psbt_parser: PSBTParser = self.controller.psbt_parser
        if not psbt_parser:
            # Should not be able to get here
            return Destination(MainMenuView)

        # Just a WarningScreen here; only use DireWarningScreen for true security risks.
        selected_menu_num = self.run_screen(
            WarningScreen,
            title=_("Transaction Error"),
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
