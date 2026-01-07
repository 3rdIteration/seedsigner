import logging
from gettext import gettext as _

#from seedsigner.gui.screens import (RET_CODE__BACK_BUTTON, ButtonListScreen, WarningScreen, settings_screens)

from seedsigner.gui.components import GUIConstants, SeedSignerIconConstants
from seedsigner.gui.screens import (RET_CODE__BACK_BUTTON, ButtonListScreen, WarningScreen, settings_screens)
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.settings import Settings, SettingsConstants, SettingsDefinition

from .view import View, Destination, MainMenuView, BackStackView

logger = logging.getLogger(__name__)



class SettingsMenuView(View):
    ADVANCED = ButtonOption("Advanced", right_icon_name=SeedSignerIconConstants.CHEVRON_RIGHT)
    HARDWARE = ButtonOption("Hardware", right_icon_name=SeedSignerIconConstants.CHEVRON_RIGHT)
    IO_TEST = ButtonOption("I/O test")
    SCARD_TEST = ButtonOption("Test Smartcard")
    LIST_READERS = ButtonOption("List card readers")
    NFC_TEST = ButtonOption("Test NFC Scan")
    DONATE = ButtonOption("Donate")
    RESTART_PCSC = ButtonOption("Restart PCSC")
    BATTERY_INFO = ButtonOption("Battery info")

    def __init__(self, visibility: str = SettingsConstants.VISIBILITY__GENERAL, selected_attr: str = None, initial_scroll: int = 0):
        super().__init__()
        self.visibility = visibility
        self.selected_attr = selected_attr

        # Used to preserve the rendering position in the list
        self.initial_scroll = initial_scroll


    def run(self):
        settings_entries = SettingsDefinition.get_settings_entries(
            visibility=self.visibility
        )
        button_data: list[ButtonOption] = [ButtonOption(e.display_name) for e in settings_entries]

        advanced_destination = None
        hardware_destination = None

        selected_button = 0
        if self.selected_attr:
            for i, entry in enumerate(settings_entries):
                if entry.attr_name == self.selected_attr:
                    selected_button = i
                    break

        if self.visibility == SettingsConstants.VISIBILITY__GENERAL:
            title = _("Settings")

            # Set up the next nested level of menuing
            button_data.append(self.ADVANCED)
            button_data.append(self.HARDWARE)
            advanced_destination = Destination(
                SettingsMenuView,
                view_args={"visibility": SettingsConstants.VISIBILITY__ADVANCED},
            )
            hardware_destination = Destination(
                SettingsMenuView,
                view_args={"visibility": SettingsConstants.VISIBILITY__HARDWARE},
            )

            if self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED:
                button_data.append(self.RESTART_PCSC)
            button_data.append(self.DONATE)

        elif self.visibility == SettingsConstants.VISIBILITY__ADVANCED:
            title = _("Advanced")

            # The hardware options nest below "Advanced"
            button_data.append(self.HARDWARE)
            hardware_destination = Destination(
                SettingsMenuView,
                view_args={"visibility": SettingsConstants.VISIBILITY__HARDWARE},
            )

        elif self.visibility == SettingsConstants.VISIBILITY__HARDWARE:
            title = "Hardware"
            from seedsigner.hardware.battery_hat import BatteryHat
            if BatteryHat.get_instance().detect_hat():
                button_data.append(self.BATTERY_INFO)
            button_data.append(self.IO_TEST)
            if self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_SUPPORT) == SettingsConstants.OPTION__ENABLED:
                button_data.append(self.LIST_READERS)
                button_data.append(self.SCARD_TEST)
                button_data.append(self.NFC_TEST)

        elif self.visibility == SettingsConstants.VISIBILITY__DEVELOPER:
            title = _("Dev Options")

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title=title,
            is_button_text_centered=False,
            button_data=button_data,
            selected_button=selected_button,
            scroll_y_initial_offset=self.initial_scroll,
        )

        # Preserve our scroll position in this Screen so we can return
        initial_scroll = self.screen.buttons[0].scroll_y

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            if self.visibility == SettingsConstants.VISIBILITY__GENERAL:
                return Destination(MainMenuView)
            elif self.visibility == SettingsConstants.VISIBILITY__ADVANCED:
                return Destination(SettingsMenuView)
            elif self.visibility == SettingsConstants.VISIBILITY__HARDWARE:
                return Destination(SettingsMenuView)
            else:
                return Destination(SettingsMenuView, view_args={"visibility": SettingsConstants.VISIBILITY__ADVANCED})
        
        if button_data[selected_menu_num] == self.ADVANCED:
            return advanced_destination

        elif button_data[selected_menu_num] == self.HARDWARE:
            return hardware_destination

        elif button_data[selected_menu_num] == self.IO_TEST:
            return Destination(IOTestView)
        
        elif button_data[selected_menu_num] == self.SCARD_TEST:
            return Destination(SCARDTestView)

        elif button_data[selected_menu_num] == self.LIST_READERS:
            return Destination(SCardReaderTestView)

        elif button_data[selected_menu_num] == self.NFC_TEST:
            return Destination(NFCTestView)

        elif button_data[selected_menu_num] == self.RESTART_PCSC:
            return Destination(RestartPCSCView)

        elif button_data[selected_menu_num] == self.DONATE:
            return Destination(DonateView)

        elif button_data[selected_menu_num] == self.BATTERY_INFO:
            return Destination(BatteryInfoView)

        elif settings_entries[selected_menu_num].attr_name == SettingsConstants.SETTING__ENCRYPTION_ITER:
            return Destination(SettingPBKDF2IterationsView, view_args=dict(attr_name=settings_entries[selected_menu_num].attr_name, parent_initial_scroll=initial_scroll))

        elif settings_entries[selected_menu_num].attr_name == SettingsConstants.SETTING__LOCALE:
            return Destination(LocaleSelectionView)

        else:
            return Destination(SettingsEntryUpdateSelectionView, view_args=dict(attr_name=settings_entries[selected_menu_num].attr_name, parent_initial_scroll=initial_scroll))



class SettingPBKDF2IterationsView(View):
    def __init__(self, attr_name: str, parent_initial_scroll: int = 0):
        super().__init__()
        self.settings_entry = SettingsDefinition.get_settings_entry(attr_name)
        self.initial_scroll = parent_initial_scroll
        self.initial_value  = str(self.settings.get_value(self.settings_entry.attr_name))

    def run(self):
        ret_value = settings_screens.SettingPBFDK2IterationsScreen(initial_value=self.initial_value).display()

        if ret_value == RET_CODE__BACK_BUTTON:
            return Destination(SettingsMenuView)

        elif not 1 <= int(ret_value) <= 50:
            WarningScreen(
                title="PBKDF2 Iterations Error",
                show_back_button=False,
                status_headline=f"out of range",
                text=f"Value must be between 1 and 50",
                button_data=[ButtonOption("Try Again")]
            ).display()

            return Destination(
                SettingPBKDF2IterationsView,
                view_args=dict(attr_name=self.settings_entry.attr_name, parent_initial_scroll=self.initial_scroll),
                skip_current_view=True
            )

        self.settings.set_value(
            attr_name=self.settings_entry.attr_name,
            value = int(ret_value)
        )

        return Destination(
            SettingsMenuView,
            view_args={
                "visibility": self.settings_entry.visibility,
                "selected_attr": self.settings_entry.attr_name,
                "initial_scroll": self.initial_scroll,
            }
        )

class LocaleSelectionView(View):
    def run(self):
        cur_language_code = self.settings.get_value(SettingsConstants.SETTING__LOCALE)

        selected_button = 0
        button_data: list[ButtonOption] = []
        for i, (language_code, display_name) in enumerate(SettingsConstants.get_detected_languages()):
            button_data.append(
                # Unique to this View: override each button's font so we can display each
                # language name in its native script.
                ButtonOption(
                    button_label=display_name,
                    return_data=language_code,
                    font_name=GUIConstants.get_button_font_name(language_code),
                    font_size=GUIConstants.get_button_font_size(language_code),
                )
            )

            if language_code == cur_language_code:
                # Highlight the current selection
                selected_button = i

        selected_menu_num = self.run_screen(
            settings_screens.SettingsEntryUpdateSelectionScreen,
            display_name=_(SettingsDefinition.get_settings_entry(attr_name=SettingsConstants.SETTING__LOCALE).display_name),
            button_data=button_data,
            selected_button=selected_button,
            checked_buttons=[selected_button],
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(SettingsMenuView)

        # Set the new language
        self.settings.set_value(SettingsConstants.SETTING__LOCALE, button_data[selected_menu_num].return_data)

        return Destination(SettingsMenuView)



class SettingsEntryUpdateSelectionView(View):
    """
        Handles changes to all selection-type settings (Multiselect, SELECT_1,
        Enabled/Disabled, etc).
    """
    def __init__(self, attr_name: str, parent_initial_scroll: int = 0, selected_button: int = None):
        super().__init__()
        self.settings_entry = SettingsDefinition.get_settings_entry(attr_name)
        self.selected_button = selected_button
        self.parent_initial_scroll = parent_initial_scroll


    def run(self):
        initial_value = self.settings.get_value(self.settings_entry.attr_name)
        button_data: list[ButtonOption] = []
        checked_buttons: list[int] = []

        if not self.settings_entry.selection_options:
            # Fallback for environments where no choices are available (e.g. no
            # cameras detected). Provide a single placeholder option so the
            # screen can render without triggering an IndexError.
            button_data.append(ButtonOption(_("No options available")))
            self.selected_button = 0
        else:
            for i, value in enumerate(self.settings_entry.selection_options):
                if type(value) == tuple:
                    value, display_name = value
                else:
                    display_name = value
                button_data.append(ButtonOption(display_name))

                if (type(initial_value) == list and value in initial_value) or value == initial_value:
                    checked_buttons.append(i)

                    if self.selected_button is None:
                        # Highlight the selection (for multiselect highlight the first
                        # selected option).
                        self.selected_button = i

            if self.selected_button is None:
                self.selected_button = 0
            
        ret_value = self.run_screen(
            settings_screens.SettingsEntryUpdateSelectionScreen,
            display_name=self.settings_entry.display_name,
            help_text=self.settings_entry.help_text,
            button_data=button_data,
            selected_button=self.selected_button,
            checked_buttons=checked_buttons,
            settings_entry_type=self.settings_entry.type,
        )

        destination = None
        settings_menu_view_destination = Destination(
            SettingsMenuView,
            view_args={
                "visibility": self.settings_entry.visibility,
                "selected_attr": self.settings_entry.attr_name,
                "initial_scroll": self.parent_initial_scroll,
            }
        )

        if ret_value == RET_CODE__BACK_BUTTON:
            return settings_menu_view_destination

        value = self.settings_entry.get_selection_option_value(ret_value)

        if self.settings_entry.type == SettingsConstants.TYPE__FREE_ENTRY:
            updated_value = ret_value
            destination = settings_menu_view_destination

        elif self.settings_entry.type == SettingsConstants.TYPE__MULTISELECT:
            updated_value = list(initial_value)
            if ret_value not in checked_buttons:
                # This is a new selection to add
                updated_value.append(value)
            else:
                # This is a de-select to remove
                updated_value.remove(value)

        else:
            # All other types are single selects (e.g. Enabled/Disabled, SELECT_1)
            if value == initial_value:
                # No change, return to menu
                return settings_menu_view_destination
            else:
                updated_value = value

        self.settings.set_value(
            attr_name=self.settings_entry.attr_name,
            value=updated_value
        )

        if self.settings_entry.attr_name == SettingsConstants.SETTING__DISPLAY_CONFIGURATION:
            self.renderer.initialize_display()

        elif self.settings_entry.attr_name == SettingsConstants.SETTING__DISPLAY_COLOR_INVERTED:
            self.renderer.disp.invert(enabled=updated_value == SettingsConstants.OPTION__ENABLED)

        if destination:
            return destination

        # All selects stay in place; re-initialize where in the list we left off
        self.selected_button = ret_value

        return Destination(SettingsEntryUpdateSelectionView, view_args=dict(attr_name=self.settings_entry.attr_name, parent_initial_scroll=self.parent_initial_scroll, selected_button=self.selected_button), skip_current_view=True)



class SettingsIngestSettingsQRView(View):
    def __init__(self, data: str):
        from seedsigner.hardware.microsd import MicroSD
        super().__init__()

        # May raise an Exception which will bubble up to the Controller to display to the
        # user.
        self.config_name, settings_update_dict = Settings.parse_settingsqr(data)

        changes_display_driver = (
            SettingsConstants.SETTING__DISPLAY_CONFIGURATION in settings_update_dict and
            self.settings.get_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION) != settings_update_dict[SettingsConstants.SETTING__DISPLAY_CONFIGURATION])
            
        self.settings.update(settings_update_dict)

        if changes_display_driver:
            self.renderer.initialize_display()

        if MicroSD.get_instance().is_inserted and self.settings.get_value(SettingsConstants.SETTING__PERSISTENT_SETTINGS) == SettingsConstants.OPTION__ENABLED:
            self.status_message = _("Persistent Settings enabled. Settings saved to SD card.")
        else:
            self.status_message = _("Settings updated in temporary memory")


    def run(self):
        from seedsigner.gui.screens.settings_screens import SettingsQRConfirmationScreen
        self.run_screen(
            SettingsQRConfirmationScreen,
            title=_("Settings QR"),
            config_name=self.config_name,
            status_message=self.status_message,
        )

        # Only one exit point
        return Destination(MainMenuView)



"""****************************************************************************
    Misc
****************************************************************************"""
class IOTestView(View):
    def run(self):
        self.run_screen(settings_screens.IOTestScreen)

        return Destination(SettingsMenuView)


class SCardReaderTestView(View):
    def run(self):
        from seedsigner.gui.screens import (RET_CODE__BACK_BUTTON, ButtonListScreen, WarningScreen, DireWarningScreen, seed_screens, LargeIconStatusScreen)
        from smartcard.System import readers
        from smartcard.Exceptions import ListReadersException
        from smartcard.pcsc.PCSCExceptions import EstablishContextException

        try:

            available_readers = readers()
            
            if available_readers:
                available_readers_text = '\n'.join(str(item)[:-5] for item in available_readers)

                print(available_readers_text)
                self.run_screen(
                        LargeIconStatusScreen,
                        title="Found Readers:",
                        status_headline=None,
                        text=available_readers_text,
                        show_back_button=False,
                )
            else:
                self.run_screen(
                        WarningScreen,
                        title="Failure",
                        status_headline=None,
                        text=f"No Smartcard readers found...",
                        show_back_button=True,
                    )
                return Destination(BackStackView)
            
        except ListReadersException:
            self.run_screen(
                    WarningScreen,
                    title="PCSC Failure",
                    status_headline=None,
                    text=f"Unable to list readers (A restart may help, possibly faulty reader)",
                    show_back_button=True,
                )
            return Destination(BackStackView)

        except EstablishContextException:
            self.run_screen(
                    WarningScreen,
                    title="PCSC Failure",
                    status_headline=None,
                    text=f"Unable to establish PCSC context(A restart may help, possibly faulty reader)",
                    show_back_button=True,
                )
            return Destination(BackStackView)
        
        return Destination(BackStackView)

class SCARDTestView(View):
    def run(self):
        
        from seedsigner.gui.screens.screen import LoadingScreenThread
        import os
        import time
        from seedsigner.gui.screens import (RET_CODE__BACK_BUTTON, ButtonListScreen, WarningScreen, DireWarningScreen, seed_screens, LargeIconStatusScreen)

        self.loading_screen = LoadingScreenThread(text="Scanning for Smart Card")
        self.loading_screen.start()

        from smartcard.CardType import ATRCardType
        from smartcard.CardRequest import CardRequest
        from smartcard.util import toHexString, toBytes
        from smartcard.CardType import AnyCardType
        from smartcard.Exceptions import CardRequestTimeoutException, ListReadersException
        from smartcard.pcsc.PCSCExceptions import EstablishContextException

        try:
            cardservice = None
            for attempt in range(5):
                try:
                    cardrequest = CardRequest(timeout=2, cardType=AnyCardType())
                    cardservice = cardrequest.waitforcard()
                    break
                except CardRequestTimeoutException:
                    if attempt < 4:
                        time.sleep(0.5)

            if cardservice is None:
                raise CardRequestTimeoutException("No Smartcard detected after retries")

            self.loading_screen.stop()

            cardservice.connection.connect()
            card_atr = toHexString(cardservice.connection.getATR())

            self.run_screen(
                    LargeIconStatusScreen,
                    title="Found SmartCard",
                    status_headline=None,
                    text=card_atr,
                    show_back_button=False,
                )
        except ListReadersException:
            self.loading_screen.stop()
            self.run_screen(
                    WarningScreen,
                    title="PCSC Failure",
                    status_headline=None,
                    text=f"Unable to list readers (A restart may help, possibly faulty reader)",
                    show_back_button=True,
                )
            return Destination(BackStackView)
        
        except EstablishContextException:
            self.loading_screen.stop()
            self.run_screen(
                    WarningScreen,
                    title="PCSC Failure",
                    status_headline=None,
                    text=f"Unable to establish PCSC context(A restart may help, possibly faulty reader)",
                    show_back_button=True,
                )
            return Destination(BackStackView)
        
        except CardRequestTimeoutException:
            self.loading_screen.stop()
            self.run_screen(
                    WarningScreen,
                    title="Failure",
                    status_headline=None,
                    text=f"No Smartcard detected...",
                    show_back_button=True,
                )
            return Destination(BackStackView)
        
        return Destination(BackStackView)

class NFCTestView(View):
    def run(self):
        
        from seedsigner.gui.screens.screen import LoadingScreenThread
        import os
        import time
        from seedsigner.gui.screens import (RET_CODE__BACK_BUTTON, ButtonListScreen, WarningScreen, DireWarningScreen, seed_screens, LargeIconStatusScreen)

        self.loading_screen = LoadingScreenThread(text="Scanning for NFC Tag")
        self.loading_screen.start()

        os.system("ifdnfc-activate no") # Need to disable IFD-NFC to be able to scan using libnfc-bindings...

        time.sleep(0.2) #Just give the loading screen a chance to load before moving on...

        import nfc
        import binascii

        context = nfc.init()
        nfcdevice = nfc.open(context)
        if nfcdevice is None:
            self.loading_screen.stop()
            print('ERROR: Unable to open NFC device.')
            self.run_screen(
                WarningScreen,
                title="NFC Failure",
                status_headline=None,
                text=f"ERROR: Unable to open NFC device. \n(May not be connected)",
                show_back_button=True,
            )
            return Destination(BackStackView)
            
        if nfc.initiator_init(nfcdevice) < 0:
            self.loading_screen.stop()
            print('ERROR: Unable to init NFC device.')
            self.run_screen(
                WarningScreen,
                title="NFC Failure",
                status_headline=None,
                text=f"ERROR: Unable to init NFC device.",
                show_back_button=True,
            )
            return Destination(BackStackView)

        print('NFC reader: %s opened' % nfc.device_get_name(nfcdevice))

        nfcmodulation = nfc.modulation()
        nfcmodulation.nmt = nfc.NMT_ISO14443A
        nfcmodulation.nbr = nfc.NBR_847 #Test at the highest baud rate for the best simulation of Smartcard operation

        nt = nfc.target()

        # Scan for 15 seconds
        ret = nfc.initiator_poll_target(nfcdevice, nfcmodulation, 1, 100, 1, nt)

        self.loading_screen.stop()

        if ret and nt.nti.nai.szUidLen:

            print('The following (NFC) ISO14443A tag was found:')
            print('    ATQA (SENS_RES): ', end='')
            nfc.print_hex(nt.nti.nai.abtAtqa, 2)
            id = 1
            if nt.nti.nai.abtUid[0] == 8:
                id = 3
            print('       UID (NFCID%d): ' % id , end='')
            nfc.print_hex(nt.nti.nai.abtUid, nt.nti.nai.szUidLen)
            foundtext="UID:\n" + binascii.hexlify(nt.nti.nai.abtUid).decode()[:14]

            print('      SAK (SEL_RES): ', end='')
            print(nt.nti.nai.btSak)
            if nt.nti.nai.szAtsLen:
                print('          ATS (ATR): ', end='')
                nfc.print_hex(nt.nti.nai.abtAts, nt.nti.nai.szAtsLen)
                foundtext = foundtext + "\nATR:\n" + binascii.hexlify(nt.nti.nai.abtAts).decode()[:28]

            self.run_screen(
                LargeIconStatusScreen,
                title="Found NFC Tag",
                status_headline=None,
                text=foundtext,
                show_back_button=False,
            )
        elif ret:
            print('Warning: IFD-NFC Conflict.')
            self.run_screen(
                WarningScreen,
                title="NFC Conflict",
                status_headline=None,
                text=f"Can't scan when IFD-NFC Active",
                show_back_button=True,
            )
        else:
            print('Warning: No NFC Tag Detected.')
            self.run_screen(
                WarningScreen,
                title="Warning",
                status_headline=None,
                text=f"Warning: No NFC Tag Detected.",
                show_back_button=True,
            )

        nfc.close(nfcdevice)
        nfc.exit(context)

        scinterface = self.settings.get_value(SettingsConstants.SETTING__SMARTCARD_INTERFACES)

        if "pn532" in scinterface:
            os.system("ifdnfc-activate yes") # Need to re-enable IFD-NFC if required...
        
        return Destination(MainMenuView)

class RestartPCSCView(View):
    def run(self):
        from seedsigner.gui.screens.screen import LoadingScreenThread
        import os
        import time
        # Restart PCSC (Just do this all the time if anything has changed)
        self.loading_screen = LoadingScreenThread(text="Restarting PCSC")
        self.loading_screen.start()
        print(self.settings.HOSTNAME)
        if self.settings.HOSTNAME == "seedsigner-os":
            os.system("/etc/init.d/S01pcscd stop")
            time.sleep(1)
            os.system("/etc/init.d/S01pcscd start")
        else:
            os.system("sudo service pcscd stop")
            time.sleep(1)
            os.system("sudo service pcscd start")

        # Drop and recreate the PC/SC context so pyscard can see readers again
        try:
            from smartcard.pcsc import PCSCContext

            pcsc_ctx = PCSCContext.instance()
            try:
                pcsc_ctx.releaseContext()
            except Exception:
                # Context may already be invalid
                pass
            pcsc_ctx.establishContext()
        except Exception:
            # Older pyscard versions don't expose PCSCContext; fall back to the
            # lower-level scard bindings.
            try:
                from smartcard.scard import (
                    SCardEstablishContext,
                    SCardReleaseContext,
                    SCARD_SCOPE_USER,
                    SCARD_S_SUCCESS,
                )

                hresult, hcontext = SCardEstablishContext(SCARD_SCOPE_USER)
                if hresult == SCARD_S_SUCCESS:
                    SCardReleaseContext(hcontext)
                    SCardEstablishContext(SCARD_SCOPE_USER)
            except Exception as e:
                print(f"Failed to reset pyscard context: {e}")
        # Drop any cached smartcard connections; restarting pcscd invalidates
        # existing handles and they must be recreated. Otherwise, subsequent
        # smartcard operations will continue to fail until the app is restarted.
        try:
            if getattr(self.controller, "Satochip_Connector", None):
                try:
                    self.controller.Satochip_Connector.card_disconnect()
                except Exception:
                    pass  # Ignore errors if already disconnected
                self.controller.Satochip_Connector = None
        except Exception:
            # Controller may not be available in some contexts
            pass

        self.loading_screen.stop()

        return Destination(SettingsMenuView)

class DonateView(View):
    def run(self):
        self.run_screen(settings_screens.DonateScreen)

        return Destination(SettingsMenuView)


class BatteryInfoView(View):
    def run(self):
        self.run_screen(settings_screens.BatteryInfoScreen)

        return Destination(SettingsMenuView, view_args={"visibility": SettingsConstants.VISIBILITY__HARDWARE})
