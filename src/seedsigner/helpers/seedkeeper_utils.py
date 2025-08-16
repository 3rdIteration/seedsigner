from pysatochip.CardConnector import CardConnector
from pysatochip.JCconstants import (
    JCconstants,
    SEEDKEEPER_DIC_TYPE,
    SEEDKEEPER_DIC_ORIGIN,
    SEEDKEEPER_DIC_EXPORT_RIGHTS,
)
from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    WarningScreen,
    DireWarningScreen,
    seed_screens,
    LargeIconStatusScreen,
    KeyboardScreen,
)
from seedsigner.gui.screens.screen import LoadingScreenThread
from seedsigner.helpers.iso7816 import format_sw_error


import os
import time
from os import urandom
import platform
import logging

logger = logging.getLogger(__name__)


def prompt_for_pin(parent_view, title: str):
    """Prompt for a PIN and enforce length requirements."""

    while True:
        ret = seed_screens.SeedAddPassphraseScreen(title=title).display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return None

        pin_str = ret.get("passphrase", "")
        if JCconstants.PIN_MIN_SIZE <= len(pin_str) <= JCconstants.PIN_MAX_SIZE:
            return pin_str

        parent_view.run_screen(
            WarningScreen,
            title="Invalid PIN",
            status_headline=None,
            text=f"PIN must be between {JCconstants.PIN_MIN_SIZE} and {JCconstants.PIN_MAX_SIZE} characters.",
            show_back_button=True,
        )


def init_satochip(parentObject, init_card_filter=None, require_pin=True):
    from seedsigner.models.settings import (
        Settings,
        SettingsConstants,
        SettingsDefinition,
    )

    # Check for existing card connector
    print("Checking existing card connector...")
    try:
        if parentObject.controller.Satochip_Connector is not None:
            print("Found existing connector, try to use it...")
            parentObject.controller.Satochip_Connector.card_get_label()

            print("Found Card:", Satochip_Connector.UID_SHA1)
            print("Expecting Card:", parentObject.controller.Satochip_Last_UID_SHA1)

            # If the card connector is still good, we will get to this line :)
            return parentObject.controller.Satochip_Connector
    except:
        parentObject.controller.Satochip_Connector = None

    try:
        if parentObject.controller.Satochip_Connector is None:
            print("No Working CardConnector, Connecting")
            print("Card Filter:", init_card_filter)
            Satochip_Connector = CardConnector(card_filter=init_card_filter)
    except Exception as e:
        parentObject.run_screen(
            WarningScreen,
            title="Failure",
            status_headline=None,
            text=str(e),
            show_back_button=True,
        )
        return None

    if require_pin:
        # Prompt for pin if one hasn't been set, otherwise a cached pin will be used
        if parentObject.controller.Satochip_PIN is None:
            print("No Cached pin, prompting for pin")
            pin_str = prompt_for_pin(parentObject, "Card PIN")
            if pin_str is None:
                return None
            card_pin = list(pin_str.encode("utf-8"))
        else:
            card_pin = parentObject.controller.Satochip_PIN

    parentObject.loading_screen = LoadingScreenThread(text="Connecting to Card")
    parentObject.loading_screen.start()

    # Spam connecting for 5 seconds to give the user time to insert the card
    status = None
    time_end = time.time() + 5

    while time.time() < time_end:
        try:

            time.sleep(0.5)  # give some time to initialize reader...
            status = Satochip_Connector.card_get_status()
            print("Found Card:", Satochip_Connector.UID_SHA1)
            print(status[3])

            if Satochip_Connector.needs_secure_channel:
                print("Initiating Secure Channel")
                Satochip_Connector.card_initiate_secure_channel()
                print("Secure Channel Initialised")

            if (
                len(status[3]) > 0
            ):  # Sometimes it's possible to end up with an invalid of zero length here...
                break

        except Exception as e:
            print("CardConnector Init Failed:" + str(e))
            time.sleep(0.1)  # Sleep for 100ms

        status = None  # Reset this every loop...

    parentObject.loading_screen.stop()

    if not status:
        filter_txt = ""
        if init_card_filter:
            if isinstance(init_card_filter, (list, tuple)):
                filter_str = ", ".join(init_card_filter)
            else:
                filter_str = str(init_card_filter)

        parentObject.run_screen(
            WarningScreen,
            title="Unable to Connect",
            status_headline=None,
            text=f"Unable to find {filter_str} \n(or Applet)\n\nTry Re-Inserting Card",
            show_back_button=True,
        )
        return None

    # Check if the Seedkeeper needs the initial setup process
    if status[3]["setup_done"]:

        if require_pin:
            # Check for an existing Seedkeeper card that we may have been using with this PIN,
            # prompt to re-enter pin if the card has been swapped...
            if (
                parentObject.controller.Satochip_Last_UID_SHA1 is not None
                and parentObject.controller.Satochip_Last_UID_SHA1
                != Satochip_Connector.UID_SHA1
            ):
                print("Found Card:", Satochip_Connector.UID_SHA1)
                print("Expecting Card:", parentObject.controller.Satochip_Last_UID_SHA1)
                print("Card has changed, prompting for new PIN")
                pin_str = prompt_for_pin(parentObject, "Card PIN")
                if pin_str is None:
                    return None
                card_pin = list(pin_str.encode("utf-8"))
            print("Same card, using existing PIN, already loaded...")

            # Check PIN
            Satochip_Connector.set_pin(0, card_pin)

            try:
                parentObject.loading_screen = LoadingScreenThread(text="Verifying PIN")
                parentObject.loading_screen.start()

                print("Verifying PIN")
                (response, sw1, sw2) = Satochip_Connector.card_verify_PIN()

                parentObject.loading_screen.stop()

                if sw1 == 0x90 and sw2 == 0x00:
                    print("Pin Correct")
                    pass  # Pin is correct
                else:
                    parentObject.run_screen(
                        WarningScreen,
                        title="Failure",
                        status_headline=None,
                        text=format_sw_error(sw1, sw2),
                        show_back_button=True,
                    )
                    return None

            # Any number of things could have gone wrong, so just report the error and return none...
            except Exception as e:
                parentObject.loading_screen.stop()
                time.sleep(0.1)  # Sleep for 100ms
                logger.exception("Pin check failed")

                parentObject.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text=str(e)[:100],
                    show_back_button=True,
                )
                return None

    else:
        print("Card Needs Initial Setup")
        parentObject.run_screen(
            WarningScreen,
            title="Card Uninitialised",
            status_headline=None,
            text=f"Set a device PIN to complete Card Setup",
            show_back_button=True,
        )

        pin_str = prompt_for_pin(parentObject, "New Card PIN")

        if pin_str is None:
            return None

        """Run the initial card setup process"""
        pin_0 = list(pin_str.encode("utf8"))
        # Allow configurable PIN attempt limit
        pin_tries_0 = Settings.get_instance().get_value(
            SettingsConstants.SETTING__SCARD_PIN_ATTEMPTS
        )
        ublk_tries_0 = 0x01
        # PUK code can be used when PIN is unknown and the card is locked
        # We use a random value as the PUK is not used currently and is not user friendly
        ublk_0 = list(urandom(16))
        pin_tries_1 = 0x01
        ublk_tries_1 = 0x01
        pin_1 = list(urandom(16))  # the second pin is not used currently
        ublk_1 = list(urandom(16))
        secmemsize = 32  # 0x0000 # => for satochip - TODO: hardcode value?
        memsize = 0x0000  # RFU
        create_object_ACL = 0x01  # RFU
        create_key_ACL = 0x01  # RFU
        create_pin_ACL = 0x01  # RFU

        (response, sw1, sw2) = Satochip_Connector.card_setup(
            pin_tries_0,
            ublk_tries_0,
            pin_0,
            ublk_0,
            pin_tries_1,
            ublk_tries_1,
            pin_1,
            ublk_1,
            secmemsize,
            memsize,
            create_object_ACL,
            create_key_ACL,
            create_pin_ACL,
            option_flags=0,
            hmacsha160_key=None,
            amount_limit=0,
        )
        if sw1 != 0x90 or sw2 != 0x00:
            print("ERROR: Setup Failed")
            parentObject.run_screen(
                WarningScreen,
                title="Invalid PIN",
                status_headline=None,
                text=format_sw_error(sw1, sw2),
                show_back_button=True,
            )
            return None
        else:
            Satochip_Connector.set_pin(0, pin_0)
            print("Setup Succeeded")
            parentObject.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Card Setup Complete",
                show_back_button=False,
            )
            # Save the PIN for the newly set up card...
            card_pin = pin_0

    # Everything works, so save object and also note the PIN & UID of the card we last successfully connected to...
    parentObject.controller.Satochip_Connector = Satochip_Connector
    parentObject.controller.Satochip_Last_UID_SHA1 = Satochip_Connector.UID_SHA1

    # Only cache pin if we are using it
    if require_pin:
        parentObject.controller.Satochip_PIN = card_pin

    return parentObject.controller.Satochip_Connector


def run_globalplatform(
    parentObject, command, loadingText="Loading", successtext="Success"
):
    from subprocess import run
    from seedsigner.models.settings import (
        Settings,
        SettingsConstants,
        SettingsDefinition,
    )

    parentObject.loading_screen = LoadingScreenThread(text=loadingText)
    parentObject.loading_screen.start()

    if platform.uname()[1] == "seedsigner-os":
        commandString = (
            "/mnt/diy/jdk/bin/java -jar /mnt/diy/Satochip-DIY/gp.jar " + command
        )
    else:
        commandString = "java -jar /home/pi/Satochip-DIY/gp.jar " + command

    data = run(commandString, capture_output=True, shell=True, text=True)

    # This process often kills IFD-NFC, so restart it if required
    scinterface = parentObject.settings.get_value(
        SettingsConstants.SETTING__SMARTCARD_INTERFACES
    )
    if "pn532" in scinterface:
        os.system("ifdnfc-activate no")
        time.sleep(1)
        os.system("ifdnfc-activate yes")

    parentObject.loading_screen.stop()

    print("StdOut:", data.stdout)
    print("StdErr:", data.stderr)

    # data.stderr = data.stderr.replace("Warning: no keys given, defaulting to 404142434445464748494A4B4C4D4E4F", "")

    data.stderr = data.stderr.split("\n")

    errors_cleaned = []
    for errorLine in data.stderr:
        if "[INFO]" in errorLine:
            continue
        elif "404142434445464748494A4B4C4D4E4F" in errorLine:
            continue
        elif len(errorLine) < 1:
            continue

        errors_cleaned.append(errorLine)

    print("StdErr (Cleaned):", errors_cleaned)

    errors_cleaned = " ".join(errors_cleaned)

    if len(errors_cleaned) > 1:
        uninstall_required = False

        # If it fails, report the error back (And make it more human readable for common errors)
        failureText = errors_cleaned
        if "is not present on card" in errors_cleaned:
            failureText = "Applet is not on the card, nothing to uninstall."

        elif "Multiple readers, must choose one" in errors_cleaned:
            failureText = "Multiple readers connected, please run with a single reader connected/activated."

        elif "Card cryptogram invalid" in errors_cleaned:
            failureText = "Card is locked (DO NOT RETRY, may BRICK card). Refer to Satochip-DIY documentation."

        elif "SCARD_E_NO_SMARTCARD" in errors_cleaned:
            failureText = "Unable to detect Card and/or Reader."

        elif "Applet loading not allowed" in errors_cleaned:
            failureText = "Applet is already installed."

        elif "0x6444" in errors_cleaned or "0x6F00" in errors_cleaned:
            failureText = "Incompatible Javacard."
            uninstall_required = True

        elif "Not enough memory space" in errors_cleaned:
            failureText = "Not enough space on Javacard for Applet..."

        elif "SCARD_E_NO_SMARTCARD" in errors_cleaned:
            failureText = "Unable to detect Card and/or Reader..."

        elif "SCARD_E_NOT_TRANSACTED" in errors_cleaned:
            failureText = "Applet installation failed, perhaps try with a different Smartcard Interface..."
            uninstall_required = True

        elif (
            "Failed to open secure channel" in errors_cleaned
            or "SCARD_W_RESET_CARD" in errors_cleaned
        ):
            failureText = "Unable to complete secure connection... (App or reader may need restart)"

        logger.error(failureText)
        parentObject.run_screen(
            WarningScreen,
            title="Failed",
            status_headline=None,
            text=failureText[:100],
            show_back_button=False,
        )

        if uninstall_required:
            command = command.replace("--install", "--uninstall")
            data = run_globalplatform(
                parentObject,
                command,
                loadingText="Uninstalling",
                successtext="Mis-Installed Applet Uninstalled",
            )
            if data is None:
                msg = "Mis-Installed Applet Uninstalled, try uninstalling it again..."
                logger.error(msg)
                parentObject.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text=msg,
                    show_back_button=False,
                )
        return None

    else:
        if successtext:
            print(successtext)
            parentObject.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=successtext,
                show_back_button=False,
            )

        return data.stdout
