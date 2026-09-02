from pysatochip.JCconstants import (
    JCconstants,
    SEEDKEEPER_DIC_TYPE,
    SEEDKEEPER_DIC_ORIGIN,
    SEEDKEEPER_DIC_EXPORT_RIGHTS,
)
from pysatochip.CardConnector import UnexpectedSW12Error
from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    WarningScreen,
    DireWarningScreen,
    seed_screens,
    LargeIconStatusScreen,
    KeyboardScreen,
)
from seedsigner.gui.screens.screen import ButtonOption, LoadingScreenThread
from seedsigner.helpers.iso7816 import format_sw_error
from seedsigner.helpers.keycard_connector import KeycardSatochipConnector


import os
import re
import time
from gettext import gettext as _
from os import urandom
import platform
import logging

logger = logging.getLogger(__name__)


def _decode_attempts_from_sw(sw1: int, sw2: int) -> int | None:
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        return sw2 & 0x0F
    return None


def get_pin_attempts_left(connector=None, sw1: int | None = None, sw2: int | None = None) -> int | None:
    attempts = None
    if sw1 is not None and sw2 is not None:
        attempts = _decode_attempts_from_sw(sw1, sw2)
        if attempts is not None:
            return attempts

    if connector is None:
        return None

    try:
        _r, _a, _b, status = connector.card_get_status()
    except Exception:
        return None

    pin_tries = status.get("PIN0_remaining_tries")
    if isinstance(pin_tries, int):
        return pin_tries
    return None


def show_incorrect_pin_warning(parent_view, connector=None, sw1: int | None = None, sw2: int | None = None) -> None:
    attempts_left = get_pin_attempts_left(connector=connector, sw1=sw1, sw2=sw2)
    if attempts_left is not None:
        attempt_word = "attempt" if attempts_left == 1 else "attempts"
        text = f"PIN is incorrect.\n{attempts_left} {attempt_word} remaining."
    else:
        text = "PIN is incorrect."

    parent_view.run_screen(
        WarningScreen,
        title="Incorrect PIN",
        status_headline=None,
        text=text,
        show_back_button=True,
    )


def _requested_satochip_flow(init_card_filter) -> bool:
    if init_card_filter is None:
        return False
    values = init_card_filter
    if not isinstance(values, (list, tuple, set)):
        values = [values]
    return any(str(v).lower() == "satochip" for v in values)


def _init_legacy_connector(init_card_filter):
    from pysatochip.CardConnector import CardConnector

    connector = CardConnector(card_filter=init_card_filter)
    # The CardConnector uses a background thread to establish the card
    # connection.  Without a delay the thread may not have run yet, so
    # card_get_status() would return before actually trying to talk to the
    # card and the probe below would not detect wrong-card-type errors.
    # 0.6 s matches the 0.5 s sleep in the outer retry loop that the
    # pysatochip authors themselves found necessary for reader initialisation.
    time.sleep(0.6)
    # Probe: throws (e.g. "Card Initialization must be satisfied") when the
    # inserted card is not a Satochip.  The caller catches this and falls
    # back to the keycard-compat backend.
    connector.card_get_status()
    return connector


def _init_card_connector(init_card_filter, backend_preference: str | None = None):
    """Create the most appropriate connector for the requested card flow.

    Selection is controlled by ``SEEDSIGNER_SMARTCARD_BACKEND``:
    - ``auto`` (default): try pysatochip first, then keycard for satochip flows
    - ``pysatochip``: force legacy backend
    - ``keycard``: force keycard compat backend (satochip flow only)
    """

    backend_pref = (backend_preference or os.environ.get("SEEDSIGNER_SMARTCARD_BACKEND", "auto")).strip().lower()
    keycard_allowed = _requested_satochip_flow(init_card_filter)

    if backend_pref == "keycard":
        if not keycard_allowed:
            # Stale preference from a previous Keycard flow; fall back to auto
            # instead of crashing (e.g. user does Keycard benchmark then loads
            # from SeedKeeper, where the card filter is ["seedkeeper"]).
            logger.info(
                "Backend pref 'keycard' incompatible with card filter %s; falling back to auto",
                init_card_filter,
            )
            backend_pref = "auto"
        else:
            return KeycardSatochipConnector.create(card_filter=init_card_filter)

    if backend_pref == "pysatochip":
        return _init_legacy_connector(init_card_filter)

    # auto backend
    try:
        return _init_legacy_connector(init_card_filter)
    except Exception as legacy_error:
        if not keycard_allowed:
            raise legacy_error
        try:
            logger.info("pysatochip init failed; trying keycard compat backend")
            return KeycardSatochipConnector.create(card_filter=init_card_filter)
        except Exception:
            raise legacy_error


def calculate_seedkeeper_secret_size(secret_dic: dict) -> int:
    """Estimate the number of bytes the secret will occupy on the Seedkeeper.

    The Seedkeeper stores both the secret header (including the automatically
    assigned id) and an AES-padded copy of the secret payload. This helper
    mirrors :func:`CardConnector.seedkeeper_import_secret`'s padding behaviour
    so that we can compare the required storage with the remaining free space
    reported by the card before attempting an import.
    """

    header_hex = secret_dic.get("header")
    if not header_hex:
        raise ValueError("Secret dictionary missing Seedkeeper header data")

    try:
        header_length = len(bytes.fromhex(header_hex))
    except ValueError as exc:
        raise ValueError("Invalid Seedkeeper header encoding") from exc

    if "secret_list" in secret_dic and secret_dic["secret_list"] is not None:
        secret_length = len(secret_dic["secret_list"])
        # Seedkeeper always pads to the next 16 byte boundary, even when the
        # plaintext length already aligns with the block size.
        padding = 16 - (secret_length % 16)
        if padding == 0:
            padding = 16
        padded_secret_length = secret_length + padding
    elif "secret_encrypted" in secret_dic and secret_dic["secret_encrypted"] is not None:
        padded_secret_length = len(bytes.fromhex(secret_dic["secret_encrypted"]))
    else:
        raise ValueError("Secret dictionary missing Seedkeeper secret data")

    return header_length + padded_secret_length


def get_seedkeeper_free_memory(connector) -> int:
    """Return the free memory (in bytes) currently reported by the Seedkeeper."""

    _, _, _, status = connector.seedkeeper_get_status()
    free_memory = status.get("free_memory")
    if free_memory is None:
        raise ValueError("Seedkeeper did not report available memory")
    return free_memory


def ensure_seedkeeper_capacity(connector, secret_dic: dict, free_memory: int | None = None):
    """Check whether the Seedkeeper has enough space for the provided secret.

    Returns a tuple ``(fits, required_bytes, available_bytes)``. When
    ``free_memory`` is ``None`` the helper will query the Seedkeeper for the
    latest free space value, otherwise the supplied ``free_memory`` will be used
    for the comparison.

    Some (older DIY) Seedkeeper applets do not implement the seedkeeper status
    command (INS 0xA7) and answer 0x6D00 ("instruction not supported") instead of
    reporting free space.  In that case capacity cannot be pre-checked, so treat
    the import as fitting and let the card surface its own out-of-memory error
    (0x9C01) during the actual import, rather than blocking every write.
    """

    required_bytes = calculate_seedkeeper_secret_size(secret_dic)
    available_bytes = free_memory
    if available_bytes is None:
        try:
            available_bytes = get_seedkeeper_free_memory(connector)
        except UnexpectedSW12Error as exc:
            status_word = sw_from_exception(exc)
            # Only an "unsupported instruction" answer means the capacity is
            # genuinely unknowable. Anything else is a real failure and must not
            # be silently reinterpreted as "assume it fits". A status word we
            # cannot parse stays lenient so that #413-style cards keep working.
            if status_word is not None and status_word not in (0x6D00, 0x6E00, 0x9C05):
                raise
            logger.warning(
                "Seedkeeper status unsupported (%s); skipping capacity pre-check",
                f"{status_word:#06x}" if status_word is not None else "unknown status word",
            )
            available_bytes = None

    if available_bytes is None:
        # Capacity cannot be determined (0x6D00); assume it fits so the write
        # proceeds and the card can reject it with its own memory error.
        return True, required_bytes, None

    return required_bytes <= available_bytes, required_bytes, available_bytes


def format_seedkeeper_space_error(required_bytes: int, free_bytes: int) -> str:
    """Return a human-readable message describing a space shortfall."""

    return (
        "Not enough space on Seedkeeper\n"
        f"Requires {required_bytes} bytes\n"
        f"{free_bytes} bytes free"
    )


# Matches the status word pysatochip embeds in its exception messages, e.g.
# "Unexpected error during secure secret import (error code 0x9c01)".
_SW_IN_MESSAGE_RE = re.compile(r"error code[:\s]*0x([0-9a-fA-F]{1,4})")


def sw_from_exception(exc) -> int | None:
    """Best-effort recovery of the status word behind a pysatochip exception.

    ``UnexpectedSW12Error`` defaults ``sw1``/``sw2`` to ``0x00``, and the
    SeedKeeper helpers we rely on (``seedkeeper_import_secret``,
    ``seedkeeper_get_status``, ``seedkeeper_reset_secret``) all raise it
    *without* passing them.  Any ``exc.sw1``/``exc.sw2`` branch on those paths
    is therefore dead code.  Prefer the attributes when they carry a real value
    and otherwise fall back to the status word embedded in the message text.

    Returns the 16-bit status word, or ``None`` when it cannot be determined.
    """

    sw1 = getattr(exc, "sw1", 0) or 0
    sw2 = getattr(exc, "sw2", 0) or 0
    status_word = (sw1 << 8) | sw2
    if status_word:
        return status_word

    match = _SW_IN_MESSAGE_RE.search(str(exc))
    if match:
        return int(match.group(1), 16)
    return None


def is_seedkeeper_v1(connector) -> bool | None:
    """Return True for a v1 SeedKeeper applet, False for newer, None if unknown.

    v1 applets refuse two instructions we depend on, by different means:
    ``seedkeeper_get_status`` (INS 0xA7) is not implemented at all and answers
    0x6D00, while ``seedkeeper_reset_secret`` (INS 0xA5) exists but throws
    SW_UNSUPPORTED_FEATURE (0x9C05) straight after its PIN check — so a v1 card
    can never free space, and a full one needs a factory reset. Both codes land
    in the same "unsupported" bucket in :func:`describe_seedkeeper_error`.

    ``card_get_status`` (INS 0x3C) does work on v1, so it is safe to probe here.
    Note the discriminator is the *protocol* version: v0.1 and v0.2 applets both
    report applet version 0.1, and differ only in protocol minor version.
    """

    try:
        status = connector.card_get_status()[3]
        return status.get("protocol_minor_version") == 1
    except Exception:  # pragma: no cover - defensive, card may have gone away
        logger.debug("Could not determine Seedkeeper applet version", exc_info=True)
        return None


def describe_seedkeeper_error(exc, connector=None, fallback: str | None = None) -> str:
    """Return a user-facing message for a failed Seedkeeper card operation.

    Handles the codes the SeedKeeper applet actually returns.  Most importantly
    0x9C01 (``SW_NO_MEMORY_LEFT``), which is how a full card rejects an import;
    on a v1 applet that is terminal, because v1 cannot delete secrets.
    """

    status_word = sw_from_exception(exc)

    if status_word == 0x9C01:
        if connector is not None and is_seedkeeper_v1(connector):
            # v1 has no reset-secret instruction, so freeing space is impossible.
            return _("Not enough space on Seedkeeper\nCard memory is full\n\n"
                     "Seedkeeper v1 cannot delete secrets. A factory reset is required.")
        return _("Not enough space on Seedkeeper\nCard memory is full\n\n"
                 "Delete a secret to free space.")

    if status_word in (0x6D00, 0x6E00, 0x9C05):
        return _("Not supported by this Seedkeeper applet") + f"\n({status_word:#06x})"

    if status_word is not None:
        return format_sw_error(status_word >> 8, status_word & 0xFF)

    return fallback or str(exc)


def prompt_for_pin(
    parent_view,
    title: str,
    *,
    numeric_only: bool = False,
    exact_length: int | None = None,
):
    """Prompt for a PIN and enforce configurable PIN requirements."""

    _KEYBOARD_DIGITS = "123"  # Matches SeedAddPassphraseScreen.KEYBOARD__DIGITS_BUTTON_TEXT
    initial_kb = _KEYBOARD_DIGITS if numeric_only else None
    while True:
        ret = seed_screens.SeedAddPassphraseScreen(
            title=title,
            initial_keyboard=initial_kb,
        ).display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return None

        pin_str = ret.get("passphrase", "")
        if numeric_only and not all(ch in "0123456789" for ch in pin_str):
            parent_view.run_screen(
                WarningScreen,
                title="Invalid PIN",
                status_headline=None,
                text="PIN must contain digits only.",
                show_back_button=True,
            )
            continue

        if exact_length is not None:
            if len(pin_str) == exact_length:
                return pin_str
            parent_view.run_screen(
                WarningScreen,
                title="Invalid PIN",
                status_headline=None,
                text=f"PIN must be exactly {exact_length} digits.",
                show_back_button=True,
            )
            continue

        if JCconstants.PIN_MIN_SIZE <= len(pin_str) <= JCconstants.PIN_MAX_SIZE:
            return pin_str

        parent_view.run_screen(
            WarningScreen,
            title="Invalid PIN",
            status_headline=None,
            text=f"PIN must be between {JCconstants.PIN_MIN_SIZE} and {JCconstants.PIN_MAX_SIZE} characters.",
            show_back_button=True,
        )


def prompt_for_new_pin(
    parent_view,
    title: str,
    *,
    numeric_only: bool = False,
    exact_length: int | None = None,
    confirm_title: str | None = None,
):
    """Prompt for a new PIN and require the user to re-enter it to confirm."""

    while True:
        pin_str = prompt_for_pin(
            parent_view,
            title,
            numeric_only=numeric_only,
            exact_length=exact_length,
        )
        if pin_str is None:
            return None

        confirm_str = prompt_for_pin(
            parent_view,
            confirm_title or f"Confirm {title}",
            numeric_only=numeric_only,
            exact_length=exact_length,
        )
        if confirm_str is None:
            return None

        if pin_str == confirm_str:
            return pin_str

        parent_view.run_screen(
            WarningScreen,
            title="PIN Mismatch",
            status_headline=None,
            text="PINs did not match.\nPlease try again.",
            show_back_button=True,
        )


def disconnect_smartcard_connections(controller):
    """Ensure no other smartcard connectors are holding the reader."""
    try:
        conn = getattr(controller, "Satochip_Connector", None)
        if conn:
            try:
                conn.card_disconnect()
            except Exception:
                pass
    finally:
        try:
            controller.Satochip_Connector = None
        except Exception:
            pass

    # Ensure gpg's smartcard daemon releases the reader as well
    try:
        from subprocess import run
        run(["gpgconf", "--kill", "scdaemon"], check=False)
        # Immediately relaunch so external tools can detect the card
        run(["gpgconf", "--launch", "scdaemon"], check=False)
    except Exception:
        pass


def init_satochip(parentObject, init_card_filter=None, require_pin=True, backend_preference: str | None = None, allow_unseeded: bool = False):
    from seedsigner.models.settings import (
        Settings,
        SettingsConstants,
        SettingsDefinition,
    )

    # Check for existing card connector
    print("Checking existing card connector...")
    Satochip_Connector = getattr(parentObject.controller, "Satochip_Connector", None)
    controller_backend_pref = backend_preference
    if controller_backend_pref is None:
        controller_backend_pref = getattr(parentObject.controller, "smartcard_backend_preference", None)

    # If a specific applet/card filter is requested, do not reuse an existing
    # connector that may still be attached to a previous flow/card type.
    # Rebuild the connector with the requested filter to avoid stale state.
    if Satochip_Connector is not None and init_card_filter:
        try:
            Satochip_Connector.card_disconnect()
        except Exception:
            pass
        parentObject.controller.Satochip_Connector = None
        Satochip_Connector = None

    if Satochip_Connector is not None:
        try:
            print("Found existing connector, try to use it...")
            Satochip_Connector.card_get_label()
            print("Found Card:", Satochip_Connector.UID_SHA1)
            print(
                "Expecting Card:",
                getattr(parentObject.controller, "Satochip_Last_UID_SHA1", None),
            )
        except Exception:
            parentObject.controller.Satochip_Connector = None
            Satochip_Connector = None

    try:
        if Satochip_Connector is None:
            print("No Working CardConnector, Connecting")
            print("Card Filter:", init_card_filter)
            print("Backend Preference:", controller_backend_pref or "auto")
            Satochip_Connector = _init_card_connector(
                init_card_filter,
                backend_preference=controller_backend_pref,
            )
            print(
                "Card Backend:",
                "keycard" if getattr(Satochip_Connector, "is_keycard_backend", False) else "pysatochip",
            )
    except Exception as e:
        parentObject.run_screen(
            WarningScreen,
            title="Failure",
            status_headline=None,
            text="No smartcard detected\n\nInsert a card and try again.",
            show_back_button=True,
        )
        return None

    is_keycard_backend = getattr(Satochip_Connector, "is_keycard_backend", False)

    if require_pin:
        # Prompt for pin if one hasn't been set, otherwise a cached pin will be used
        if parentObject.controller.Satochip_PIN is None:
            print("No Cached pin, prompting for pin")
            pin_str = prompt_for_pin(
                parentObject,
                "Card PIN",
                numeric_only=is_keycard_backend,
                exact_length=6 if is_keycard_backend else None,
            )
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
            else:
                # Cleanup the connector and try again
                try:
                    Satochip_Connector.card_disconnect()
                except Exception:
                    pass

        except Exception as e:
            print("CardConnector Init Failed:" + str(e))
            # Ensure the connector state is clean before trying again
            try:
                Satochip_Connector.card_disconnect()
            except Exception:
                pass
            time.sleep(0.1)  # Sleep for 100ms

        status = None  # Reset this every loop...

    parentObject.loading_screen.stop()

    if not status:
        # If we never connected, ensure the connector is reset for future attempts
        try:
            Satochip_Connector.card_disconnect()
        except Exception:
            pass
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
                pin_str = prompt_for_pin(
                    parentObject,
                    "Card PIN",
                    numeric_only=is_keycard_backend,
                    exact_length=6 if is_keycard_backend else None,
                )
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
                elif sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
                    show_incorrect_pin_warning(
                        parentObject,
                        connector=Satochip_Connector,
                        sw1=sw1,
                        sw2=sw2,
                    )
                    return None
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

                # clear any cached PIN as it's obviously wrong and was mistakenly cached somewhere...
                # (This can happen when the card UID is incorrectly read which happens sometimes)
                try:
                    parentObject.controller.Satochip_PIN = None
                except:
                    pass

                parentObject.run_screen(
                    WarningScreen,
                    title="Failed",
                    status_headline=None,
                    text=str(e)[:100],
                    show_back_button=True,
                )
                return None

    else:
        if getattr(Satochip_Connector, "is_keycard_backend", False):
            # In keycard flows that allow unseeded cards (e.g. "Initialise with
            # Seed"), continue into the generic setup path below so a factory-
            # fresh card can be initialized in-app before importing a seed.
            if not allow_unseeded:
                parentObject.run_screen(
                    WarningScreen,
                    title="Card Uninitialised",
                    status_headline=None,
                    text="Initialize Keycard first\nusing keycard-cli.",
                    show_back_button=True,
                )
                return None

        print("Card Needs Initial Setup")
        parentObject.run_screen(
            WarningScreen,
            title="Card Uninitialised",
            status_headline=None,
            text=f"Set a device PIN to complete Card Setup",
            show_back_button=True,
        )

        pin_str = prompt_for_new_pin(
            parentObject,
            "New Card PIN",
            numeric_only=is_keycard_backend,
            exact_length=6 if is_keycard_backend else None,
            confirm_title="Confirm Card PIN",
        )

        if pin_str is None:
            return None

        duress_pin_str = None
        if is_keycard_backend:
            # Keycard applet v3.1+: an optional duress PIN unlocks a decoy
            # wallet. It can only be set now — the applet does not allow
            # adding or changing it after initialization.
            selected = parentObject.run_screen(
                WarningScreen,
                title="Duress PIN?",
                status_headline=None,
                text="Optional decoy-wallet PIN.\nCannot be added later.",
                show_back_button=False,
                button_data=[ButtonOption("Set Duress PIN"), ButtonOption("Skip")],
            )
            if selected == 0:
                while True:
                    duress_pin_str = prompt_for_new_pin(
                        parentObject,
                        "Duress PIN",
                        numeric_only=True,
                        exact_length=6,
                        confirm_title="Confirm Duress PIN",
                    )
                    if duress_pin_str is None:
                        return None
                    if duress_pin_str != pin_str:
                        break
                    parentObject.run_screen(
                        WarningScreen,
                        title="Invalid PIN",
                        status_headline=None,
                        text="Duress PIN must differ\nfrom the main PIN.",
                        show_back_button=True,
                    )

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

        setup_kwargs = {}
        if duress_pin_str:
            # Only the keycard backend understands the duress PIN.
            setup_kwargs["duress_pin"] = duress_pin_str

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
            **setup_kwargs,
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
                title="Card Setup",
                status_headline=None,
                text="PIN set. Import seed next.",
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


def restart_pn532(scinterface):
    """Restart the PN532 NFC reader (Linux/Raspberry Pi only)"""
    from subprocess import run
    import time
    import sys
    if "pn532" in scinterface and sys.platform.startswith('linux'):
        try:
            run(["ifdnfc-activate", "no"], check=False, timeout=5)
            time.sleep(1)
            run(["ifdnfc-activate", "yes"], check=False, timeout=5)
        except Exception:
            pass  # Silently ignore errors on platforms where this tool isn't available

def pygp_format_error(e):
    err_str = str(e)
    if "is not present on card" in err_str:
        return "Applet is not on the card, nothing to uninstall."
    elif "Multiple readers, must choose one" in err_str:
        return "Multiple readers connected, please run with a single reader connected/activated."
    elif "Card cryptogram invalid" in err_str or "verification of the card cryptogram failed" in err_str.lower() or "Referenced data not found" in err_str:
        return "Wrong key. Repeated wrong tries can brick the card."
    elif "SCARD_E_NO_SMARTCARD" in err_str:
        return "Unable to detect Card and/or Reader."
    elif "Applet loading not allowed" in err_str:
        return "Applet is already installed."
    elif "0x6444" in err_str or "0x6F00" in err_str:
        return "Incompatible Javacard."
    elif "Not enough memory space" in err_str:
        return "Not enough space on Javacard for Applet..."
    elif "SCARD_E_NOT_TRANSACTED" in err_str:
        return "Applet installation failed, perhaps try with a different Smartcard Interface..."
    elif "Failed to open secure channel" in err_str or "SCARD_W_RESET_CARD" in err_str:
        return "Unable to complete secure connection... (App or reader may need restart)"
    return err_str