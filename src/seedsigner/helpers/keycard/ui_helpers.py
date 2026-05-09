"""Shared helpers for the Tools > Keycard view layer.

These functions used to be private methods inside ``views/keycard_views.py``;
they live here so that test code and any future card-specific UI (e.g. an
alternate JavaCard applet) can reuse the exact same input/wipe/path logic
without depending on ``keycard_views`` (which carries view-only side
effects).

Threat model recap (see also ``AGENTS.md`` > Ethereum + Keycard):
- PINs and pairing passwords live only in mutable ``bytearray`` objects
  for the duration of one APDU exchange. ``wipe_bytearray()`` zeros them
  on the way out. Wiping is best-effort -- Python's GC and CPython's
  string interning prevent ironclad guarantees.
- The pairing key is the only secret cached in memory across an
  operation; it lives on ``Controller.keycard_pairing`` for the boot.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional, Tuple

from seedsigner.helpers.secure_delete import wipe_string

if TYPE_CHECKING:
    from seedsigner.helpers.keycard.client import KeycardClient
    from seedsigner.helpers.keycard.secure_channel import PairingInfo
    from seedsigner.views.view import View


logger = logging.getLogger(__name__)

PIN_LENGTH = 6


def format_path(components) -> str:
    """Human-readable ``m/...`` rendering of a BIP-32 path component list.

    Each component is a 32-bit unsigned int; the high bit marks hardened
    children and gets stripped before rendering.
    """
    parts = []
    for c in components:
        hardened = bool(c & 0x80000000)
        idx = c & 0x7FFFFFFF
        parts.append(f"{idx}'" if hardened else str(idx))
    return "m/" + "/".join(parts)


def extract_pubkey(export_response: bytes) -> Optional[bytes]:
    """Pull the 65-byte uncompressed public key from an EXPORT KEY response.

    Status Keycard wraps the public key in a TLV template ``0xA1 [TLVs]``
    where the pubkey itself sits under tag ``0x80``, length 65, leading
    byte ``0x04``. Returns ``None`` if the response cannot be parsed.
    """
    if not export_response:
        return None
    if export_response[0] == 0xA1:
        body = export_response[2:2 + export_response[1]]
    else:
        body = export_response
    cursor = 0
    while cursor + 2 <= len(body):
        tag = body[cursor]
        length = body[cursor + 1]
        value = body[cursor + 2:cursor + 2 + length]
        if tag == 0x80 and len(value) == 65 and value[0] == 0x04:
            return bytes(value)
        cursor += 2 + length
    return None


def extract_extended_pubkey(
    export_response: bytes,
) -> Optional[Tuple[bytes, bytes]]:
    """Pull (pubkey, chain_code) from an EXPORT KEY (extended) response.

    With ``EXPORT_P2_EXTENDED_PUBLIC`` the Status Keycard returns the
    same ``0xA1 [TLVs]`` template as ``extract_pubkey``, but with an
    additional 32-byte chain code under tag ``0x82``. Returns ``None``
    if either field is missing or malformed.
    """
    if not export_response:
        return None
    if export_response[0] == 0xA1:
        body = export_response[2:2 + export_response[1]]
    else:
        body = export_response
    pubkey: Optional[bytes] = None
    chain_code: Optional[bytes] = None
    cursor = 0
    while cursor + 2 <= len(body):
        tag = body[cursor]
        length = body[cursor + 1]
        value = body[cursor + 2:cursor + 2 + length]
        if tag == 0x80 and len(value) == 65 and value[0] == 0x04:
            pubkey = bytes(value)
        elif tag == 0x82 and len(value) == 32:
            chain_code = bytes(value)
        cursor += 2 + length
    if pubkey is None or chain_code is None:
        return None
    return pubkey, chain_code


def wipe_bytearray(buf: Optional[bytearray]) -> None:
    """Best-effort in-place zeroing of a mutable byte buffer."""
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0


def prompt_for_text(parent_view: "View", title: str, *, max_len: int = 80) -> Optional[str]:
    """Show a passphrase-style keyboard, return the captured string or None.

    Used for the pairing password (NOT the PIN — see ``prompt_for_pin``).
    The caller is responsible for wiping the returned string after use.
    """
    from seedsigner.gui.screens import RET_CODE__BACK_BUTTON, WarningScreen
    from seedsigner.gui.screens import seed_screens

    while True:
        ret = seed_screens.SeedAddPassphraseScreen(title=title).display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return None
        text = ret.get("passphrase", "") if isinstance(ret, dict) else ""
        if 1 <= len(text) <= max_len:
            return text
        parent_view.run_screen(
            WarningScreen,
            title="Invalid input",
            status_headline=None,
            text=f"Length must be 1..{max_len}.",
            show_back_button=True,
        )


def prompt_for_pin(parent_view: "View", title: str) -> Optional[bytearray]:
    """Capture a 6-digit ASCII PIN as a mutable ``bytearray``.

    The caller MUST ``wipe_bytearray()`` the returned buffer once the
    APDU exchange is done. Returns ``None`` if the user backs out.
    """
    from seedsigner.gui.screens import RET_CODE__BACK_BUTTON, WarningScreen
    from seedsigner.gui.screens import seed_screens

    while True:
        ret = seed_screens.SeedAddPassphraseScreen(
            title=title,
            initial_keyboard=seed_screens.SeedAddPassphraseScreen.KEYBOARD__DIGITS_BUTTON_TEXT,
        ).display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return None
        pin_str = ret.get("passphrase", "") if isinstance(ret, dict) else ""
        if len(pin_str) == PIN_LENGTH and pin_str.isdigit() and pin_str.isascii():
            buf = bytearray(pin_str.encode("ascii"))
            try:
                wipe_string(pin_str)
            except Exception:
                pass
            return buf
        parent_view.run_screen(
            WarningScreen,
            title="Invalid PIN",
            status_headline=None,
            text=f"PIN must be exactly {PIN_LENGTH} digits.",
            show_back_button=True,
        )


def _active_aid(parent_view: "View"):
    """Resolve the AID to SELECT for Keycard ops on this controller.

    Falls back to the published Status AID if the controller doesn't
    expose ``active_keycard_aid`` (e.g. early-init test stubs).
    """
    from seedsigner.helpers.keycard.commands import APPLET_AID
    return getattr(parent_view.controller, "active_keycard_aid", APPLET_AID)


# Status Keycard package prefix (8 bytes) + 1-byte version + 1-byte instance.
# The last byte is the instance suffix; cards initialised by keycard-shell
# may live at a suffix other than 0x01.
_KEYCARD_INSTANCE_PREFIX = bytes.fromhex("A000000804000101")
_KNOWN_INSTANCE_SUFFIXES = [bytes([b]) for b in range(0x01, 0x10)]  # 01..0F


def select_with_autodetect(client, controller):
    """SELECT the active Keycard applet, auto-probing on 6A82.

    First tries ``controller.active_keycard_aid``; if the card returns
    ``0x6A82`` (file/applet not found), probes a small set of known
    instance AIDs (``A000000804000101`` + ``0x01..0x0F``) and updates
    ``controller.active_keycard_aid`` on the first match. Avoids forcing
    the user through Manage Instances → Switch active when a stock card
    happens to use a non-default instance suffix.

    Returns the ``SelectResponse`` from the successful SELECT. Raises
    the original ``APDUError(0x6A82)`` if no candidate matches, so
    callers see the canonical "Applet not found" classification.
    """
    from seedsigner.helpers.keycard.commands import APDUError

    target = getattr(controller, "active_keycard_aid", None) or (
        _KEYCARD_INSTANCE_PREFIX + b"\x01"
    )
    last_exc: Optional[APDUError] = None
    try:
        return client.select(aid=target)
    except APDUError as exc:
        if exc.sw != 0x6A82:
            raise
        last_exc = exc

    for suffix in _KNOWN_INSTANCE_SUFFIXES:
        candidate = _KEYCARD_INSTANCE_PREFIX + suffix
        if candidate == target:
            continue
        try:
            info = client.select(aid=candidate)
        except APDUError as exc:
            if exc.sw == 0x6A82:
                continue
            raise
        controller.active_keycard_aid = candidate
        return info

    assert last_exc is not None
    raise last_exc


def open_unlocked_session(parent_view: "View", pin: bytearray) -> Tuple["KeycardClient", "PairingInfo"]:
    """Connect, SELECT, OPEN_SECURE_CHANNEL, VERIFY_PIN.

    Auto-switch behaviour: SELECT runs before any pairing lookup so the
    function discovers which physical card is currently in the reader,
    then picks the right cached pairing for that card. The AID we
    SELECT is ``controller.active_keycard_aid`` so multi-instance
    setups can target the right applet.

    Raises :class:`KeycardCardChangedError` (with the card's
    ``instance_uid``) if no pairing for the inserted card exists in the
    boot cache. The caller is responsible for wiping ``pin`` after use.
    """
    from seedsigner.helpers.keycard import KeycardCardChangedError
    from seedsigner.helpers.keycard.client import KeycardClient
    from seedsigner.helpers.keycard.reader import (
        release_other_smartcard_holders, wait_for_card,
    )

    release_other_smartcard_holders(parent_view.controller)
    connection = wait_for_card(timeout_s=5.0)
    client = KeycardClient(connection)
    info = select_with_autodetect(client, parent_view.controller)
    parent_view.controller.last_keycard_uid = bytes(info.instance_uid)

    pairing = parent_view.controller.get_pairing_for(info.instance_uid)
    if pairing is None:
        raise KeycardCardChangedError(info.instance_uid)

    client.open_secure_channel(pairing)
    client.verify_pin(bytes(pin))
    return client, pairing


def identify_inserted_card(parent_view: "View") -> Tuple["KeycardClient", bytes]:
    """SELECT only — identify which card/instance is in the reader.

    Returns ``(client, instance_uid)`` and updates
    ``controller.last_keycard_uid``. Used by entry-point views that
    need to redirect to the Pair flow when the inserted card has no
    cached pairing.
    """
    from seedsigner.helpers.keycard.client import KeycardClient
    from seedsigner.helpers.keycard.reader import (
        release_other_smartcard_holders, wait_for_card,
    )

    release_other_smartcard_holders(parent_view.controller)
    connection = wait_for_card(timeout_s=5.0)
    client = KeycardClient(connection)
    info = select_with_autodetect(client, parent_view.controller)
    uid = bytes(info.instance_uid)
    parent_view.controller.last_keycard_uid = uid
    return client, uid


def classify_card_error(
    exc: BaseException,
    *,
    default_title: str = "Card error",
) -> Tuple[str, str]:
    """Map a Keycard-flow exception to a user-friendly ``(title, body)``.

    The view layer uses this to avoid two recurring UX bugs:

    1. A successful ``wait_for_card`` followed by an ``APDUError`` with
       SW=0x6A82 (applet not at active AID) used to be reported as
       "Card not reachable" — misleading: the card *is* reachable.
    2. A no-card timeout used to render ``str(exc)`` ("card not
       reachable; reseat and retry") into the body of a screen whose
       title was already "Card not reachable" — duplicated wording.

    Bodies are kept to ≤2 lines / ~60 chars per line so they fit the
    ``KeycardErrorView`` (truncated to 120 chars by the view).

    ``default_title`` is what the caller wants for "I don't know what
    went wrong" — usually the operation name, e.g. ``"Generate failed"``
    or ``"Signing failed"``. It's overridden when this function
    recognises a specific failure mode.
    """
    from seedsigner.helpers.iso7816 import ISO7816_STATUS_WORDS
    from seedsigner.helpers.keycard import KeycardCardChangedError
    from seedsigner.helpers.keycard.commands import APDUError
    from seedsigner.helpers.keycard.pairing_storage import PairingStorageError
    from seedsigner.helpers.keycard.reader import NoCardError, NoReaderError
    from seedsigner.helpers.keycard.secure_channel import SecureChannelError

    if isinstance(exc, NoReaderError):
        return ("No reader", "Connect a card reader\nand retry.")
    if isinstance(exc, NoCardError):
        return ("No card", "Insert a card and retry.")
    if isinstance(exc, KeycardCardChangedError):
        return ("Card changed", "Pair the inserted card\nfirst.")
    if isinstance(exc, SecureChannelError):
        # The "cryptogram mismatch" failure is only ever caused by a
        # wrong pairing password (PAIR step 1 cryptogram check); other
        # SecureChannelError messages (length errors, MAC mismatches)
        # are genuine secure-channel issues.
        if "cryptogram" in str(exc).lower():
            return ("Wrong password",
                    "Pairing password did\nnot match this card.")
        return ("Pairing failed", "Secure channel could\nnot be opened.")
    if isinstance(exc, PairingStorageError):
        return ("Storage error", str(exc)[:100])
    if isinstance(exc, APDUError):
        sw = exc.sw
        if sw == 0x6A82:
            return ("Applet not found",
                    "Try Manage instances\nto switch active AID.")
        if sw in (0x6982, 0x6985):
            return ("Card refused",
                    f"Auth/condition not met\n(SW={sw:04X}).")
        if (sw & 0xFFF0) == 0x63C0:
            tries = sw & 0x000F
            return ("Wrong PIN", f"{tries} tries left.")
        if (sw & 0xFF00) == 0x6D00:
            return ("Not supported",
                    "Card does not implement\nthis op.")
        short = ISO7816_STATUS_WORDS.get(sw, "Card error")
        return (default_title, f"SW={sw:04X}\n{short}"[:100])
    return (default_title, str(exc)[:100])
