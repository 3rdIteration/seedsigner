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
        ret = seed_screens.SeedAddPassphraseScreen(title=title).display()
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
    from seedsigner.helpers.keycard.reader import wait_for_card

    connection = wait_for_card(timeout_s=5.0)
    client = KeycardClient(connection)
    info = client.select(aid=_active_aid(parent_view))
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
    from seedsigner.helpers.keycard.reader import wait_for_card

    connection = wait_for_card(timeout_s=5.0)
    client = KeycardClient(connection)
    info = client.select(aid=_active_aid(parent_view))
    uid = bytes(info.instance_uid)
    parent_view.controller.last_keycard_uid = uid
    return client, uid
