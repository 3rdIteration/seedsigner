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
from gettext import gettext as _
from typing import TYPE_CHECKING, Optional, Tuple

from seedsigner.helpers.l10n import mark_for_translation as _mft
from seedsigner.helpers.secure_delete import wipe_string

if TYPE_CHECKING:
    from seedsigner.helpers.keycard.client import KeycardClient
    from seedsigner.helpers.keycard.global_platform import CardMemory
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


def _strip_outer_template(export_response: bytes) -> bytes:
    """Unwrap an outer BER-TLV template if present.

    Status Keycard wraps EXPORT KEY responses in ``0xA1 LL ...`` (template
    tag, short-form length). Some applet variants either omit the template
    entirely or use the long-form length (``0x81 LL``). This returns the
    inner bytes regardless.
    """
    if not export_response:
        return b""
    if export_response[0] != 0xA1:
        return export_response
    if len(export_response) < 2:
        return b""
    length_byte = export_response[1]
    if length_byte == 0x81:
        if len(export_response) < 3:
            return b""
        length = export_response[2]
        return export_response[3:3 + length]
    if length_byte & 0x80:
        # Higher long-form lengths (0x82, 0x83, ...) — not expected from
        # Keycard for these payloads, treat as malformed.
        return b""
    return export_response[2:2 + length_byte]


def _iter_inner_tlvs(body: bytes):
    """Yield ``(tag, value)`` tuples from a flat short-form / 0x81 BER-TLV stream."""
    cursor = 0
    while cursor + 2 <= len(body):
        tag = body[cursor]
        length_byte = body[cursor + 1]
        if length_byte == 0x81:
            if cursor + 3 > len(body):
                return
            length = body[cursor + 2]
            value = body[cursor + 3:cursor + 3 + length]
            cursor += 3 + length
        elif length_byte & 0x80:
            return
        else:
            length = length_byte
            value = body[cursor + 2:cursor + 2 + length]
            cursor += 2 + length
        yield tag, bytes(value)


def extract_pubkey(export_response: bytes) -> Optional[bytes]:
    """Pull the 65-byte uncompressed public key from an EXPORT KEY response.

    Accepts every shape we have seen in the wild:

    * ``0xA1 LL 0x80 0x41 04 ...`` — Status Keycard spec wrapping (template
      tag with short-form length, inner pubkey under tag ``0x80``).
    * ``0xA1 0x81 LL 0x80 0x41 04 ...`` — same with BER long-form length
      on the outer template.
    * ``0x80 0x41 04 ...`` — bare inner TLV without the outer template.
    * ``04 ...`` (exactly 65 bytes) — raw uncompressed pubkey, no TLV
      wrapping at all (some custom applets).

    Returns ``None`` if none of these shapes match.
    """
    if not export_response:
        return None
    body = _strip_outer_template(export_response)
    if not body:
        return None
    # Bare uncompressed pubkey, no TLV at all.
    if len(body) == 65 and body[0] == 0x04:
        return bytes(body)
    for tag, value in _iter_inner_tlvs(body):
        if tag == 0x80 and len(value) == 65 and value[0] == 0x04:
            return value
    return None


def extract_extended_pubkey(
    export_response: bytes,
) -> Optional[Tuple[bytes, bytes]]:
    """Pull (pubkey, chain_code) from an EXPORT KEY (extended) response.

    Accepts the same wrapping variants as :func:`extract_pubkey`, plus
    the bare ``04 ... (pubkey,65) || (chain_code,32)`` form (97 bytes
    total) seen on some custom applets. Returns ``None`` if either field
    is missing or malformed.
    """
    if not export_response:
        return None
    body = _strip_outer_template(export_response)
    if not body:
        return None
    # Bare pubkey || chain_code, no TLV.
    if len(body) == 97 and body[0] == 0x04:
        return bytes(body[:65]), bytes(body[65:])
    pubkey: Optional[bytes] = None
    chain_code: Optional[bytes] = None
    for tag, value in _iter_inner_tlvs(body):
        if tag == 0x80 and len(value) == 65 and value[0] == 0x04:
            pubkey = value
        elif tag == 0x82 and len(value) == 32:
            chain_code = value
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

    Escape paths:
      * Top-nav back arrow (UP then PRESS, or LEFT while on top-nav).
      * Saving with empty input is treated as cancel — gives the user an
        out without having to discover the top-nav navigation.
    """
    from seedsigner.gui.screens import WarningScreen
    from seedsigner.gui.screens import seed_screens

    while True:
        ret = seed_screens.SeedAddPassphraseScreen(title=title).display()
        if isinstance(ret, dict) and "is_back_button" in ret:
            return None
        text = ret.get("passphrase", "") if isinstance(ret, dict) else ""
        if not text:
            # Empty Save = cancel. Avoids the "Invalid input" loop trap.
            return None
        if len(text) <= max_len:
            return text
        parent_view.run_screen(
            WarningScreen,
            title=_("Too long"),
            status_headline=None,
            text=_("Max {} chars.").format(max_len),
            show_back_button=True,
        )


def prompt_for_pin(
    parent_view: "View", title: str, num_digits: int = PIN_LENGTH,
) -> Optional[bytearray]:
    """Capture a fixed-length ASCII digit code as a mutable ``bytearray``.

    Defaults to the 6-digit PIN; pass ``num_digits=12`` for the PUK.
    The caller MUST ``wipe_bytearray()`` the returned buffer once the
    APDU exchange is done. Returns ``None`` if the user backs out.
    """
    from seedsigner.gui.screens import RET_CODE__BACK_BUTTON, WarningScreen
    from seedsigner.gui.screens.screen import KeycardPINEntryScreen

    while True:
        # Dedicated masked PIN pad: exactly num_digits slots, digits only,
        # auto-submits once the last slot is filled.
        ret = KeycardPINEntryScreen(title=title, num_digits=num_digits).display()
        if ret == RET_CODE__BACK_BUTTON:
            return None
        pin_str = ret if isinstance(ret, str) else ""
        if len(pin_str) == num_digits and pin_str.isdigit() and pin_str.isascii():
            buf = bytearray(pin_str.encode("ascii"))
            try:
                wipe_string(pin_str)
            except Exception:
                pass
            return buf
        parent_view.run_screen(
            WarningScreen,
            title=_("Invalid entry"),
            status_headline=None,
            text=_("Must be exactly {} digits.").format(num_digits),
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
# Instance-AID candidates to probe (both 9-byte and 10-byte conventions) come
# from the shared ``global_platform.keycard_instance_aid_candidates`` builder,
# so the three probe sites (here, ``probe_keycard_instance_aids``, and
# ``card_probe``) can never drift apart again.


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

    Every successful SELECT records the AID→``instance_uid`` mapping
    (``remember_aid_for_uid``). This is the single choke-point that keeps
    ``keycard_aid_to_uid`` authoritative for the active instance, so
    instance-name display never has to guess via ``last_keycard_uid``.
    """
    from seedsigner.helpers.keycard.commands import APDUError

    target = getattr(controller, "active_keycard_aid", None) or (
        _KEYCARD_INSTANCE_PREFIX + b"\x01"
    )
    last_exc: Optional[APDUError] = None
    try:
        info = client.select(aid=target)
    except APDUError as exc:
        if exc.sw != 0x6A82:
            raise
        last_exc = exc
    else:
        controller.remember_aid_for_uid(target, info.instance_uid)
        return info

    from seedsigner.helpers.keycard.global_platform import (
        keycard_instance_aid_candidates,
    )
    for candidate in keycard_instance_aid_candidates(_KEYCARD_INSTANCE_PREFIX):
        if candidate == target:
            continue
        try:
            info = client.select(aid=candidate)
        except APDUError as exc:
            if exc.sw == 0x6A82:
                continue
            raise
        controller.active_keycard_aid = candidate
        controller.remember_aid_for_uid(candidate, info.instance_uid)
        return info

    assert last_exc is not None
    raise last_exc


def open_unlocked_session(
    parent_view: "View",
    pin: Optional[bytearray] = None,
    *,
    require_key: bool = True,
    skip_pin_verify: bool = False,
) -> Tuple["KeycardClient", "PairingInfo"]:
    """Connect, SELECT, (PAIR if ephemeral), OPEN_SECURE_CHANNEL, VERIFY_PIN.

    Auto-switch behaviour: SELECT runs before any pairing lookup so the
    function discovers which physical card is currently in the reader,
    then picks the right cached pairing for that card. The AID we
    SELECT is ``controller.active_keycard_aid`` so multi-instance
    setups can target the right applet.

    PIN handling:

    * If ``pin`` is None and a cached PIN exists for the inserted card,
      it is used transparently.
    * If ``pin`` is None and no cached PIN exists,
      :class:`KeycardPinRequiredError` is raised so the view layer can
      prompt the user.
    * If ``pin`` is provided, it is sent to the card; on success a
      copy is stored in ``Controller.keycard_pins`` so subsequent
      operations skip the prompt. The caller still owns ``pin`` and
      MUST wipe it.
    * If VERIFY_PIN fails with SW=``0x63CX`` (bad PIN), the cache for
      this UID is dropped before the exception propagates.

    Pairing source priority for the inserted card:

    1. Ephemeral secret cached for this boot — re-PAIR(P2=EPHEMERAL)
       and OPEN with index 0xFF. The on-card ephemeral key is cleared
       on every applet deselect, so we cannot reuse a previous
       ``PairingInfo`` here; the cached *secret* is what survives.
    2. Persistent ``PairingInfo`` cached for this boot — OPEN directly.

    ``require_key``: when True (default), bail with
    :class:`KeycardNoMasterKeyError` if the SELECT response indicates no
    master key on the card. Sign / derive / export flows must keep this
    on so the user sees a clear error instead of a cryptic SW=0x6985.
    Flows that *create* a key (GENERATE_KEY, LOAD_KEY) or do not touch
    it (CHANGE_PIN, UNPAIR) pass ``require_key=False`` so they can run
    on a freshly initialised card.

    Raises :class:`KeycardCardChangedError` (with the card's
    ``instance_uid``) if no pairing data exists for the inserted card.
    """
    from seedsigner.helpers.keycard import (
        KeycardCardChangedError, KeycardNoMasterKeyError,
        KeycardNotInitialisedError, KeycardPinRequiredError,
    )
    from seedsigner.helpers.keycard.client import KeycardClient
    from seedsigner.helpers.keycard.commands import (
        APDUError, PAIR_P2_EPHEMERAL, supports_ephemeral_pairing,
    )
    from seedsigner.helpers.keycard.reader import (
        release_other_smartcard_holders, wait_for_card,
    )

    release_other_smartcard_holders(parent_view.controller)
    connection = wait_for_card(timeout_s=5.0)
    client = KeycardClient(connection)
    info = select_with_autodetect(client, parent_view.controller)
    if info.app_version == 0:
        raise KeycardNotInitialisedError(
            "card not initialised; run Initialise first"
        )
    # SelectResponse.key_uid is empty until GENERATE_KEY or LOAD_KEY runs.
    # Without a master key, every DERIVE/EXPORT returns SW=0x6985 and the
    # user sees a cryptic "Parse fail" — bail early with a clear error.
    # Callers that *create* a key (GENERATE_KEY, LOAD_KEY) or do not need
    # one (CHANGE_PIN, UNPAIR) pass ``require_key=False`` to skip this.
    if require_key and not info.key_uid:
        raise KeycardNoMasterKeyError(info.instance_uid)
    parent_view.controller.last_keycard_uid = bytes(info.instance_uid)

    pairing = None
    ephemeral_secret = parent_view.controller.get_ephemeral_secret_for(
        info.instance_uid,
    )
    if ephemeral_secret is not None:
        if not supports_ephemeral_pairing(info.app_version):
            # Stale state: we cached an ephemeral secret but the card
            # currently in the reader doesn't speak v3.2. Drop the
            # stale entry and ask the user to re-pair instead of
            # silently allocating a persistent slot on the older card.
            parent_view.controller.forget_ephemeral_secret_for(
                info.instance_uid,
            )
            raise KeycardCardChangedError(info.instance_uid)
        pairing = client.pair(ephemeral_secret, p2=PAIR_P2_EPHEMERAL)
    else:
        pairing = parent_view.controller.get_pairing_for(info.instance_uid)

    if pairing is None:
        raise KeycardCardChangedError(info.instance_uid)

    client.open_secure_channel(pairing)

    # UNBLOCK PIN runs against a *blocked* PIN, so its flow needs the
    # secure channel without VERIFY_PIN (which would just burn nothing —
    # the applet rejects verification attempts while blocked).
    if skip_pin_verify:
        return client, pairing

    if pin is None:
        cached_pin = parent_view.controller.get_pin_for(info.instance_uid)
        if cached_pin is None:
            raise KeycardPinRequiredError(info.instance_uid)
        pin_to_send = bytes(cached_pin)
    else:
        pin_to_send = bytes(pin)

    try:
        client.verify_pin(pin_to_send)
    except APDUError as exc:
        # SW=0x63CX = bad PIN, X attempts remaining. Drop the cache so
        # we don't keep burning attempts with a stale value; the next
        # call will raise KeycardPinRequiredError and trigger a prompt.
        if (exc.sw & 0xFFF0) == 0x63C0:
            parent_view.controller.forget_pin_for(info.instance_uid)
        raise

    if pin is not None:
        parent_view.controller.set_pin_for(info.instance_uid, pin)
    return client, pairing


def open_unlocked_session_cached_or_prompt(
    parent_view: "View",
    pin_title: str = "Card PIN",
    *,
    require_key: bool = True,
) -> Tuple["KeycardClient", "PairingInfo"]:
    """Variant of :func:`open_unlocked_session` that prompts for the PIN
    on cache miss and wipes the captured buffer before returning.

    ``require_key`` is forwarded to :func:`open_unlocked_session`; see
    that function for semantics.

    Raises :class:`KeycardPinPromptCancelled` if the user backs out of
    the PIN keyboard. All other exceptions from
    :func:`open_unlocked_session` propagate unchanged.
    """
    from seedsigner.helpers.keycard import (
        KeycardPinPromptCancelled, KeycardPinRequiredError,
    )

    try:
        return open_unlocked_session(
            parent_view, pin=None, require_key=require_key,
        )
    except KeycardPinRequiredError:
        pass

    pin = prompt_for_pin(parent_view, pin_title)
    if pin is None:
        raise KeycardPinPromptCancelled()
    try:
        return open_unlocked_session(
            parent_view, pin=pin, require_key=require_key,
        )
    finally:
        wipe_bytearray(pin)


def query_card_memory(parent_view: "View") -> Optional["CardMemory"]:
    """Read free card memory via GlobalPlatform GET DATA 0xFF21.

    Opens a transient connection, SELECTs the ISD, reads the Extended Card
    Resources Information (free persistent / volatile memory + app count) in
    the clear — no ISD authentication needed — then **releases the reader**
    so a subsequent ``gp.jar`` install can grab it.

    Returns ``None`` on any failure (no card/reader, unsupported tag,
    protocol error) so callers can degrade gracefully: the Storage view
    shows an "unavailable" message and the pre-install check simply skips
    rather than blocking a valid install.
    """
    from seedsigner.helpers import seedkeeper_utils
    from seedsigner.helpers.keycard.global_platform import GpSecureChannel
    from seedsigner.helpers.keycard.reader import (
        release_other_smartcard_holders, wait_for_card,
    )

    try:
        release_other_smartcard_holders(parent_view.controller)
        connection = wait_for_card(timeout_s=5.0)
        channel = GpSecureChannel(connection)
        channel.select_isd()
        return channel.get_extended_card_resources()
    except Exception as exc:
        logger.info("query_card_memory unavailable: %s", exc)
        return None
    finally:
        # Drop the PC/SC handle so gp.jar / the next CardConnector start fresh.
        try:
            seedkeeper_utils.disconnect_smartcard_connections(
                parent_view.controller,
            )
        except Exception:
            logger.debug("query_card_memory cleanup failed", exc_info=True)


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


def try_silent_ephemeral_pair(parent_view: "View") -> bool:
    """Best-effort silent v3.2+ ephemeral pairing of the inserted card.

    SELECTs the card, and if it supports ephemeral pairing, tries the
    well-known keycard-cli default password (PBKDF2) then the
    keycard-shell raw PSK. On success caches the 32-byte secret on the
    controller and returns True. Returns False on any failure (no card,
    pre-3.2 card, wrong credentials, transient I/O error) without
    raising — callers fall back to the explicit ``ToolsKeycardPairView``.

    The helper is the inline-friendly equivalent of the silent steps
    performed by ``ToolsKeycardPairView._run_ephemeral``: any view that
    would otherwise round-trip the user through the Pair menu can call
    this first and continue with the requested action.
    """
    from seedsigner.helpers.keycard.client import KeycardClient
    from seedsigner.helpers.keycard.commands import (
        PAIR_P2_EPHEMERAL, supports_ephemeral_pairing,
    )
    from seedsigner.helpers.keycard.crypto import (
        KEYCARD_SHELL_DEFAULT_PSK, derive_pairing_secret,
    )
    from seedsigner.helpers.keycard.reader import (
        release_other_smartcard_holders, wait_for_card,
    )

    # keycard-cli / keycard-shell default password (kept in sync with
    # the constant in views.keycard_views; duplicated here to avoid a
    # views→helpers import cycle).
    DEFAULT_PAIRING_PASSWORD = "KeycardDefaultPairing"

    try:
        release_other_smartcard_holders(parent_view.controller)
        connection = wait_for_card(timeout_s=2.0)
        client = KeycardClient(connection)
        info = select_with_autodetect(client, parent_view.controller)
    except Exception:
        return False

    if info.app_version == 0:
        return False
    if not supports_ephemeral_pairing(info.app_version):
        return False

    instance_uid = bytes(info.instance_uid)
    parent_view.controller.last_keycard_uid = instance_uid
    parent_view.controller.remember_aid_for_uid(
        parent_view.controller.active_keycard_aid, instance_uid,
    )

    # Already have a cached ephemeral secret for this card — nothing to do.
    if parent_view.controller.get_ephemeral_secret_for(instance_uid) is not None:
        return True

    default_secret = derive_pairing_secret(DEFAULT_PAIRING_PASSWORD)
    paired = False
    try:
        try:
            client.pair(default_secret, p2=PAIR_P2_EPHEMERAL)
            parent_view.controller.set_ephemeral_secret_for(
                instance_uid, default_secret,
            )
            paired = True
        except Exception:
            try:
                client.pair(KEYCARD_SHELL_DEFAULT_PSK, p2=PAIR_P2_EPHEMERAL)
                parent_view.controller.set_ephemeral_secret_for(
                    instance_uid, KEYCARD_SHELL_DEFAULT_PSK,
                )
                paired = True
            except Exception:
                paired = False
    finally:
        # Wipe the freshly-derived default secret (the module-level shell
        # PSK is a constant and must stay intact).
        try:
            buf = bytearray(default_secret)
            for i in range(len(buf)):
                buf[i] = 0
        except Exception:
            pass

    return paired


def classify_card_error(
    exc: BaseException,
    *,
    default_title: str = _mft("Card error"),
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
    from seedsigner.helpers.keycard import (
        KeycardCardChangedError, KeycardNoMasterKeyError,
        KeycardNotInitialisedError,
    )
    from seedsigner.helpers.keycard.commands import APDUError
    from seedsigner.helpers.keycard.pairing_storage import PairingStorageError
    from seedsigner.helpers.keycard.reader import NoCardError, NoReaderError
    from seedsigner.helpers.keycard.secure_channel import SecureChannelError

    if isinstance(exc, NoReaderError):
        return (_("No reader"), _("Connect a card reader\nand retry."))
    if isinstance(exc, NoCardError):
        return (_("No card"), _("Insert a card and retry."))
    if isinstance(exc, KeycardCardChangedError):
        return (_("Card changed"), _("Pair the inserted card\nfirst."))
    if isinstance(exc, KeycardNotInitialisedError):
        return (_("Not initialised"),
                _("Initialise this\ninstance first."))
    if isinstance(exc, KeycardNoMasterKeyError):
        return (_("No key on card"),
                _("Generate key or\nimport seed first."))
    if isinstance(exc, SecureChannelError):
        # The "cryptogram mismatch" failure is only ever caused by a
        # wrong pairing password (PAIR step 1 cryptogram check); other
        # SecureChannelError messages (length errors, MAC mismatches)
        # are genuine secure-channel issues.
        msg = str(exc)
        if "cryptogram" in msg.lower():
            return (_("Wrong password"),
                    _("Pairing password did\nnot match this card."))
        # Surface the underlying reason so a stale pairing on disk, a
        # MAC mismatch, or a truncated OPEN response can be diagnosed
        # without attaching a debugger.
        detail = (msg or "unknown")[:60]
        return (_("Secure channel"), _("SC open failed:\n{}").format(detail))
    if isinstance(exc, PairingStorageError):
        return (_("Storage error"), str(exc)[:100])
    if isinstance(exc, APDUError):
        sw = exc.sw
        if sw == 0x6A82:
            return (_("Applet not found"),
                    _("Try Manage › Instances\nto switch active AID."))
        if sw in (0x6982, 0x6985):
            return (_("Card refused"),
                    _("Auth/condition not met\n(SW={}).").format(f"{sw:04X}"))
        if (sw & 0xFFF0) == 0x63C0:
            tries = sw & 0x000F
            if tries == 0:
                # Point at the recovery path instead of a dead-end error.
                return (_("PIN blocked"),
                        _("Unblock with PUK via\nThis instance menu."))
            # TRANSLATOR_NOTE: {} is the number of remaining PIN attempts
            return (_("Wrong PIN"), _("{} tries left.").format(tries))
        if (sw & 0xFF00) == 0x6D00:
            return (_("Not supported"),
                    _("Card does not implement\nthis op."))
        short = ISO7816_STATUS_WORDS.get(sw, _("Card error"))
        # TRANSLATOR_NOTE: {} placeholders are a hex status word and a short reason
        return (_(default_title), (_("SW={}\n{}").format(f"{sw:04X}", short))[:100])
    return (_(default_title), str(exc)[:100])
