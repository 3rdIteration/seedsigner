"""GlobalPlatform SCP02 secure channel + applet management.

This module implements the minimum subset of GlobalPlatform 2.1.1 that
SeedSigner needs to manage **multiple Status Keycard applet instances**
on a single JavaCard:

* SCP02 (i='15') secure channel with the default Issuer Security Domain
  (ISD) keys present on retail Status Keycards.
* INITIALIZE UPDATE + EXTERNAL AUTHENTICATE.
* GET STATUS for applet instances (P1=0x40).
* INSTALL [for install].
* DELETE.

Threat model
------------
The default ISD keys (``404142...4F``) work on any card whose issuer
hasn't rotated them. Anyone in physical possession of the card AND the
ISD keys can install or delete applets, so this is **management-only**
functionality and never used for signing seed/key material.

We deliberately implement only **C-MAC** (security level 0x01), not
C-MAC+C-ENC: the commands we send (INSTALL, DELETE, GET STATUS) carry
no secret payload. Adding C-ENC would only complicate the code without
a security benefit for these specific operations.

The crypto primitives used are 3DES (in 2-key form, 16-byte keys) for
session-key derivation and cryptograms, and the ISO 9797-1 algorithm 3
("retail MAC") with padding method 2 for the C-MAC.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

from Cryptodome.Cipher import DES, DES3

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Common Card Manager / Issuer Security Domain AIDs. We try them in order
# at SELECT time; the first that responds 9000 wins.
ISD_AID_VISA = bytes.fromhex("A000000003000000")
ISD_AID_MASTERCARD = bytes.fromhex("A000000151000000")
ISD_AID_CANDIDATES = (ISD_AID_VISA, ISD_AID_MASTERCARD)

# Default keys baked into retail Status Keycards (and any GP card with
# unrotated keys). 16 bytes per key, used as 2-key 3DES (k1||k2 with k1
# reused as the third sub-key).
DEFAULT_ISD_KEY = bytes.fromhex("404142434445464748494A4B4C4D4E4F")

# CLA / INS bytes used by the Card Manager.
CLA_GP = 0x80
CLA_GP_MAC = 0x84  # GP CLA with secure-messaging bit set (CMAC)

INS_INITIALIZE_UPDATE = 0x50
INS_EXTERNAL_AUTHENTICATE = 0x82
INS_GET_STATUS_GP = 0xF2
INS_GET_DATA = 0xCA
INS_INSTALL = 0xE6
INS_DELETE = 0xE4
INS_SELECT = 0xA4

# GET DATA tag for "Extended Card Resources Information" (GlobalPlatform
# Amendment / ETSI TS 102 226): free persistent + volatile memory and the
# number of installed applications. Sent as P1=0xFF, P2=0x21.
GET_DATA_P1_EXT_CARD_RESOURCES = 0xFF
GET_DATA_P2_EXT_CARD_RESOURCES = 0x21

# GET STATUS P1 selectors (we only need applets/instances).
GP_STATUS_P1_APPLICATIONS = 0x40

# INSTALL [for install] P1.
INSTALL_P1_FOR_INSTALL_AND_MAKE_SELECTABLE = 0x0C

# Security level requested in EXTERNAL AUTHENTICATE.
SECURITY_LEVEL_CMAC = 0x01

# 3DES key-derivation constants for SCP02 session keys.
KDF_CONST_S_ENC = bytes.fromhex("0182")
KDF_CONST_S_MAC = bytes.fromhex("0101")
KDF_CONST_S_DEK = bytes.fromhex("0181")

# Status word for "OK".
SW_OK = 0x9000


class GpProtocolError(Exception):
    """Raised when an APDU response is not what SCP02 expects."""


# ---------------------------------------------------------------------------
# Crypto primitives
# ---------------------------------------------------------------------------


def _iso9797_pad(data: bytes, block: int = 8) -> bytes:
    """Padding method 2: ``80 00 00 …`` to a multiple of ``block``."""
    pad_len = block - (len(data) % block)
    return data + b"\x80" + b"\x00" * (pad_len - 1)


def _3des_cbc_encrypt(key16: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key16) != 16:
        raise ValueError("3DES key must be 16 bytes (2-key form)")
    if len(iv) != 8:
        raise ValueError("3DES IV must be 8 bytes")
    if len(data) % 8 != 0:
        raise ValueError("3DES-CBC input must be a multiple of 8 bytes")
    return DES3.new(key16, DES3.MODE_CBC, iv).encrypt(data)


def derive_session_key(static_key: bytes, derivation_const: bytes,
                       sequence_counter: bytes) -> bytes:
    """SCP02 session key from a static ISD key.

    derivation = ``derivation_const(2) || sequence_counter(2) || zeros(12)``
    session_key = 3DES-CBC(static_key, IV=0, derivation)
    """
    if len(static_key) != 16:
        raise ValueError("static key must be 16 bytes")
    if len(derivation_const) != 2:
        raise ValueError("derivation constant must be 2 bytes")
    if len(sequence_counter) != 2:
        raise ValueError("sequence counter must be 2 bytes")
    derivation = derivation_const + sequence_counter + b"\x00" * 12
    return _3des_cbc_encrypt(static_key, b"\x00" * 8, derivation)


def cryptogram(s_enc: bytes, parts: List[bytes]) -> bytes:
    """SCP02 cryptogram = last 8 bytes of 3DES-CBC over padded ``parts``.

    Used both for the card cryptogram (verification) and the host
    cryptogram (we send it to the card in EXTERNAL AUTHENTICATE).
    """
    blob = b"".join(parts)
    padded = _iso9797_pad(blob, 8)
    return _3des_cbc_encrypt(s_enc, b"\x00" * 8, padded)[-8:]


def retail_mac(s_mac: bytes, icv: bytes, data: bytes) -> bytes:
    """ISO 9797-1 algorithm 3 retail MAC with padding method 2.

    All blocks except the last are processed with single-DES CBC using
    ``s_mac[:8]``; the final block is processed with 3DES (k1||k2||k1).
    The chained ICV from the previous SCP02 command becomes the IV of
    the first DES-CBC step.
    """
    if len(s_mac) != 16:
        raise ValueError("S-MAC must be 16 bytes")
    if len(icv) != 8:
        raise ValueError("ICV must be 8 bytes")
    k1 = s_mac[:8]
    k2 = s_mac[8:]
    padded = _iso9797_pad(data, 8)

    iv = icv
    if len(padded) > 8:
        head = padded[:-8]
        intermediate = DES.new(k1, DES.MODE_CBC, iv).encrypt(head)
        iv = intermediate[-8:]

    last = padded[-8:]
    xored = bytes(a ^ b for a, b in zip(last, iv))
    step1 = DES.new(k1, DES.MODE_ECB).encrypt(xored)
    step2 = DES.new(k2, DES.MODE_ECB).decrypt(step1)
    return DES.new(k1, DES.MODE_ECB).encrypt(step2)


def encrypt_icv(s_mac: bytes, mac_value: bytes) -> bytes:
    """Compute the next-command ICV: single-DES encrypt the prior MAC
    with the first half of S-MAC."""
    if len(mac_value) != 8:
        raise ValueError("MAC must be 8 bytes")
    return DES.new(s_mac[:8], DES.MODE_ECB).encrypt(mac_value)


# ---------------------------------------------------------------------------
# Secure channel
# ---------------------------------------------------------------------------


@dataclass
class GpSession:
    """One SCP02 session worth of derived keys + chaining state."""

    s_enc: bytes
    s_mac: bytes
    s_dek: bytes
    sequence_counter: bytes
    card_challenge: bytes
    icv: bytes  # MAC chaining value, starts at zero, updated each command

    @property
    def is_open(self) -> bool:
        return self.s_enc and self.s_mac


def _build_initialize_update(host_challenge: bytes, key_version: int = 0,
                             key_index: int = 0) -> List[int]:
    if len(host_challenge) != 8:
        raise ValueError("host challenge must be 8 bytes")
    return [CLA_GP, INS_INITIALIZE_UPDATE, key_version, key_index,
            len(host_challenge)] + list(host_challenge) + [0x00]


def parse_initialize_update_response(resp: bytes) -> dict:
    """Parse the 28-byte response from INITIALIZE UPDATE (SCP02)."""
    if len(resp) != 28:
        raise GpProtocolError(
            f"INITIALIZE UPDATE: expected 28 bytes, got {len(resp)}")
    return {
        "key_diversification": resp[0:10],
        "key_version": resp[10],
        "scp_id": resp[11],
        "sequence_counter": resp[12:14],
        "card_challenge": resp[14:20],
        "card_cryptogram": resp[20:28],
    }


class GpSecureChannel:
    """Open + maintain an SCP02 secure channel with the Card Manager.

    Usage::

        gp = GpSecureChannel(connection)
        gp.open()  # uses default ISD keys
        gp.transmit_protected(INS_INSTALL, p1, p2, data)
        ...
    """

    def __init__(self, connection,
                 enc_key: bytes = DEFAULT_ISD_KEY,
                 mac_key: bytes = DEFAULT_ISD_KEY,
                 dek_key: bytes = DEFAULT_ISD_KEY):
        self._conn = connection
        self._k_enc = enc_key
        self._k_mac = mac_key
        self._k_dek = dek_key
        self.session: Optional[GpSession] = None

    # ---- raw transmit ----

    def _transmit_raw(self, apdu, command_label: str = "") -> bytes:
        from seedsigner.helpers.iso7816 import format_sw_error
        data, sw1, sw2 = self._conn.transmit(list(apdu))
        sw = ((sw1 & 0xFF) << 8) | (sw2 & 0xFF)
        if sw != SW_OK:
            if len(apdu) >= 5:
                cla, ins, p1, p2, lc = apdu[0], apdu[1], apdu[2], apdu[3], apdu[4]
                head = bytes(apdu[5:5 + min(8, max(0, len(apdu) - 5))]).hex()
                logger.warning(
                    "GP %s CLA=%02X INS=%02X P1=%02X P2=%02X Lc=%02X SW=%04X data_head=%s",
                    command_label or "?", cla, ins, p1, p2, lc, sw, head,
                )
            else:
                logger.warning("GP %s short APDU SW=%04X", command_label or "?", sw)
            raise GpProtocolError(format_sw_error(sw1, sw2))
        return bytes(data)

    # ---- handshake ----

    def select_isd(self, candidates=ISD_AID_CANDIDATES) -> bytes:
        """SELECT the ISD. Returns the AID that succeeded."""
        from seedsigner.helpers.iso7816 import format_sw_error
        last_error = None
        for aid in candidates:
            apdu = [0x00, INS_SELECT, 0x04, 0x00, len(aid)] + list(aid) + [0x00]
            data, sw1, sw2 = self._conn.transmit(apdu)
            sw = ((sw1 & 0xFF) << 8) | (sw2 & 0xFF)
            if sw == SW_OK:
                return aid
            last_error = format_sw_error(sw1, sw2)
        raise GpProtocolError(f"no ISD AID accepted: {last_error}")

    def get_extended_card_resources(self) -> "CardMemory":
        """Read GET DATA 0xFF21 (Extended Card Resources Information).

        Issued in the clear right after :meth:`select_isd` — this
        publicly-readable data object needs no secure channel (the same way
        ``gp --info`` reports free memory before authenticating). Raises
        :class:`GpProtocolError` (via :meth:`_transmit_raw`) if the card
        does not expose the tag, e.g. SW=0x6A88; callers treat that as
        "storage info unavailable".
        """
        resp = self._transmit_raw(
            [0x00, INS_GET_DATA,
             GET_DATA_P1_EXT_CARD_RESOURCES, GET_DATA_P2_EXT_CARD_RESOURCES,
             0x00],
            command_label="GET DATA[FF21]",
        )
        return parse_extended_card_resources(resp)

    def open(self, host_challenge: Optional[bytes] = None) -> GpSession:
        """Run INITIALIZE UPDATE + EXTERNAL AUTHENTICATE, returning the
        active session."""
        from os import urandom
        if host_challenge is None:
            host_challenge = urandom(8)

        resp = self._transmit_raw(
            _build_initialize_update(host_challenge),
            command_label="INITIALIZE UPDATE",
        )
        parsed = parse_initialize_update_response(resp)
        # We only implement SCP02 (i='15'). If the card negotiated a
        # different protocol the session-key KDF below would diverge from
        # whatever the card actually used and any authenticated command
        # would fail with 6982 / 6300 from the card's side. Bail early
        # with a clear message so the user isn't misled by the downstream
        # error.
        if parsed["scp_id"] != 0x02:
            raise GpProtocolError(
                f"unexpected SCP id 0x{parsed['scp_id']:02X} (expected 0x02)"
            )
        sequence = parsed["sequence_counter"]
        card_challenge = parsed["card_challenge"]
        card_cryptogram_received = parsed["card_cryptogram"]

        s_enc = derive_session_key(self._k_enc, KDF_CONST_S_ENC, sequence)
        s_mac = derive_session_key(self._k_mac, KDF_CONST_S_MAC, sequence)
        s_dek = derive_session_key(self._k_dek, KDF_CONST_S_DEK, sequence)

        # Verify the card cryptogram before sending anything authenticated.
        expected_card = cryptogram(s_enc,
                                   [host_challenge, sequence, card_challenge])
        if expected_card != card_cryptogram_received:
            raise GpProtocolError("card cryptogram mismatch")

        host_cryptogram = cryptogram(s_enc,
                                     [sequence, card_challenge, host_challenge])

        # Build EXTERNAL AUTHENTICATE: CLA_GP_MAC, INS=0x82,
        # P1=security_level (0x01 = CMAC), P2=0x00,
        # data = host_cryptogram(8) + cmac(8). cmac is computed over
        # CLA, INS, P1, P2, Lc=0x10 (= 16), host_cryptogram. ICV=zeros.
        cla = CLA_GP_MAC
        p1 = SECURITY_LEVEL_CMAC
        mac_input = bytes([cla, INS_EXTERNAL_AUTHENTICATE, p1, 0x00, 0x10]) + host_cryptogram
        cmac = retail_mac(s_mac, b"\x00" * 8, mac_input)
        ea_apdu = (
            [cla, INS_EXTERNAL_AUTHENTICATE, p1, 0x00, 0x10]
            + list(host_cryptogram) + list(cmac)
        )
        self._transmit_raw(ea_apdu, command_label="EXTERNAL AUTHENTICATE")

        # The MAC value (cmac) becomes the ICV's predecessor; per SCP02
        # the next command's ICV is encrypt(prev_mac, K1_MAC).
        next_icv = encrypt_icv(s_mac, cmac)
        self.session = GpSession(
            s_enc=s_enc, s_mac=s_mac, s_dek=s_dek,
            sequence_counter=sequence,
            card_challenge=card_challenge,
            icv=next_icv,
        )
        return self.session

    # ---- authenticated commands ----

    def transmit_protected_with_sw(self, ins: int, p1: int, p2: int,
                                   data: bytes = b"",
                                   command_label: str = "") -> tuple:
        """Send a CLA_GP_MAC command and return ``(response_data, sw)``.

        Unlike :meth:`transmit_protected`, this never raises on a non-9000
        SW: the caller decides which warning words (e.g. 6310 "more data
        available") preserve their accompanying data. Hard errors should
        be inspected via the returned SW.

        The MAC chaining ICV is updated on every successful exchange,
        regardless of SW, so a warning-class response leaves the channel
        usable for the follow-up command.
        """
        if self.session is None:
            raise GpProtocolError("secure channel not open")
        if not 0 <= len(data) <= 247:
            raise ValueError("APDU data too long for SCP02 with CMAC")

        cla = CLA_GP_MAC
        lc = len(data) + 8

        mac_input = bytes([cla, ins, p1, p2, lc]) + bytes(data)
        cmac = retail_mac(self.session.s_mac, self.session.icv, mac_input)

        apdu = [cla, ins, p1, p2, lc] + list(data) + list(cmac)
        resp_data, sw1, sw2 = self._conn.transmit(apdu)
        sw = ((sw1 & 0xFF) << 8) | (sw2 & 0xFF)

        # Update ICV chaining unconditionally so the next command's MAC
        # lines up with what the card expects.
        self.session = GpSession(
            s_enc=self.session.s_enc,
            s_mac=self.session.s_mac,
            s_dek=self.session.s_dek,
            sequence_counter=self.session.sequence_counter,
            card_challenge=self.session.card_challenge,
            icv=encrypt_icv(self.session.s_mac, cmac),
        )
        return bytes(resp_data), sw

    def transmit_protected(self, ins: int, p1: int, p2: int,
                           data: bytes = b"",
                           command_label: str = "") -> bytes:
        """Send a CLA_GP_MAC command authenticated with a fresh C-MAC.

        Raises :class:`GpProtocolError` on any non-9000 SW. ``command_label``
        is used only for logging on failure.
        """
        if self.session is None:
            raise GpProtocolError("secure channel not open")
        if not 0 <= len(data) <= 247:
            # 247 = 255 - 8 (header) leaves room for the MAC.
            raise ValueError("APDU data too long for SCP02 with CMAC")

        cla = CLA_GP_MAC
        lc = len(data) + 8  # +8 for the trailing C-MAC

        mac_input = bytes([cla, ins, p1, p2, lc]) + bytes(data)
        cmac = retail_mac(self.session.s_mac, self.session.icv, mac_input)

        apdu = [cla, ins, p1, p2, lc] + list(data) + list(cmac)
        resp = self._transmit_raw(apdu, command_label=command_label)
        # Update chaining ICV for the next command.
        self.session = GpSession(
            s_enc=self.session.s_enc,
            s_mac=self.session.s_mac,
            s_dek=self.session.s_dek,
            sequence_counter=self.session.sequence_counter,
            card_challenge=self.session.card_challenge,
            icv=encrypt_icv(self.session.s_mac, cmac),
        )
        return resp


# ---------------------------------------------------------------------------
# High-level operations
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AppletInstance:
    """One row from GET STATUS P1=0x40."""
    aid: bytes
    life_cycle: int
    privileges: int


@dataclass(frozen=True)
class CardMemory:
    """Free-memory snapshot from GET DATA 0xFF21.

    ``free_nv`` is the free persistent (EEPROM) memory in bytes — the only
    figure that matters for whether an applet will fit. ``free_volatile``
    is free transient (RAM) memory; ``num_apps`` is the number of installed
    applications the card reports. The card does **not** expose its *total*
    capacity, so callers derive ``total`` themselves (free + known footprint
    of the installed apps).
    """
    free_nv: int
    free_volatile: int
    num_apps: int


def parse_extended_card_resources(data: bytes) -> CardMemory:
    """Parse a GET DATA 0xFF21 (Extended Card Resources Information) response.

    Layout (GlobalPlatform Amendment / ETSI TS 102 226)::

        FF 21 LL
           81 LL  <number of installed applications>
           82 LL  <free non-volatile (persistent) memory, big-endian>
           83 LL  <free volatile (transient) memory, big-endian>

    Some cards return the bare inner TLVs without the outer ``FF21`` wrapper;
    both forms are accepted. Inner values are big-endian unsigned ints (1–4
    bytes); missing tags default to 0.
    """
    body = data
    # Strip an optional outer FF21 template (its length may be short- or
    # long-form). The inner SIMPLE-TLV objects always use short-form lengths.
    if len(body) >= 2 and body[0] == 0xFF and body[1] == 0x21:
        idx = 2
        if idx < len(body) and (body[idx] & 0x80):
            # Long-form: low 7 bits = number of subsequent length bytes.
            num_len_bytes = body[idx] & 0x7F
            idx += 1 + num_len_bytes
        else:
            idx += 1
        body = body[idx:]

    num_apps = 0
    free_nv = 0
    free_volatile = 0
    cur = 0
    while cur + 1 < len(body):
        tag = body[cur]
        length = body[cur + 1]
        value = body[cur + 2:cur + 2 + length]
        if len(value) < length:
            break  # truncated entry — bail rather than misparse
        value_int = int.from_bytes(value, "big") if value else 0
        if tag == 0x81:
            num_apps = value_int
        elif tag == 0x82:
            free_nv = value_int
        elif tag == 0x83:
            free_volatile = value_int
        cur += 2 + length
    return CardMemory(free_nv=free_nv, free_volatile=free_volatile,
                      num_apps=num_apps)


def _get_status_pages(channel: GpSecureChannel, p2_first: int) -> bytes:
    """Issue GET STATUS, paging on 6310, and return the concatenated payload.

    Returns ``b""`` if the card responds 6A88 ("Referenced data not found")
    or any other warning that means "no more entries". Raises
    :class:`GpProtocolError` for hard failures.
    """
    blob = b""
    p2_more = (p2_first & ~0x01) | 0x01  # set "next occurrence" bit
    cur_p2 = p2_first
    while True:
        resp, sw = channel.transmit_protected_with_sw(
            INS_GET_STATUS_GP, GP_STATUS_P1_APPLICATIONS, cur_p2,
            bytes([0x4F, 0x00]),
            command_label="GET STATUS",
        )
        if sw == SW_OK:
            blob += resp
            return blob
        if sw == 0x6310:
            blob += resp
            cur_p2 = p2_more
            continue
        if sw == 0x6A88:
            # No matching entries — return what we have (possibly empty).
            return blob
        # Anything else is a hard error.
        from seedsigner.helpers.iso7816 import format_sw_error
        raise GpProtocolError(format_sw_error((sw >> 8) & 0xFF, sw & 0xFF))


def list_instances(channel: GpSecureChannel) -> List[AppletInstance]:
    """Return every applet instance the Card Manager reports.

    Sends GET STATUS with P1=0x40 (applications). Tries the modern
    TLV format first (P2=0x02); if the card returns no entries (either
    empty data, ``0x6A88`` "no match", or ``0x6A86`` "wrong P1/P2"), falls
    back to the legacy non-TLV format (P2=0x00) which older cards expose.

    Both paths page on ``0x6310`` ("more data available") and concatenate
    the chunks before parsing.
    """
    # Modern TLV format.
    try:
        data = _get_status_pages(channel, p2_first=0x02)
    except GpProtocolError as exc:
        # Some cards reject P2=0x02 outright with 6A86 or 6A81 — fall
        # through to the legacy probe instead of giving up.
        msg = str(exc).lower()
        if "6a86" not in msg and "6a81" not in msg:
            raise
        data = b""
    logger.info(
        "GET STATUS P2=02 -> %d bytes head=%s",
        len(data), data[:16].hex() if data else "",
    )
    out = _parse_status_tlv(data)
    if out:
        return out

    # Legacy non-TLV format. Each entry is ``[AID_len][AID][life][privs]``
    # with no template wrapper and no inner tags; AIDs are 5..16 bytes.
    try:
        legacy = _get_status_pages(channel, p2_first=0x00)
    except GpProtocolError as exc:
        logger.warning("GET STATUS legacy probe failed: %s", exc)
        return out
    logger.info(
        "GET STATUS P2=00 -> %d bytes head=%s",
        len(legacy), legacy[:16].hex() if legacy else "",
    )
    return _parse_status_legacy(legacy)


MAX_KEYCARD_INSTANCES = 4


def keycard_instance_aid_candidates(prefix: bytes = bytes.fromhex("A000000804000101"),
                                    slots=None) -> List[bytes]:
    """Ordered, de-duped *suffixed* instance-AID candidates to probe by SELECT.

    Status cards initialised by keycard-cli/keycard-shell use the **9-byte
    canonical** instance AID ``prefix + slot``; instances minted by older
    SeedSigner builds use the **10-byte legacy** form ``prefix + 0x01 + slot``.
    We emit both so either is found regardless of which tool created it, the
    9-byte (real-card) form first. The bare ``prefix`` is **not** included —
    callers that want it (the GET-STATUS-empty fallback) prepend it themselves.

    Centralising this is deliberate: the suffix-probe loop used to be copied in
    three places with two different conventions, which is the drift that let a
    new instance collide with an existing slot.
    """
    if slots is None:
        slots = range(0x01, 0x01 + MAX_KEYCARD_INSTANCES)
    out: List[bytes] = []
    seen = set()
    for x in slots:
        for cand in (prefix + bytes([x]), prefix + bytes([0x01, x])):
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
    return out


def probe_keycard_instance_aids(connection,
                                package_prefix: bytes = bytes.fromhex("A000000804000101"),
                                instance_byte_range: range = range(0x01, 0x01 + MAX_KEYCARD_INSTANCES)
                                ) -> List[bytes]:
    """Brute-probe likely Keycard applet AIDs via cleartext SELECT.

    Used as a fallback for cards whose ISD does not expose installed
    applets via GET STATUS — we can still confirm an instance exists by
    SELECTing it. Sends one SELECT per candidate AID:

    * Bare ``package_prefix`` (no extra suffix), then
    * both the 9-byte ``package_prefix || X`` and 10-byte
      ``package_prefix || 0x01 || X`` forms for each ``X`` in
      ``instance_byte_range`` (see :func:`keycard_instance_aid_candidates`).

    Returns the AIDs that responded with SW=9000. Note: this side-effect
    SELECTs the *last responding* applet on the card, so callers should
    treat the connection as no longer holding a GP secure channel after
    this returns.
    """
    found: List[bytes] = []
    candidates: List[bytes] = [package_prefix] + keycard_instance_aid_candidates(
        package_prefix, instance_byte_range,
    )
    for aid in candidates:
        apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid) + [0x00]
        try:
            _, sw1, sw2 = connection.transmit(apdu)
        except Exception as exc:
            logger.debug("probe SELECT %s failed: %s", aid.hex(), exc)
            continue
        sw = ((sw1 & 0xFF) << 8) | (sw2 & 0xFF)
        if sw == SW_OK:
            found.append(aid)
    logger.info("probe_keycard_instance_aids: %d hits", len(found))
    return found


def _parse_status_legacy(payload: bytes) -> List[AppletInstance]:
    """Parse a GET STATUS legacy (non-TLV) response stream.

    Format per GP 2.1.1: a sequence of ``[AID_len(1)][AID(5..16)]
    [life_cycle(1)][privileges(1)]`` records, no delimiters.
    """
    out: List[AppletInstance] = []
    cur = 0
    while cur < len(payload):
        aid_len = payload[cur]
        if aid_len < 5 or aid_len > 16 or cur + 1 + aid_len + 2 > len(payload):
            # Malformed entry; bail out rather than guess.
            break
        aid = bytes(payload[cur + 1:cur + 1 + aid_len])
        life = payload[cur + 1 + aid_len]
        privs = payload[cur + 2 + aid_len]
        out.append(AppletInstance(aid=aid, life_cycle=life, privileges=privs))
        cur += 3 + aid_len
    return out


def _parse_status_tlv(payload: bytes) -> List[AppletInstance]:
    """Parse a GET STATUS TLV stream. Each entry is ``E3 LL ...`` (or
    ``E3 81 LL ...`` BER long-form) with inner tags ``4F`` (AID),
    ``9F70`` (life cycle) and ``C5`` (privileges)."""
    out: List[AppletInstance] = []
    cur = 0
    while cur < len(payload):
        if payload[cur] != 0xE3:
            cur += 1
            continue
        if cur + 1 >= len(payload):
            break
        length_byte = payload[cur + 1]
        if length_byte == 0x81:
            if cur + 2 >= len(payload):
                break
            length = payload[cur + 2]
            body = payload[cur + 3:cur + 3 + length]
            entry_size = 3 + length
        elif length_byte & 0x80:
            # Higher long-form (0x82, 0x83) — not expected from GET STATUS;
            # bail rather than misparse.
            break
        else:
            length = length_byte
            body = payload[cur + 2:cur + 2 + length]
            entry_size = 2 + length
        aid = b""
        life = 0
        privs = 0
        bcur = 0
        while bcur < len(body):
            tag = body[bcur]
            if tag == 0x4F:
                ll = body[bcur + 1]
                aid = bytes(body[bcur + 2:bcur + 2 + ll])
                bcur += 2 + ll
            elif tag == 0x9F:
                # Two-byte tag 9F70 (life cycle) — accept any length.
                tag2 = body[bcur + 1]
                ll = body[bcur + 2]
                if tag2 == 0x70 and ll >= 1:
                    life = body[bcur + 3]
                bcur += 3 + ll
            elif tag == 0xC5:
                ll = body[bcur + 1]
                if ll >= 1:
                    privs = body[bcur + 2]
                bcur += 2 + ll
            else:
                # Unknown tag: skip what we can.
                ll = body[bcur + 1]
                bcur += 2 + ll
        if aid:
            out.append(AppletInstance(aid=aid, life_cycle=life, privileges=privs))
        cur += entry_size
    return out


def install_for_install(channel: GpSecureChannel,
                        package_aid: bytes,
                        applet_aid: bytes,
                        instance_aid: bytes,
                        privileges: bytes = b"\x00",
                        install_params: bytes = b"") -> bytes:
    """INSTALL [for install and make selectable]."""
    if not (5 <= len(instance_aid) <= 16):
        raise ValueError("instance AID length must be 5..16 bytes")
    # data = LV-encoded list:
    #   package_aid_len ‖ package_aid
    # ‖ applet_aid_len  ‖ applet_aid
    # ‖ instance_aid_len ‖ instance_aid
    # ‖ priv_len ‖ priv
    # ‖ params_len ‖ (0xC9 ‖ params_inner_len ‖ params_inner)
    # ‖ token_len ‖ token (0)
    inner_params = bytes([0xC9, len(install_params)]) + install_params
    body = (
        bytes([len(package_aid)]) + package_aid
        + bytes([len(applet_aid)]) + applet_aid
        + bytes([len(instance_aid)]) + instance_aid
        + bytes([len(privileges)]) + privileges
        + bytes([len(inner_params)]) + inner_params
        + bytes([0])  # zero-length token
    )
    return channel.transmit_protected(
        INS_INSTALL, INSTALL_P1_FOR_INSTALL_AND_MAKE_SELECTABLE, 0x00, body,
        command_label="INSTALL[install+selectable]",
    )


# INSTALL [for install] alone — used as the first half of the two-step
# fallback when the combined "install + make selectable" form is rejected.
INSTALL_P1_FOR_INSTALL_ONLY = 0x04
INSTALL_P1_FOR_MAKE_SELECTABLE = 0x08


def install_for_make_selectable(channel: GpSecureChannel,
                                instance_aid: bytes) -> bytes:
    """INSTALL [for make selectable] on an already-installed instance.

    Used as the second step of the two-APDU install sequence on cards
    that reject the combined ``P1=0x0C`` form.
    """
    body = (
        bytes([0])  # zero-length package AID
        + bytes([0])  # zero-length applet AID
        + bytes([len(instance_aid)]) + instance_aid
        + bytes([0])  # zero-length privileges
        + bytes([0])  # zero-length params
        + bytes([0])  # zero-length token
    )
    return channel.transmit_protected(
        INS_INSTALL, INSTALL_P1_FOR_MAKE_SELECTABLE, 0x00, body,
        command_label="INSTALL[selectable]",
    )


def install_for_install_with_fallback(channel: GpSecureChannel,
                                      package_aid: bytes,
                                      applet_aid: bytes,
                                      instance_aid: bytes,
                                      privileges: bytes = b"\x00",
                                      install_params: bytes = b"") -> bytes:
    """INSTALL with fallback for cards that reject the combined P1=0x0C.

    Tries the canonical ``INSTALL [for install + make selectable]``
    first. If the card refuses with ``0x6982`` (security status not
    satisfied) — which on some applet/JCRE combinations indicates the
    lifecycle handler wants the two phases sent separately — retries
    with ``INSTALL [for install]`` (P1=0x04) followed by
    ``INSTALL [for make selectable]`` (P1=0x08).

    Other status words propagate from the first attempt unchanged.
    """
    try:
        return install_for_install(
            channel, package_aid, applet_aid, instance_aid,
            privileges=privileges, install_params=install_params,
        )
    except GpProtocolError as exc:
        if "6982" not in str(exc):
            raise
        logger.warning(
            "INSTALL[install+selectable] returned 6982; trying split form",
        )

    inner_params = bytes([0xC9, len(install_params)]) + install_params
    body = (
        bytes([len(package_aid)]) + package_aid
        + bytes([len(applet_aid)]) + applet_aid
        + bytes([len(instance_aid)]) + instance_aid
        + bytes([len(privileges)]) + privileges
        + bytes([len(inner_params)]) + inner_params
        + bytes([0])  # zero-length token
    )
    channel.transmit_protected(
        INS_INSTALL, INSTALL_P1_FOR_INSTALL_ONLY, 0x00, body,
        command_label="INSTALL[install]",
    )
    return install_for_make_selectable(channel, instance_aid)


def delete_aid(channel: GpSecureChannel, aid: bytes,
               with_related: bool = True) -> bytes:
    """DELETE the applet instance ``aid``.

    With ``with_related=True`` (P2=0x80) the Card Manager also deletes
    related objects (instance + executable load file references).
    """
    p2 = 0x80 if with_related else 0x00
    body = bytes([0x4F, len(aid)]) + bytes(aid)
    return channel.transmit_protected(
        INS_DELETE, 0x00, p2, body, command_label="DELETE",
    )
