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
INS_INSTALL = 0xE6
INS_DELETE = 0xE4
INS_SELECT = 0xA4

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

    def _transmit_raw(self, apdu) -> bytes:
        from seedsigner.helpers.iso7816 import format_sw_error
        data, sw1, sw2 = self._conn.transmit(list(apdu))
        sw = ((sw1 & 0xFF) << 8) | (sw2 & 0xFF)
        if sw != SW_OK:
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

    def open(self, host_challenge: Optional[bytes] = None) -> GpSession:
        """Run INITIALIZE UPDATE + EXTERNAL AUTHENTICATE, returning the
        active session."""
        from os import urandom
        if host_challenge is None:
            host_challenge = urandom(8)

        resp = self._transmit_raw(_build_initialize_update(host_challenge))
        parsed = parse_initialize_update_response(resp)
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
        self._transmit_raw(ea_apdu)

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

    def transmit_protected(self, ins: int, p1: int, p2: int,
                           data: bytes = b"") -> bytes:
        """Send a CLA_GP_MAC command authenticated with a fresh C-MAC."""
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
        resp = self._transmit_raw(apdu)
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


def list_instances(channel: GpSecureChannel) -> List[AppletInstance]:
    """Return every applet instance the Card Manager reports.

    Sends GET STATUS with P1=0x40 (applications), P2=0x02 (TLV format),
    data = ``4F 00`` (empty AID = list all). Loops while the response
    SW is ``0x6310`` (more data).
    """
    out: List[AppletInstance] = []
    p2 = 0x02  # TLV format
    p2_more = 0x03  # repeat with "next occurrence"
    cur_p2 = p2
    while True:
        try:
            data = channel.transmit_protected(
                INS_GET_STATUS_GP, GP_STATUS_P1_APPLICATIONS, cur_p2,
                bytes([0x4F, 0x00]),
            )
            more = False
        except GpProtocolError as exc:
            # 6310 means "more data available"; the response payload was
            # already consumed by transmit_protected raising; we'd have
            # to teach transmit_raw to return the payload too. For now,
            # treat a single round as good-enough; cards rarely have
            # >5 applets.
            if "6310" in str(exc):
                more = True
                break
            raise
        out.extend(_parse_status_tlv(data))
        if not more:
            break
        cur_p2 = p2_more
    return out


def _parse_status_tlv(payload: bytes) -> List[AppletInstance]:
    """Parse a GET STATUS TLV stream. Each entry is ``E3 LL ...`` with
    inner tags ``4F`` (AID), ``9F70`` (life cycle) and ``C5`` (privileges)."""
    out: List[AppletInstance] = []
    cur = 0
    while cur < len(payload):
        if payload[cur] != 0xE3:
            cur += 1
            continue
        # Length: short form only for our purposes.
        length = payload[cur + 1]
        body = payload[cur + 2:cur + 2 + length]
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
        cur += 2 + length
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
    )


def delete_aid(channel: GpSecureChannel, aid: bytes,
               with_related: bool = True) -> bytes:
    """DELETE the applet instance ``aid``.

    With ``with_related=True`` (P2=0x80) the Card Manager also deletes
    related objects (instance + executable load file references).
    """
    p2 = 0x80 if with_related else 0x00
    body = bytes([0x4F, len(aid)]) + bytes(aid)
    return channel.transmit_protected(INS_DELETE, 0x00, p2, body)
