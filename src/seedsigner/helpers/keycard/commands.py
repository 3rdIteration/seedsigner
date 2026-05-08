"""APDU commands for the Status Keycard JavaCard applet.

Reference: https://keycard.tech/docs/apdu/ and
https://github.com/status-im/status-keycard/blob/master/src/main/java/im/status/keycard/applet/KeycardApplet.java
"""

from __future__ import annotations

from typing import Iterable, List, Optional

# Application AID published by Status Keycard.
APPLET_AID = bytes.fromhex("A0000008040001010101")

# Class bytes
CLA_ISO7816 = 0x00
CLA_PROPRIETARY = 0x80
CLA_PROTECTED = 0x84  # encrypted (post secure channel open)

# Instructions
INS_SELECT = 0xA4
INS_OPEN_SECURE_CHANNEL = 0x10
INS_MUTUALLY_AUTHENTICATE = 0x11
INS_PAIR = 0x12
INS_UNPAIR = 0x13
INS_IDENTIFY_CARD = 0x14
INS_VERIFY_PIN = 0x20
INS_CHANGE_PIN = 0x21
INS_UNBLOCK_PIN = 0x22
INS_LOAD_KEY = 0xD0
INS_DERIVE_KEY = 0xD1
INS_GENERATE_MNEMONIC = 0xD2
INS_REMOVE_KEY = 0xD3
INS_GENERATE_KEY = 0xD4
INS_DUPLICATE_KEY = 0xD5
INS_SIGN = 0xC0
INS_SET_PINLESS_PATH = 0xC1
INS_EXPORT_KEY = 0xC2
INS_GET_STATUS = 0xF2
INS_INIT = 0xFE

# DERIVE KEY P1 source
DERIVE_P1_FROM_MASTER = 0x00
DERIVE_P1_FROM_PARENT = 0x40
DERIVE_P1_FROM_CURRENT = 0x80

# EXPORT KEY P1
EXPORT_P1_CURRENT = 0x00
EXPORT_P1_DERIVE = 0x01
EXPORT_P1_DERIVE_AND_MAKE_CURRENT = 0x02

# EXPORT KEY P2
EXPORT_P2_PRIVATE_AND_PUBLIC = 0x00
EXPORT_P2_PUBLIC_ONLY = 0x01
EXPORT_P2_EXTENDED_PUBLIC = 0x02

# SIGN P1
SIGN_P1_CURRENT_KEY = 0x00
SIGN_P1_DERIVE = 0x01
SIGN_P1_DERIVE_AND_MAKE_CURRENT = 0x02
SIGN_P1_PINLESS = 0x03

# Status word for "OK"
SW_OK = 0x9000


class APDUError(Exception):
    def __init__(self, sw: int, message: str):
        super().__init__(f"{message} (SW={sw:04X})")
        self.sw = sw


def build_apdu(cla: int, ins: int, p1: int, p2: int, data: bytes = b"", le: Optional[int] = None) -> List[int]:
    if not 0 <= len(data) <= 255:
        raise ValueError("APDU data must be 0..255 bytes (no extended length)")
    apdu = [cla, ins, p1, p2]
    if data:
        apdu.append(len(data))
        apdu.extend(data)
    if le is not None:
        apdu.append(le)
    return apdu


def select_applet(aid: bytes = APPLET_AID) -> List[int]:
    return build_apdu(CLA_ISO7816, INS_SELECT, 0x04, 0x00, aid)


def identify_card(challenge: bytes) -> List[int]:
    if len(challenge) != 32:
        raise ValueError("IDENTIFY requires a 32-byte challenge")
    return build_apdu(CLA_PROPRIETARY, INS_IDENTIFY_CARD, 0x00, 0x00, challenge)


def init(pin: bytes, puk: bytes, pairing_secret: bytes) -> List[int]:
    if len(pin) != 6:
        raise ValueError("PIN must be 6 ASCII digits")
    if len(puk) != 12:
        raise ValueError("PUK must be 12 ASCII digits")
    if len(pairing_secret) != 32:
        raise ValueError("pairing secret must be 32 bytes")
    return build_apdu(
        CLA_PROPRIETARY, INS_INIT, 0x00, 0x00,
        bytes(pin) + bytes(puk) + bytes(pairing_secret),
    )


def pair_step1(challenge: bytes) -> List[int]:
    if len(challenge) != 32:
        raise ValueError("PAIR step 1 challenge must be 32 bytes")
    return build_apdu(CLA_PROPRIETARY, INS_PAIR, 0x00, 0x00, challenge)


def pair_step2(client_cryptogram: bytes) -> List[int]:
    if len(client_cryptogram) != 32:
        raise ValueError("PAIR step 2 cryptogram must be 32 bytes")
    return build_apdu(CLA_PROPRIETARY, INS_PAIR, 0x01, 0x00, client_cryptogram)


def unpair(pairing_index: int) -> List[int]:
    return build_apdu(CLA_PROPRIETARY, INS_UNPAIR, pairing_index, 0x00)


def open_secure_channel(pairing_index: int, ephemeral_pubkey: bytes) -> List[int]:
    if len(ephemeral_pubkey) != 65 or ephemeral_pubkey[0] != 0x04:
        raise ValueError("ephemeral pubkey must be 65-byte uncompressed (0x04 prefix)")
    return build_apdu(
        CLA_PROPRIETARY, INS_OPEN_SECURE_CHANNEL, pairing_index, 0x00, ephemeral_pubkey,
    )


def mutually_authenticate(payload: bytes) -> List[int]:
    return build_apdu(CLA_PROTECTED, INS_MUTUALLY_AUTHENTICATE, 0x00, 0x00, payload)


def get_status(p1: int = 0x00) -> List[int]:
    # P1=0x00: application status; P1=0x01: key path
    return build_apdu(CLA_PROPRIETARY, INS_GET_STATUS, p1, 0x00, b"", le=0x00)


def verify_pin(pin: bytes) -> List[int]:
    if len(pin) != 6:
        raise ValueError("PIN must be 6 ASCII digits")
    return build_apdu(CLA_PROPRIETARY, INS_VERIFY_PIN, 0x00, 0x00, bytes(pin))


def change_pin(p1: int, new_secret: bytes) -> List[int]:
    return build_apdu(CLA_PROPRIETARY, INS_CHANGE_PIN, p1, 0x00, bytes(new_secret))


def generate_key() -> List[int]:
    return build_apdu(CLA_PROPRIETARY, INS_GENERATE_KEY, 0x00, 0x00)


def remove_key() -> List[int]:
    return build_apdu(CLA_PROPRIETARY, INS_REMOVE_KEY, 0x00, 0x00)


def derive_key(path_components: Iterable[int], source: int = DERIVE_P1_FROM_MASTER) -> List[int]:
    components = list(path_components)
    if not components:
        # empty path = master key (already current after FROM_MASTER)
        return build_apdu(CLA_PROPRIETARY, INS_DERIVE_KEY, source, 0x00)
    data = b"".join(int(c & 0xFFFFFFFF).to_bytes(4, "big") for c in components)
    return build_apdu(CLA_PROPRIETARY, INS_DERIVE_KEY, source, 0x00, data)


def export_key(p1: int = EXPORT_P1_CURRENT, p2: int = EXPORT_P2_PUBLIC_ONLY,
               path_components: Optional[Iterable[int]] = None) -> List[int]:
    data = b""
    if path_components is not None:
        data = b"".join(int(c & 0xFFFFFFFF).to_bytes(4, "big") for c in path_components)
    return build_apdu(CLA_PROPRIETARY, INS_EXPORT_KEY, p1, p2, data, le=0x00)


def sign(hash_to_sign: bytes, p1: int = SIGN_P1_CURRENT_KEY,
         path_components: Optional[Iterable[int]] = None) -> List[int]:
    if len(hash_to_sign) != 32:
        raise ValueError("Keycard SIGN requires a 32-byte hash")
    data = bytes(hash_to_sign)
    if path_components is not None:
        data = data + b"".join(int(c & 0xFFFFFFFF).to_bytes(4, "big") for c in path_components)
    return build_apdu(CLA_PROPRIETARY, INS_SIGN, p1, 0x00, data, le=0x00)


def parse_path(path: str) -> List[int]:
    """Parse a BIP-32 path like "m/44'/60'/0'/0/0" into integer components.

    Hardened components (with apostrophe) get the high bit set.
    """
    s = path.strip()
    if s.startswith("m/"):
        s = s[2:]
    elif s == "m":
        return []
    if not s:
        return []
    out: List[int] = []
    for part in s.split("/"):
        hardened = False
        if part.endswith("'") or part.endswith("h") or part.endswith("H"):
            hardened = True
            part = part[:-1]
        if not part.isdigit():
            raise ValueError(f"invalid path component: {part!r}")
        idx = int(part)
        if idx >= 0x80000000:
            raise ValueError("path component out of range")
        if hardened:
            idx |= 0x80000000
        out.append(idx)
    return out
