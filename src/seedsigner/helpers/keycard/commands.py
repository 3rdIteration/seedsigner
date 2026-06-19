"""APDU commands for the Status Keycard JavaCard applet.

Reference: https://keycard.tech/docs/apdu/ and
https://github.com/status-im/status-keycard/blob/master/src/main/java/im/status/keycard/applet/KeycardApplet.java
"""

from __future__ import annotations

import hmac
from typing import Iterable, List, Optional

# Status Keycard signing-instance AID, 9-byte canonical form
# (KEYCARD_APPLET_AID prefix ``A000000804000101`` + slot ``01``). This is the
# form keycard-cli / keycard-shell and real Status cards use, and the form
# SeedSigner now mints for *every* instance (blank-card install + Create
# instance). It is the boot-default ``active_keycard_aid`` and the first-try
# SELECT target; ``select_with_autodetect`` still probes the 10-byte legacy
# form (``…010101``, minted by older builds) so previously-created cards work.
APPLET_AID = bytes.fromhex("A00000080400010101")

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
INS_FACTORY_RESET = 0xFD

# FACTORY_RESET requires fixed magic bytes in P1/P2 to defeat accidental
# triggers (Status Keycard convention; see KeycardApplet.java).
FACTORY_RESET_P1_MAGIC = 0xAA
FACTORY_RESET_P2_MAGIC = 0x55

# LOAD KEY P1 (key import format) — Status Keycard applet:
#   0x01 = EC keypair TLV (no chain code)
#   0x02 = extended EC keypair TLV (privkey + 32-byte chain code)
#   0x03 = 64-byte BIP-39 binary seed (raw, no TLV) — what we send
LOAD_KEY_P1_EC = 0x01
LOAD_KEY_P1_EXT_EC = 0x02
LOAD_KEY_P1_BIP39_SEED = 0x03

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

# PAIR P2 (introduced in applet v3.2 / commit 731314f).
# v3.1 cards ignore P2 entirely and behave as PERSISTENT.
PAIR_P2_ANY = 0x00         # tries persistent slot, falls back to ephemeral
PAIR_P2_EPHEMERAL = 0x01   # always ephemeral, never consumes a card slot
PAIR_P2_PERSISTENT = 0x02  # always persistent, SW=6A84 if no slot free

# Pairing index returned by PAIR step 2 when ephemeral pairing was used,
# and accepted by OPEN_SECURE_CHANNEL / UNPAIR to address the ephemeral key.
EPHEMERAL_PAIRING_INDEX = 0xFF

# v3.2 applet version (major<<8 | minor). Cards reporting >= this in the
# SELECT response support the ephemeral pairing extensions.
APP_VERSION_EPHEMERAL_PAIRING = 0x0302

# Status word for "OK"
SW_OK = 0x9000


def supports_ephemeral_pairing(app_version: int) -> bool:
    """True when the applet at ``app_version`` understands PAIR P2=0x01.

    v3.1 cards (0x0301) do not branch on P2 and would silently allocate a
    persistent slot if asked for ephemeral. Gate the ephemeral flow on
    this check so we don't burn pairing slots on older firmware.
    """
    return app_version >= APP_VERSION_EPHEMERAL_PAIRING


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


def factory_reset() -> List[int]:
    """Wipe PIN, PUK, pairings and master key from the card.

    Cleartext command (does NOT require an open secure channel). The
    fixed magic in P1/P2 is the on-card sanity check.
    """
    return build_apdu(
        CLA_PROPRIETARY, INS_FACTORY_RESET,
        FACTORY_RESET_P1_MAGIC, FACTORY_RESET_P2_MAGIC,
    )


def init(pin: bytes, puk: bytes, pairing_secret: bytes) -> List[int]:
    """Legacy plaintext INIT builder. Kept for unit tests; not used by
    KeycardClient anymore — Status Keycard 3.x rejects this format with
    SW=6A80 and the wire-correct path lives in
    :func:`init_encrypted`.
    """
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


# INIT max-attempts defaults. The 50-byte INIT form lets the applet apply its
# own compiled-in retry limits; the moment we send the 58-byte form (to set a
# duress/alt PIN) we MUST supply both counters — there is no "use default"
# sentinel. These mirror KeycardApplet.java's DEFAULT_PIN_MAX_RETRIES (3) /
# DEFAULT_PUK_MAX_RETRIES (5) — the exact limits a classic 50-byte init
# applies — so enabling the duress PIN does NOT silently change the card's
# retry limits. (The applet validates PIN in 2..PIN_MAX_RETRIES=10 and PUK in
# 3..PUK_MAX_RETRIES=12, so raising these is allowed if ever desired.) Keep in
# sync with the applet.
DEFAULT_MAX_PIN_ATTEMPTS = 3
DEFAULT_MAX_PUK_ATTEMPTS = 5


def build_init_plaintext(
    pin: bytes,
    puk: bytes,
    pairing_secret: bytes,
    duress_pin: Optional[bytes] = None,
    max_pin_attempts: int = DEFAULT_MAX_PIN_ATTEMPTS,
    max_puk_attempts: int = DEFAULT_MAX_PUK_ATTEMPTS,
) -> bytes:
    """Assemble the cleartext INIT payload (the bytes the applet decrypts).

    The Status Keycard applet's INIT accepts exactly three payload lengths
    (see ``KeycardApplet.processInit``):

    * 50 bytes — ``PIN(6) || PUK(12) || pairingSecret(32)`` (classic form;
      applet uses its own retry limits and defaults the alt PIN to PUK[:6]).
    * 52 bytes — ``+ maxPINAttempts(1) || maxPUKAttempts(1)``.
    * 58 bytes — ``+ altPIN(6)`` — the duress PIN.

    Without ``duress_pin`` this returns the 50-byte form, byte-identical to
    the historic ``client.init`` behaviour. With ``duress_pin`` it returns
    the 58-byte form (the only way to set the alt PIN forces the two
    max-attempts bytes too).

    The alt/duress PIN MUST differ from the main PIN: the applet's
    ``verifyPIN`` matches *both* an equal alt PIN and routes to the decoy
    chain code, so only the decoy is reachable until the two PINs are made
    distinct again (the real key material is never lost — `verifyPIN`
    re-decides routing on every unlock — but it is a confusing footgun). We
    reject the collision here as defence in depth (the UI guards it too).
    """
    if len(pin) != 6:
        raise ValueError("PIN must be 6 ASCII digits")
    if len(puk) != 12:
        raise ValueError("PUK must be 12 ASCII digits")
    if len(pairing_secret) != 32:
        raise ValueError("pairing secret must be 32 bytes")

    if duress_pin is None:
        return bytes(pin) + bytes(puk) + bytes(pairing_secret)

    if len(duress_pin) != 6:
        raise ValueError("duress PIN must be 6 ASCII digits")
    if not 1 <= max_pin_attempts <= 0xFF:
        raise ValueError("max_pin_attempts must be 1..255")
    if not 1 <= max_puk_attempts <= 0xFF:
        raise ValueError("max_puk_attempts must be 1..255")
    if hmac.compare_digest(bytes(pin), bytes(duress_pin)):
        raise ValueError("duress PIN must differ from main PIN")

    return (
        bytes(pin)
        + bytes(puk)
        + bytes(pairing_secret)
        + bytes([max_pin_attempts, max_puk_attempts])
        + bytes(duress_pin)
    )


def init_encrypted(client_pub: bytes, iv: bytes, ciphertext: bytes) -> List[int]:
    """Build an INIT APDU in the Status Keycard one-shot-encrypted format.

    Wire layout (matches ``SecureChannel.oneShotDecrypt`` in the applet):
      ``pub_len(1) || client_pubkey(pub_len) || iv(16) || ciphertext``
    where ciphertext = AES-256-CBC(ECDH_x(client_priv, card_static_pub),
    iv, ISO9797-M2-pad(PIN || PUK || pairing_secret)). The leading
    length byte is read at OFFSET_CDATA by the applet (line 100 of
    ``SecureChannel.java``: ``apduBuffer[ISO7816.OFFSET_CDATA]``);
    omitting it makes the applet read 16 bytes of pubkey-as-IV and
    decrypt garbage, leading to SW=6A80 on the post-decrypt validation.
    """
    if len(client_pub) != 65 or client_pub[0] != 0x04:
        raise ValueError(
            "client pubkey must be 65-byte uncompressed (0x04 prefix)"
        )
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    if not ciphertext or len(ciphertext) % 16 != 0:
        raise ValueError("ciphertext must be a non-empty multiple of 16")
    return build_apdu(
        CLA_PROPRIETARY, INS_INIT, 0x00, 0x00,
        bytes([len(client_pub)]) + bytes(client_pub) + bytes(iv) + bytes(ciphertext),
    )


def pair_step1(challenge: bytes, p2: int = PAIR_P2_PERSISTENT) -> List[int]:
    """PAIR step 1.

    ``p2`` selects pairing type on v3.2+ applets:
      * ``PAIR_P2_PERSISTENT`` (0x02, default): consume a slot; fail if full.
      * ``PAIR_P2_EPHEMERAL`` (0x01): in-RAM only; cleared on deselect.
      * ``PAIR_P2_ANY`` (0x00): persistent if a slot is free, else ephemeral.

    v3.1 cards ignore ``p2`` and always behave as persistent.
    """
    if len(challenge) != 32:
        raise ValueError("PAIR step 1 challenge must be 32 bytes")
    return build_apdu(CLA_PROPRIETARY, INS_PAIR, 0x00, p2, challenge)


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


GENERATE_MNEMONIC_VALID_WORD_COUNTS = (12, 15, 18, 21, 24)


def generate_mnemonic(word_count: int) -> List[int]:
    """GENERATE MNEMONIC APDU.

    P1 is the "checksum size" word — Status applet uses the same parameter
    naming as BIP-39 entropy/32: 4→12 words, 5→15, 6→18, 7→21, 8→24.

    Response body is ``2 * word_count`` bytes: pairs of 16-bit big-endian
    indices into the BIP-39 wordlist. Caller is responsible for mapping
    indices to words.

    Sent over the secure channel; does NOT require PIN verification.
    """
    if word_count not in GENERATE_MNEMONIC_VALID_WORD_COUNTS:
        raise ValueError(
            f"word_count must be one of {GENERATE_MNEMONIC_VALID_WORD_COUNTS}"
        )
    p1 = word_count // 3
    # Le=0x00 → request "all available" bytes; secure-channel wrapper will
    # honour Lr from the card.
    return build_apdu(
        CLA_PROPRIETARY, INS_GENERATE_MNEMONIC, p1, 0x00, b"", le=0x00,
    )


def load_bip39_seed(seed64: bytes) -> List[int]:
    """LOAD KEY APDU for the 64-byte BIP-39 seed.

    The card derives the master key on-card from the supplied seed
    (HMAC-SHA512 with the standard "Bitcoin seed" key per BIP-32).

    The APDU is sent over the secure channel (the caller must have
    verified the PIN). The CLA is the *plaintext* proprietary class
    here; the secure channel wrapper switches it to ``CLA_PROTECTED``
    when the call goes through ``_transmit_protected``.
    """
    if len(seed64) != 64:
        raise ValueError("BIP-39 seed must be exactly 64 bytes")
    return build_apdu(
        CLA_PROPRIETARY, INS_LOAD_KEY,
        LOAD_KEY_P1_BIP39_SEED, 0x00,
        bytes(seed64),
    )


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
