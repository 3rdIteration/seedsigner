"""Status Keycard secure channel.

Reference: https://github.com/status-im/status-keycard/blob/master/docs/sdk-flow.md
and the JavaCard applet ``SecureChannel`` implementation.

Pairing flow
------------
PAIR P1=0x00, data=client_challenge(32):
    card returns: card_cryptogram(32) || card_challenge(32)
    where card_cryptogram = SHA256(pairing_secret || client_challenge).

PAIR P1=0x01, data=client_cryptogram(32):
    where client_cryptogram = SHA256(pairing_secret || card_challenge).
    Card returns: pairing_index(1) || pairing_salt(32).
    Final pairing_key = SHA256(pairing_secret || pairing_salt).

Open Secure Channel flow
------------------------
1. Client generates ephemeral secp256k1 keypair (priv_e, pub_e).
2. OPEN_SECURE_CHANNEL P1=pairing_index, data=pub_e.
3. Card returns 48 bytes: salt(32) || iv_seed(16).
4. Both compute shared = ECDH_x(priv_e, card_static_pub).
5. session_keys = SHA512(shared || pairing_key || salt)
   enc_key  = session_keys[:32]
   mac_key  = session_keys[32:]
6. Initial IV = iv_seed.
7. Client sends MUTUALLY_AUTHENTICATE with a 32-byte client_challenge encrypted
   under the channel.  Card replies with 32 bytes (its own challenge).
   Both sides update IV after every command.

Protected APDU format
---------------------
CLA = 0x84.  Lc = 16 + len(ciphertext).  Data = ciphertext
(ISO/IEC 9797-1 method 2 padded, AES-256-CBC). After encryption, the
MAC is prepended:  data_field = mac(16) || ciphertext.

MAC inputs:

* Command:  ``[CLA, INS, P1, P2, Lc, 0×11, ciphertext]``  (16 + len(ct) bytes)
* Response: ``[Lr, 0×15, ciphertext]``                    (16 + len(ct) bytes)

Where ``Lr`` is the **total** response length (MAC + ciphertext) — i.e.
``16 + len(ciphertext)``, NOT just ``len(ciphertext)``. This matches
``SecureChannel.java`` (Status applet) line ``apduBuffer[0] = (byte)
(len + SC_BLOCK_SIZE);`` and ``app/keycard/secure_channel.c``
(keycard-shell) ``data[0] = apdu->lr;``.

The MAC uses an all-zero IV and the *first* output block. After every
command/response the AES-CBC encryption IV is replaced by the MAC.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from seedsigner.helpers.iso7816 import format_sw_error

from . import crypto
from .commands import APDUError, SW_OK


@dataclass
class PairingInfo:
    pairing_index: int
    pairing_key: bytes  # 32 bytes


class SecureChannelError(Exception):
    pass


class SecureChannel:
    def __init__(self, pairing: PairingInfo, card_static_pub: bytes):
        if len(pairing.pairing_key) != 32:
            raise ValueError("pairing key must be 32 bytes")
        if len(card_static_pub) != 65 or card_static_pub[0] != 0x04:
            raise ValueError("card static pubkey must be 65-byte uncompressed")
        self.pairing = pairing
        self.card_static_pub = card_static_pub
        self._enc_key: Optional[bytes] = None
        self._mac_key: Optional[bytes] = None
        self._iv: Optional[bytes] = None
        self._client_priv: Optional[bytes] = None
        self._client_pub: Optional[bytes] = None

    @property
    def is_open(self) -> bool:
        return self._enc_key is not None and self._iv is not None

    def begin_open(self) -> bytes:
        """Return the ephemeral public key to send in OPEN_SECURE_CHANNEL."""
        priv, pub = crypto.secp256k1_generate_keypair()
        self._client_priv = priv
        self._client_pub = pub
        return pub

    def derive_session_from(self, card_response: bytes) -> None:
        """Apply the card's response (salt(32) || iv(16)) to derive session keys."""
        if self._client_priv is None:
            raise SecureChannelError("call begin_open() first")
        if len(card_response) != 48:
            raise SecureChannelError(
                f"expected 48-byte open-channel response, got {len(card_response)}"
            )
        salt = card_response[:32]
        iv = card_response[32:]

        shared = crypto.secp256k1_ecdh(self._client_priv, self.card_static_pub)
        session = crypto.sha512(shared + self.pairing.pairing_key + salt)
        self._enc_key = session[:32]
        self._mac_key = session[32:]
        self._iv = iv

    def wrap_command(self, cla: int, ins: int, p1: int, p2: int, data: bytes) -> bytes:
        """Encrypt ``data`` and prepend the MAC.  Returns the new APDU data field."""
        if not self.is_open:
            raise SecureChannelError("secure channel not open")
        ciphertext = crypto.aes_cbc_encrypt(self._enc_key, self._iv, data)
        mac_input = bytes([cla, ins, p1, p2, len(ciphertext) + 16]) + b"\x00" * 11 + ciphertext
        mac = crypto.aes_cbc_block(self._mac_key, b"\x00" * 16, mac_input)
        self._iv = mac
        return mac + ciphertext

    def unwrap_response(self, response: bytes) -> bytes:
        """Verify MAC, decrypt, and split off the inner status word.

        The Status applet's ``SecureChannel.respond()`` appends the
        applet's two-byte SW (the one the user actually cares about) to
        the response data BEFORE padding and AES-CBC encryption — the
        outer SW that ``KeycardClient.transmit()`` checks is just the
        secure-channel envelope and is almost always ``0x9000`` while the
        inner SW carries the real verdict (wrong PIN, no key, etc.).

        Until 2026-05-11 this method returned the full decrypted payload
        ``data || sw1 || sw2`` and every caller silently ignored the
        trailing two bytes. That meant a wrong PIN succeeded "silently"
        on ``VERIFY_PIN`` and only blew up on the next operation with the
        infamous ``Parse fail resp=6985``. We now strip and check the
        inner SW here so the failure surfaces on the operation that
        actually failed, with the correct status word.
        """
        if not self.is_open:
            raise SecureChannelError("secure channel not open")
        if len(response) < 32 or len(response) % 16 != 0:
            raise SecureChannelError("response must be 16-byte aligned and >= 32 bytes")
        mac, ciphertext = response[:16], response[16:]

        # The Status applet's `respond()` writes the *total* response
        # length (MAC(16) + ciphertext) into the first byte of the MAC
        # input — see SecureChannel.java `respond()`:
        #     apduBuffer[0] = (byte) (len + SC_BLOCK_SIZE);
        # We had `len(ciphertext)` here, which always mismatched the
        # card and surfaced as "response MAC mismatch" on the
        # MUTUALLY_AUTHENTICATE reply, blocking every secure channel.
        mac_input = bytes([len(response) & 0xFF]) + b"\x00" * 15 + ciphertext
        expected = crypto.aes_cbc_block(self._mac_key, b"\x00" * 16, mac_input)
        if expected != mac:
            raise SecureChannelError("response MAC mismatch")

        plaintext = crypto.aes_cbc_decrypt(self._enc_key, self._iv, ciphertext)
        # The IV chain must advance regardless of the inner SW so the
        # next command/response stays in lockstep with the card.
        self._iv = mac

        if len(plaintext) < 2:
            raise SecureChannelError(
                "decrypted payload too short to carry a status word"
            )
        sw1, sw2 = plaintext[-2], plaintext[-1]
        sw = ((sw1 & 0xFF) << 8) | (sw2 & 0xFF)
        if sw != SW_OK:
            raise APDUError(sw, format_sw_error(sw1, sw2))
        return plaintext[:-2]


def derive_pairing_key(pairing_secret: bytes, pairing_salt: bytes) -> bytes:
    return crypto.sha256(pairing_secret + pairing_salt)


def expected_card_cryptogram(pairing_secret: bytes, client_challenge: bytes) -> bytes:
    return crypto.sha256(pairing_secret + client_challenge)


def client_cryptogram(pairing_secret: bytes, card_challenge: bytes) -> bytes:
    return crypto.sha256(pairing_secret + card_challenge)
