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
CLA = 0x84.  Lc = len(ciphertext).  Data = ciphertext (PKCS#7 padded, AES-256-CBC).
After encryption, MAC is prepended:  data_field = mac(16) || ciphertext.
MAC = AES-256-CBC of  (header(4) || padded_lc_block || ciphertext) under mac_key
       with current IV; the *first* output block is the MAC.
After every command/response the IV is replaced by the MAC (16 bytes).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import crypto


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
        """Verify MAC and decrypt ``response``."""
        if not self.is_open:
            raise SecureChannelError("secure channel not open")
        if len(response) < 32 or len(response) % 16 != 0:
            raise SecureChannelError("response must be 16-byte aligned and >= 32 bytes")
        mac, ciphertext = response[:16], response[16:]

        mac_input = bytes([len(ciphertext)]) + b"\x00" * 15 + ciphertext
        expected = crypto.aes_cbc_block(self._mac_key, b"\x00" * 16, mac_input)
        if expected != mac:
            raise SecureChannelError("response MAC mismatch")

        plaintext = crypto.aes_cbc_decrypt(self._enc_key, self._iv, ciphertext)
        self._iv = mac
        return plaintext


def derive_pairing_key(pairing_secret: bytes, pairing_salt: bytes) -> bytes:
    return crypto.sha256(pairing_secret + pairing_salt)


def expected_card_cryptogram(pairing_secret: bytes, client_challenge: bytes) -> bytes:
    return crypto.sha256(pairing_secret + client_challenge)


def client_cryptogram(pairing_secret: bytes, card_challenge: bytes) -> bytes:
    return crypto.sha256(pairing_secret + card_challenge)
