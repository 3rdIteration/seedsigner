"""High-level orchestration around the Status Keycard applet."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional, Sequence

from seedsigner.helpers.iso7816 import format_sw_error

from . import commands, crypto
from .commands import (
    APDUError, APPLET_AID, INS_MUTUALLY_AUTHENTICATE, SW_OK,
)
from .responses import (
    SelectResponse, SignatureResponse, StatusResponse,
    parse_generate_mnemonic, parse_select, parse_signature, parse_status,
)
from .secure_channel import (
    PairingInfo, SecureChannel, SecureChannelError,
    client_cryptogram, derive_pairing_key, expected_card_cryptogram,
)

logger = logging.getLogger(__name__)


class KeycardClient:
    """Wraps a PC/SC ``CardConnection`` (or any object with ``transmit(apdu) -> (data, sw1, sw2)``)."""

    def __init__(self, connection):
        self._conn = connection
        self._select_response: Optional[SelectResponse] = None
        self._sc: Optional[SecureChannel] = None

    @property
    def select_response(self) -> Optional[SelectResponse]:
        return self._select_response

    @property
    def secure_channel(self) -> Optional[SecureChannel]:
        return self._sc

    def transmit(self, apdu: Sequence[int]) -> bytes:
        data, sw1, sw2 = self._conn.transmit(list(apdu))
        sw = ((sw1 & 0xFF) << 8) | (sw2 & 0xFF)
        if sw != SW_OK:
            raise APDUError(sw, format_sw_error(sw1, sw2))
        return bytes(data)

    # --- cleartext commands -------------------------------------------------

    def select(self, aid: bytes = APPLET_AID) -> SelectResponse:
        resp = self.transmit(commands.select_applet(aid))
        self._select_response = parse_select(resp)
        return self._select_response

    def init(self, pin: bytes, puk: bytes, pairing_secret: bytes) -> None:
        """Run INIT against a pre-init applet using the one-shot encrypted format.

        Status Keycard rejects plaintext INIT data with SW=6A80; the
        applet expects ``client_pubkey(65) || iv(16) || AES-256-CBC(
        PIN(6) || PUK(12) || pairing_secret(32) )`` where the AES key is
        the raw X-coordinate of ECDH(client_priv, card_static_pub) and
        padding is ISO 9797-1 method 2 (matches the secure-channel
        ``oneShotEncrypt`` in ``SecureChannel.java``).

        Caller must have run ``select()`` first so the card pubkey is
        cached on ``self._select_response``.
        """
        if self._select_response is None or not self._select_response.secp256k1_pubkey:
            raise SecureChannelError(
                "INIT requires a prior SELECT carrying the card pubkey"
            )
        if len(pin) != 6:
            raise ValueError("PIN must be 6 ASCII bytes")
        if len(puk) != 12:
            raise ValueError("PUK must be 12 ASCII bytes")
        if len(pairing_secret) != 32:
            raise ValueError("pairing secret must be 32 bytes")

        client_priv, client_pub = crypto.secp256k1_generate_keypair()
        shared_x = b""
        try:
            shared_x = crypto.secp256k1_ecdh(
                client_priv, self._select_response.secp256k1_pubkey,
            )
            iv = crypto.random_bytes(16)
            plaintext = bytes(pin) + bytes(puk) + bytes(pairing_secret)
            ciphertext = crypto.aes_cbc_encrypt(shared_x, iv, plaintext)
            self.transmit(
                commands.init_encrypted(client_pub, iv, ciphertext),
            )
        finally:
            # Best-effort wipe of the ephemeral private key + AES key.
            for buf in (client_priv, shared_x):
                try:
                    ba = bytearray(buf)
                    for i in range(len(ba)):
                        ba[i] = 0
                except Exception:
                    pass

    def factory_reset(self) -> None:
        """Wipe the card. No secure channel required.

        Raises ``APDUError`` (typically SW=``0x6D00`` "instruction not
        supported") if the applet version doesn't expose this command.
        """
        self.transmit(commands.factory_reset())

    def pair(self, pairing_secret: bytes,
             p2: int = commands.PAIR_P2_PERSISTENT) -> PairingInfo:
        """Run PAIR (steps 1 + 2) and return the resulting PairingInfo.

        Pass ``p2=PAIR_P2_EPHEMERAL`` on v3.2+ cards to allocate the
        ephemeral pairing slot (index 0xFF, cleared on deselect, no
        persistent slot consumed). v3.1 cards ignore P2 and always use a
        persistent slot.
        """
        client_challenge = crypto.random_bytes(32)
        resp1 = self.transmit(commands.pair_step1(client_challenge, p2=p2))
        if len(resp1) != 64:
            raise SecureChannelError(f"PAIR step 1: expected 64 bytes, got {len(resp1)}")
        card_cryptogram = resp1[:32]
        card_challenge = resp1[32:]

        if expected_card_cryptogram(pairing_secret, client_challenge) != card_cryptogram:
            raise SecureChannelError("card pairing cryptogram mismatch")

        resp2 = self.transmit(commands.pair_step2(client_cryptogram(pairing_secret, card_challenge)))
        if len(resp2) != 33:
            raise SecureChannelError(f"PAIR step 2: expected 33 bytes, got {len(resp2)}")

        return PairingInfo(
            pairing_index=resp2[0],
            pairing_key=derive_pairing_key(pairing_secret, resp2[1:]),
        )

    def pair_ephemeral(self, pairing_secret: bytes) -> PairingInfo:
        """Convenience: PAIR with ``PAIR_P2_EPHEMERAL``.

        Caller is responsible for checking ``select_response.app_version
        >= APP_VERSION_EPHEMERAL_PAIRING`` first; this method does NOT
        re-validate, so passing it to a v3.1 card silently allocates a
        persistent slot (P2 is ignored on those cards).
        """
        return self.pair(pairing_secret, p2=commands.PAIR_P2_EPHEMERAL)

    def unpair(self, pairing_index: int) -> None:
        self.transmit(commands.unpair(pairing_index))

    # --- secure channel ------------------------------------------------------

    def open_secure_channel(self, pairing: PairingInfo) -> SecureChannel:
        if self._select_response is None:
            self.select()
        sc = SecureChannel(pairing, self._select_response.secp256k1_pubkey)
        eph_pub = sc.begin_open()
        resp = self.transmit(commands.open_secure_channel(pairing.pairing_index, eph_pub))
        sc.derive_session_from(resp)

        client_challenge = crypto.random_bytes(32)
        wrapped = sc.wrap_command(commands.CLA_PROTECTED, INS_MUTUALLY_AUTHENTICATE, 0x00, 0x00, client_challenge)
        apdu = [commands.CLA_PROTECTED, INS_MUTUALLY_AUTHENTICATE, 0x00, 0x00, len(wrapped)] + list(wrapped) + [0x00]
        resp = self.transmit(apdu)
        sc.unwrap_response(resp)
        self._sc = sc
        return sc

    def _transmit_protected(self, ins: int, p1: int, p2: int, data: bytes = b"") -> bytes:
        if self._sc is None or not self._sc.is_open:
            raise SecureChannelError("secure channel not open")
        wrapped = self._sc.wrap_command(commands.CLA_PROTECTED, ins, p1, p2, data)
        apdu = [commands.CLA_PROTECTED, ins, p1, p2, len(wrapped)] + list(wrapped) + [0x00]
        resp = self.transmit(apdu)
        return self._sc.unwrap_response(resp)

    # --- protected commands --------------------------------------------------

    def verify_pin(self, pin: bytes) -> None:
        if len(pin) != 6:
            raise ValueError("PIN must be 6 ASCII digits")
        self._transmit_protected(commands.INS_VERIFY_PIN, 0x00, 0x00, bytes(pin))

    def change_pin(self, new_pin: bytes) -> None:
        """Replace the user PIN on the card. Requires the current PIN to
        have been verified earlier in this secure-channel session.
        """
        if len(new_pin) != 6:
            raise ValueError("PIN must be 6 ASCII digits")
        self._transmit_protected(
            commands.INS_CHANGE_PIN, 0x00, 0x00, bytes(new_pin),
        )

    def get_status(self) -> StatusResponse:
        resp = self._transmit_protected(commands.INS_GET_STATUS, 0x00, 0x00)
        return parse_status(resp)

    def generate_key(self) -> bytes:
        return self._transmit_protected(commands.INS_GENERATE_KEY, 0x00, 0x00)

    def generate_mnemonic(self, word_count: int) -> List[int]:
        """Ask the card to generate a fresh BIP-39 mnemonic.

        The card supplies the entropy and returns the wordlist indices
        (16-bit big-endian, one pair per word) over the secure channel.
        The host is responsible for mapping indices to words and deriving
        the 64-byte BIP-39 seed before sending it back via LOAD KEY.

        Requires an open secure channel; PIN verification is NOT required
        (matches the Status applet spec — GENERATE MNEMONIC has no key-
        material precondition).
        """
        if word_count not in commands.GENERATE_MNEMONIC_VALID_WORD_COUNTS:
            raise ValueError(
                f"word_count must be one of "
                f"{commands.GENERATE_MNEMONIC_VALID_WORD_COUNTS}"
            )
        p1 = word_count // 3
        resp = self._transmit_protected(
            commands.INS_GENERATE_MNEMONIC, p1, 0x00,
        )
        return parse_generate_mnemonic(resp, word_count)

    def load_bip39_seed(self, seed64: bytes) -> None:
        """Push a 64-byte BIP-39 seed to the card via LOAD KEY P1=0x02.

        Requires an open secure channel and a verified PIN. The card
        replaces any existing master key.
        """
        if len(seed64) != 64:
            raise ValueError("BIP-39 seed must be exactly 64 bytes")
        self._transmit_protected(
            commands.INS_LOAD_KEY,
            commands.LOAD_KEY_P1_BIP39_SEED,
            0x00,
            bytes(seed64),
        )

    def remove_key(self) -> None:
        self._transmit_protected(commands.INS_REMOVE_KEY, 0x00, 0x00)

    def derive_key(self, path_components: Sequence[int],
                   source: int = commands.DERIVE_P1_FROM_MASTER) -> None:
        if path_components:
            data = b"".join(int(c & 0xFFFFFFFF).to_bytes(4, "big") for c in path_components)
        else:
            data = b""
        self._transmit_protected(commands.INS_DERIVE_KEY, source, 0x00, data)

    def export_pubkey(self, path_components: Optional[Sequence[int]] = None,
                      extended: bool = False) -> bytes:
        p1 = commands.EXPORT_P1_DERIVE if path_components is not None else commands.EXPORT_P1_CURRENT
        p2 = commands.EXPORT_P2_EXTENDED_PUBLIC if extended else commands.EXPORT_P2_PUBLIC_ONLY
        data = b""
        if path_components is not None:
            data = b"".join(int(c & 0xFFFFFFFF).to_bytes(4, "big") for c in path_components)
        return self._transmit_protected(commands.INS_EXPORT_KEY, p1, p2, data)

    def sign(self, hash_to_sign: bytes,
             path_components: Optional[Sequence[int]] = None,
             derive_and_make_current: bool = False) -> SignatureResponse:
        if len(hash_to_sign) != 32:
            raise ValueError("Keycard SIGN requires a 32-byte hash")
        if path_components is None:
            p1 = commands.SIGN_P1_CURRENT_KEY
            data = bytes(hash_to_sign)
        else:
            p1 = (commands.SIGN_P1_DERIVE_AND_MAKE_CURRENT
                  if derive_and_make_current
                  else commands.SIGN_P1_DERIVE)
            data = bytes(hash_to_sign) + b"".join(
                int(c & 0xFFFFFFFF).to_bytes(4, "big") for c in path_components
            )
        resp = self._transmit_protected(commands.INS_SIGN, p1, 0x00, data)
        return parse_signature(resp)


def recover_id_for(public_key: bytes, message_hash: bytes, r: bytes, s: bytes) -> int:
    """Determine the recovery id (0 or 1) such that ecrecover(r, s, recId, hash) == public_key."""
    from embit.util import secp256k1

    r_int = int.from_bytes(r, "big")
    s_int = int.from_bytes(s, "big")

    for rec_id in (0, 1):
        compact = r + s
        try:
            sig = secp256k1.ecdsa_recoverable_signature_parse_compact(compact, rec_id)
            recovered = secp256k1.ecdsa_recover(sig, message_hash)
            recovered_bytes = bytes(secp256k1.ec_pubkey_serialize(recovered, secp256k1.EC_UNCOMPRESSED))
            if recovered_bytes == public_key:
                return rec_id
        except Exception as exc:
            logger.debug("recovery attempt rec_id=%d failed: %s", rec_id, exc)
            continue
    raise ValueError("could not determine recovery id from signature/public key/hash")
