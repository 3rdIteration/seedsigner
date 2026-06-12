from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace
import re

from embit import bip32, ec


_XPUB_HEADERS_MAINNET = {
    "standard": 0x0488B21E,  # xpub
    "p2wpkh-p2sh": 0x049D7CB2,  # ypub
    "p2wsh-p2sh": 0x0295B43F,  # Ypub
    "p2wpkh": 0x04B24746,  # zpub
    "p2wsh": 0x02AA7ED3,  # Zpub
}

_XPUB_HEADERS_TESTNET = {
    "standard": 0x043587CF,  # tpub
    "p2wpkh-p2sh": 0x044A5262,  # upub
    "p2wsh-p2sh": 0x024289EF,  # Upub
    "p2wpkh": 0x045F1CF6,  # vpub
    "p2wsh": 0x02575483,  # Vpub
}


def _candidate_keycard_paths() -> list[Path]:
    candidates: list[Path] = []

    env_path = os.environ.get("SEEDSIGNER_KEYCARD_PY_PATH") or os.environ.get("SEEDSIGNER_KEYCARD_CLI_PATH")
    if env_path:
        candidates.append(Path(env_path).expanduser())

    # Default local-dev layout:
    #   GitHub/
    #     seedsigner/
    #     keycard-py/
    repo_root = Path(__file__).resolve().parents[3]
    candidates.append(repo_root.parent / "keycard-py")

    return candidates


def get_keycard_class():
    """Return (KeyCard, constants) from keycard-py if available, otherwise None.

    The import is attempted directly first. If unavailable, we try common
    local-development paths and an optional explicit environment variable.
    """

    try:
        from keycard.keycard import KeyCard
        from keycard import constants

        return KeyCard, constants
    except Exception:
        pass

    for candidate in _candidate_keycard_paths():
        try:
            if not candidate.exists() or not candidate.is_dir():
                continue
            candidate_str = str(candidate)
            if candidate_str not in sys.path:
                sys.path.insert(0, candidate_str)

            from keycard.keycard import KeyCard
            from keycard import constants

            return KeyCard, constants
        except Exception:
            continue

    return None


def _pin_to_text(pin) -> str:
    if isinstance(pin, str):
        return pin
    if isinstance(pin, (bytes, bytearray)):
        return bytes(pin).decode("utf-8")
    if isinstance(pin, list):
        return bytes(pin).decode("utf-8")
    raise ValueError("Unsupported PIN format")


def _value_to_text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8")
    if isinstance(value, list):
        return bytes(value).decode("utf-8")
    raise ValueError("Unsupported value format")


def _digits_from_bytes(data: bytes, length: int) -> str:
    if length <= 0:
        raise ValueError("length must be positive")
    # Deterministically map arbitrary bytes to ASCII digits.
    out = []
    for i in range(length):
        out.append(str(data[i % len(data)] % 10))
    return "".join(out)


def _uid_sha1_from_instance_uid(instance_uid_hex: str | None) -> str:
    if instance_uid_hex:
        try:
            uid_bytes = bytes.fromhex(instance_uid_hex)
            return hashlib.sha1(uid_bytes).hexdigest()
        except Exception:
            pass
    return hashlib.sha1(b"keycard").hexdigest()


def _normalize_uncompressed_pubkey(pubkey: bytes) -> bytes:
    if len(pubkey) == 65 and pubkey[0] == 0x04:
        return pubkey
    if len(pubkey) == 64:
        return b"\x04" + pubkey
    raise ValueError("Expected uncompressed public key format")


def _compress_pub(pubkey: bytes) -> bytes:
    if len(pubkey) == 33:
        return pubkey
    if len(pubkey) == 65 and pubkey[0] == 0x04:
        x = pubkey[1:33]
        y_last = pubkey[64]
        prefix = b"\x03" if (y_last & 1) else b"\x02"
        return prefix + x
    if len(pubkey) == 64:
        x = pubkey[:32]
        y_last = pubkey[63]
        prefix = b"\x03" if (y_last & 1) else b"\x02"
        return prefix + x
    raise ValueError("Unexpected public key format")


def _hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha).digest()


def _parse_bip32_path(path: str) -> list[int]:
    text = path.strip()
    if text in ("", "m"):
        return []
    if not text.startswith("m/"):
        raise ValueError(f"unsupported path format: {path}")
    parts = text[2:].split("/")
    result: list[int] = []
    for p in parts:
        hardened = p.endswith("'") or p.endswith("h") or p.endswith("H")
        if hardened:
            p = p[:-1]
        idx = int(p)
        if idx < 0 or idx >= 0x80000000:
            raise ValueError(f"invalid path index: {idx}")
        if hardened:
            idx |= 0x80000000
        result.append(idx)
    return result


def _path_from_indices(indices: list[int]) -> str:
    if not indices:
        return "m"
    parts = []
    for i in indices:
        base = i & 0x7FFFFFFF
        hardened = bool(i & 0x80000000)
        parts.append(f"{base}{"'" if hardened else ""}")
    return "m/" + "/".join(parts)


class ECPubkeyCompat:
    def __init__(self, raw_pub: bytes):
        self._raw_pub = _normalize_uncompressed_pubkey(raw_pub)

    def get_public_key_bytes(self, compressed: bool = True) -> bytes:
        return _compress_pub(self._raw_pub) if compressed else self._raw_pub

    def get_public_key_hex(self, compressed: bool = True) -> str:
        return self.get_public_key_bytes(compressed=compressed).hex()


class KeycardSatochipConnector:
    """Thin adapter exposing the pysatochip-style calls used by SeedSigner."""

    is_keycard_backend = True
    requires_message_digest = True
    needs_secure_channel = False
    card_type = "Keycard"

    def __init__(self, inner) -> None:
        self._card = inner["card"]
        self._constants = inner["constants"]
        self._pairing_password = inner["pairing_password"]
        self._pairing_index = None
        self._pairing_key = None
        self._secure_open = False
        self._last_path = None
        self._label = None
        self._last_select_has_key_uid = False
        self.pin = None
        self.parser = SimpleNamespace(authentikey=None)
        self.UID_SHA1 = _uid_sha1_from_instance_uid(None)
        self._refresh_uid()

    # Well-known Status Keycard factory default pairing password.
    # Any card that hasn't had its PSK changed will accept this.
    DEFAULT_PAIRING_PASSWORD = "KeycardDefaultPairing"

    @classmethod
    def create(cls, card_filter=None):
        if card_filter:
            normalized = [str(v).lower() for v in (card_filter if isinstance(card_filter, (list, tuple)) else [card_filter])]
            if not any(v == "satochip" for v in normalized):
                raise ValueError("Keycard backend only supports Satochip-style flows")

        keycard_api = get_keycard_class()
        if keycard_api is None:
            raise ImportError(
                "Unable to load keycard backend. Install keycard-py or set SEEDSIGNER_KEYCARD_PY_PATH."
            )
        keycard_cls, constants = keycard_api

        pairing_password = (
            os.environ.get("SEEDSIGNER_KEYCARD_PAIRING_PASSWORD")
            or cls.DEFAULT_PAIRING_PASSWORD
        )
        card = keycard_cls()
        try:
            card.transport.connect()
        except Exception:
            card.transport.disconnect()
            card.transport.connect()
        return cls({
            "card": card,
            "constants": constants,
            "pairing_password": pairing_password,
        })

    def _ensure_secure_channel(self) -> None:
        if self._secure_open:
            return

        self._card.select()
        self._pairing_index, self._pairing_key = self._card.pair(self._pairing_password)
        self._card.open_secure_channel(self._pairing_index, self._pairing_key)
        self._secure_open = True

    def _ensure_pin_verified(self) -> None:
        sw1, sw2 = self._verify_pin_sw()
        if (sw1, sw2) != (0x90, 0x00):
            raise ValueError(f"APDU failed with SW={sw1:02X}{sw2:02X}")

    @staticmethod
    def _extract_status_word(exc: Exception) -> int | None:
        for attr in ("status_word", "sw"):
            value = getattr(exc, attr, None)
            if isinstance(value, int):
                return value & 0xFFFF

        sw1 = getattr(exc, "sw1", None)
        sw2 = getattr(exc, "sw2", None)
        if isinstance(sw1, int) and isinstance(sw2, int):
            return ((sw1 & 0xFF) << 8) | (sw2 & 0xFF)

        text = str(exc)
        match = re.search(r"SW\s*=\s*([0-9A-Fa-f]{4})", text)
        if match:
            return int(match.group(1), 16)

        match = re.search(r"0x([0-9A-Fa-f]{4})", text)
        if match:
            return int(match.group(1), 16)

        return None

    def _pin_tries_from_status(self) -> int | None:
        try:
            status = getattr(self._card, "status", None)
        except Exception:
            return None
        if not isinstance(status, dict):
            return None

        direct_keys = (
            "PIN0_remaining_tries",
            "pin_remaining_tries",
            "pin_retry_counter",
            "pin_retry_count",
            "pin_tries_left",
            "pin_attempts_left",
        )
        for key in direct_keys:
            value = status.get(key)
            if isinstance(value, int):
                return value

        pin_status = status.get("pin")
        if isinstance(pin_status, dict):
            for key in ("remaining_tries", "tries_left", "attempts_left"):
                value = pin_status.get(key)
                if isinstance(value, int):
                    return value

        return None

    def _pin_failure_sw(self, fallback_sw: tuple[int, int] = (0x63, 0xC0)) -> tuple[int, int]:
        tries = self._pin_tries_from_status()
        if isinstance(tries, int) and 0 <= tries <= 15:
            return (0x63, 0xC0 | tries)
        return fallback_sw

    def _verify_pin_sw(self) -> tuple[int, int]:
        if self.pin is None:
            raise ValueError("PIN has not been set")

        # Keycard tracks a session-level verified PIN state; avoid sending a
        # duplicate VERIFY PIN APDU if we already have a verified session.
        try:
            if bool(getattr(self._card, "is_pin_verified", False)):
                return (0x90, 0x00)
        except Exception:
            pass

        pin_text = _pin_to_text(self.pin)
        try:
            ok = self._card.verify_pin(pin_text)
        except Exception as exc:
            status_word = self._extract_status_word(exc)
            if status_word is None:
                raise
            if 0x63C0 <= status_word <= 0x63CF:
                return ((status_word >> 8) & 0xFF, status_word & 0xFF)
            # Some firmware reports PIN failure as 6A80; translate it to 63Cx
            # so UI can render a proper incorrect-PIN message.
            if status_word == 0x6A80:
                return self._pin_failure_sw()
            return ((status_word >> 8) & 0xFF, status_word & 0xFF)

        if ok:
            return (0x90, 0x00)
        return self._pin_failure_sw()

    def _refresh_uid(self) -> None:
        try:
            info = self._card.select()
            instance_uid = getattr(info, "instance_uid", None)
            self._last_select_has_key_uid = bool(getattr(info, "key_uid", None))
            if isinstance(instance_uid, bytes):
                instance_uid = instance_uid.hex()
            self.UID_SHA1 = _uid_sha1_from_instance_uid(instance_uid)
        except Exception:
            pass

    @staticmethod
    def _sw_to_tuple(status_word: int) -> tuple[int, int]:
        return ((status_word >> 8) & 0xFF, status_word & 0xFF)

    def _load_key_with_sw(self, key_type, **kwargs) -> tuple[int, int]:
        try:
            self._card.load_key(key_type, **kwargs)
            return (0x90, 0x00)
        except Exception as exc:
            status_word = self._extract_status_word(exc)
            if status_word is not None:
                return self._sw_to_tuple(status_word)
            raise

    def card_get_label(self):
        return self._label or "Keycard"

    def card_disconnect(self):
        try:
            return self._card.transport.disconnect()
        finally:
            self._secure_open = False

    def set_mode_factory_reset(self, enabled: bool):
        _ = enabled
        return None

    def card_initiate_secure_channel(self):
        return ([], 0x90, 0x00)

    def set_pin(self, pin_nbr, pin):
        _ = pin_nbr
        self.pin = pin

    def card_verify_PIN(self):
        self._ensure_secure_channel()
        sw1, sw2 = self._verify_pin_sw()
        return ([], sw1, sw2)

    def card_get_status(self):
        self._refresh_uid()

        # A factory-fresh Keycard is present, but it cannot be paired until
        # device init (PIN/PUK/pairing secret) has completed.
        try:
            if bool(self._card.is_initialized) is False:
                out = {
                    "setup_done": False,
                    "device_initialized": False,
                    "key_initialized": False,
                    "is_seeded": False,
                }
                return ([], 0x90, 0x00, out)
        except Exception:
            # If the backend cannot report init state yet, fall through to the
            # regular secure-channel path below.
            pass

        self._ensure_secure_channel()
        out = {}

        # Some card states return SW=6985 for GET STATUS even though the card
        # is present and initialized for further setup/import actions.
        try:
            status = self._card.status
            if isinstance(status, dict):
                out.update(status)
        except Exception as exc:
            sw = self._extract_status_word(exc)
            if sw != 0x6985:
                raise

        try:
            path_indices = self._card.get_key_path
        except Exception as exc:
            sw = self._extract_status_word(exc)
            if sw != 0x6985:
                raise
            path_indices = None

        out["device_initialized"] = True
        if isinstance(path_indices, list):
            out["path"] = _path_from_indices(path_indices)
        key_initialized = bool(
            out.get(
                "key_initialized",
                out.get("initialized", self._last_select_has_key_uid),
            )
        ) or bool(self._last_select_has_key_uid)
        out["key_initialized"] = key_initialized
        out["is_seeded"] = bool(out.get("is_seeded", key_initialized))
        out.setdefault("setup_done", True)
        pin_tries = self._pin_tries_from_status()
        if pin_tries is not None:
            out.setdefault("PIN0_remaining_tries", pin_tries)
        return ([], 0x90, 0x00, out)

    def card_setup(
        self,
        pin_tries_0,
        ublk_tries_0,
        pin_0,
        ublk_0,
        pin_tries_1,
        ublk_tries_1,
        pin_1,
        ublk_1,
        secmemsize,
        memsize,
        create_object_ACL,
        create_key_ACL,
        create_pin_ACL,
        option_flags=0,
        hmacsha160_key=None,
        amount_limit=0,
    ):
        _ = pin_tries_0
        _ = ublk_tries_0
        _ = pin_tries_1
        _ = ublk_tries_1
        _ = pin_1
        _ = ublk_1
        _ = secmemsize
        _ = memsize
        _ = create_object_ACL
        _ = create_key_ACL
        _ = create_pin_ACL
        _ = option_flags
        _ = hmacsha160_key
        _ = amount_limit

        pin_text = _value_to_text(pin_0)
        if not (len(pin_text) == 6 and pin_text.isdigit()):
            raise ValueError("Keycard PIN must be exactly 6 digits")

        if isinstance(ublk_0, list):
            source = bytes(ublk_0) or b"\x00"
            puk_text = _digits_from_bytes(source, 12)
        else:
            puk_text = _value_to_text(ublk_0)
            if not puk_text.isdigit():
                source = puk_text.encode("utf-8") or b"\x00"
                puk_text = _digits_from_bytes(source, 12)
            elif len(puk_text) != 12:
                source = puk_text.encode("utf-8")
                puk_text = _digits_from_bytes(source, 12)

        try:
            self._card.init(pin_text, puk_text, self._pairing_password)
            self.pin = list(pin_text.encode("utf-8"))
            self._secure_open = False
            return ([], 0x90, 0x00)
        except Exception as exc:
            status_word = self._extract_status_word(exc)
            if status_word is not None:
                return ([], (status_word >> 8) & 0xFF, status_word & 0xFF)
            raise

    def card_change_PIN(self, pin_nbr, old_pin, new_pin):
        _ = pin_nbr
        self._ensure_secure_channel()
        old_text = _value_to_text(old_pin)
        new_text = _value_to_text(new_pin)
        self.pin = list(old_text.encode("utf-8"))
        sw1, sw2 = self._verify_pin_sw()
        if (sw1, sw2) != (0x90, 0x00):
            return ([], sw1, sw2)
        self._card.change_pin(new_text)
        self.pin = list(new_text.encode("utf-8"))
        return ([], 0x90, 0x00)

    def card_change_PUK(self, pin_nbr, old_puk, new_puk):
        _ = pin_nbr
        _ = old_puk
        self._ensure_secure_channel()
        self._ensure_pin_verified()
        new_text = _value_to_text(new_puk)
        self._card.change_puk(new_text)
        return ([], 0x90, 0x00)

    def card_unblock_PIN(self, pin_nbr, puk, new_pin=None):
        _ = pin_nbr
        self._ensure_secure_channel()
        puk_text = _value_to_text(puk)
        if new_pin is None:
            if self.pin is None:
                raise ValueError("New PIN is required")
            new_pin_text = _pin_to_text(self.pin)
        else:
            new_pin_text = _value_to_text(new_pin)
        self._card.unblock_pin(puk_text, new_pin_text)
        self.pin = list(new_pin_text.encode("utf-8"))
        return ([], 0x90, 0x00)

    def card_set_label(self, label):
        self._ensure_secure_channel()
        sw1, sw2 = self._verify_pin_sw()
        if (sw1, sw2) != (0x90, 0x00):
            return ([], sw1, sw2)
        label_text = _value_to_text(label)
        self._card.store_data(label_text.encode("utf-8"), slot=self._constants.StorageSlot.PUBLIC)
        self._label = label_text
        return ([], 0x90, 0x00)

    def card_reset_factory(self):
        self._ensure_secure_channel()
        sw1, sw2 = self._verify_pin_sw()
        if (sw1, sw2) != (0x90, 0x00):
            return ([], sw1, sw2)
        self._card.factory_reset()
        self._secure_open = False
        self.pin = None
        return ([], 0x90, 0x00)

    def card_bip32_import_seed(self, seed_bytes):
        self._ensure_secure_channel()
        sw1, sw2 = self._verify_pin_sw()
        if (sw1, sw2) != (0x90, 0x00):
            return ([], sw1, sw2)

        seed = bytes(seed_bytes)

        sw1, sw2 = self._load_key_with_sw(
            self._constants.LoadKeyType.BIP39_SEED,
            bip39_seed=seed,
        )
        if (sw1, sw2) == (0x90, 0x00):
            return ([], 0x90, 0x00)

        if (sw1, sw2) != (0x69, 0x85):
            return ([], sw1, sw2)

        # Some firmware reports a stale key state and requires a clear before
        # accepting a new import, even when status looks unseeded.
        try:
            self._card.remove_key()
        except Exception as remove_exc:
            remove_sw = self._extract_status_word(remove_exc)
            # Ignore "conditions not satisfied" while clearing state;
            # still attempt import fallbacks below.
            if remove_sw not in (None, 0x6985):
                sw1, sw2 = self._sw_to_tuple(remove_sw)
                return ([], sw1, sw2)

        sw1, sw2 = self._load_key_with_sw(
            self._constants.LoadKeyType.BIP39_SEED,
            bip39_seed=seed,
        )
        if (sw1, sw2) == (0x90, 0x00):
            return ([], 0x90, 0x00)

        if (sw1, sw2) != (0x69, 0x85):
            return ([], sw1, sw2)

        # Additional compatibility fallback: import root key material explicitly
        # as EXTENDED_ECC at m.
        root = bip32.HDKey.from_seed(seed)
        uncompressed_pub = b"\x04" + root.key.get_public_key()._point
        sw1, sw2 = self._load_key_with_sw(
            self._constants.LoadKeyType.EXTENDED_ECC,
            public_key=uncompressed_pub,
            private_key=root.key.secret,
            chain_code=root.chain_code,
        )
        return ([], sw1, sw2)

    def card_remove_key(self):
        self._ensure_secure_channel()
        sw1, sw2 = self._verify_pin_sw()
        if (sw1, sw2) != (0x90, 0x00):
            return ([], sw1, sw2)
        self._card.remove_key()
        return ([], 0x90, 0x00)

    def card_bip32_get_authentikey(self):
        key = self._card.ident()
        wrapped = ECPubkeyCompat(key)
        self.parser.authentikey = wrapped
        return wrapped

    def card_export_authentikey(self):
        return self.card_bip32_get_authentikey()

    def card_bip32_get_extendedkey(self, path):
        self._ensure_secure_channel()
        sw1, sw2 = self._verify_pin_sw()
        if (sw1, sw2) != (0x90, 0x00):
            raise ValueError(f"APDU failed with SW={sw1:02X}{sw2:02X}")
        from keycard.parsing import tlv as kc_tlv

        path_str = path.decode("ascii") if isinstance(path, bytes) else str(path)
        if path_str in ("", "m"):
            path_str = "m"

        # Navigate the card to the requested derivation path, then export the
        # current key with its chain code.  Using derive_key + CURRENT avoids
        # SW=6A80 that is returned by some Status keycard firmware when
        # DERIVE + EXTENDED_PUBLIC are combined in a single EXPORT KEY APDU.
        self._card.derive_key(path_str)

        response = self._card.send_secure_apdu(
            ins=self._constants.INS_EXPORT_KEY,
            p1=self._constants.DerivationOption.CURRENT,
            p2=self._constants.KeyExportOption.EXTENDED_PUBLIC,
            data=b"",
        )
        outer = kc_tlv.parse_tlv(response)
        tpl = outer.get(0xA1)
        if not tpl:
            raise ValueError("Missing keypair template (tag 0xA1) in export response")
        inner = kc_tlv.parse_tlv(tpl[0])
        pubkey = inner.get(0x80, [None])[0]
        chain_code = inner.get(0x82, [None])[0]

        if not pubkey:
            raise ValueError("Missing public key in export response")
        if not chain_code:
            raise ValueError("Missing chain code in export response")

        self._last_path = path_str
        return ECPubkeyCompat(pubkey), chain_code

    def card_bip32_get_xpub(self, path, xtype, is_mainnet):
        path_str = path.decode("ascii") if isinstance(path, bytes) else str(path)
        indices = _parse_bip32_path(path_str)
        depth = len(indices)
        child_index = indices[-1] if indices else 0

        # Compute parent fingerprint first so that _last_path ends up as the
        # child path after both derive operations.
        if depth == 0:
            fingerprint = b"\x00\x00\x00\x00"
        else:
            parent_path = _path_from_indices(indices[:-1])
            parent, _ = self.card_bip32_get_extendedkey(parent_path)
            fingerprint = _hash160(parent.get_public_key_bytes(compressed=True))[:4]

        child, child_chain = self.card_bip32_get_extendedkey(path_str)

        header_map = _XPUB_HEADERS_MAINNET if is_mainnet else _XPUB_HEADERS_TESTNET
        version = header_map.get(xtype)
        if version is None:
            raise ValueError(f"unsupported xtype: {xtype}")
        version_bytes = int(version).to_bytes(4, "big")

        hd = bip32.HDKey(
            key=ec.PublicKey.parse(child.get_public_key_bytes(compressed=True)),
            chain_code=child_chain,
            version=version_bytes,
            depth=depth,
            fingerprint=fingerprint,
            child_number=child_index,
        )
        return hd.to_base58()

    @staticmethod
    def _normalize_digest(data):
        if isinstance(data, list):
            digest = bytes(data)
        elif isinstance(data, bytes):
            digest = data
        else:
            digest = bytes.fromhex(str(data))
        if len(digest) != 32:
            raise ValueError("digest must be exactly 32 bytes")
        return digest

    def card_sign_transaction_hash(self, keynbr, txhash, chalresponse=None):
        _ = chalresponse
        self._ensure_secure_channel()
        digest = self._normalize_digest(txhash)

        if int(keynbr) == 0xFF and self._last_path:
            sig = self._card.sign_with_path(digest, self._last_path)
        else:
            sig = self._card.sign(digest)

        der = sig.signature_der
        return (list(der), 0x90, 0x00)

    def card_sign_message(self, keynbr, pubkey, message, hmac=b"", altcoin=None):
        _ = pubkey
        _ = hmac
        _ = altcoin
        self._ensure_secure_channel()
        digest = self._normalize_digest(message)

        if int(keynbr) == 0xFF and self._last_path:
            sig = self._card.sign_with_path(digest, self._last_path)
        else:
            sig = self._card.sign(digest)

        der = sig.signature_der
        compact = getattr(sig, "signature", None)
        if not compact or len(compact) != 65:
            compact = b"\x1f" + b"\x00" * 64
        return (list(der), 0x90, 0x00, compact)
