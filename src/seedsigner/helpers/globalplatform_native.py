import importlib.util
import shlex
from dataclasses import dataclass
from pathlib import Path


class GlobalPlatformNativeError(Exception):
    pass


@dataclass
class GlobalPlatformCommand:
    list_verbose: bool = False
    install_path: str | None = None
    create_aid: str | None = None
    params: str | None = None
    delete_aid: str | None = None
    force_delete: bool = False
    key_hex: str | None = None
    lock_keys: tuple[str, str, str] | None = None
    unlock: bool = False


class GlobalPlatformNativeRunner:
    """Executes the subset of GlobalPlatformPro CLI operations used by SeedSigner."""

    def __init__(self):
        self.backend = _PyGlobalPlatformBackend()

    def run(self, command: str) -> str:
        parsed = self.parse_command(command)

        if parsed.list_verbose:
            rows = self.backend.list_packages(verbose=True)
            return "\n".join([f"PKG: {aid} (|{label}|)" for aid, label in rows])

        if parsed.install_path:
            self.backend.install_cap(
                cap_path=parsed.install_path,
                create_aid=parsed.create_aid,
                install_params=parsed.params,
                key_hex=parsed.key_hex,
            )
            return "OK"

        if parsed.delete_aid:
            self.backend.delete_aid(parsed.delete_aid, force=parsed.force_delete, key_hex=parsed.key_hex)
            return "OK"

        if parsed.unlock:
            if not parsed.key_hex:
                raise GlobalPlatformNativeError("--unlock requires --key")
            self.backend.unlock_card(parsed.key_hex)
            return "OK"

        if parsed.lock_keys:
            self.backend.lock_card(*parsed.lock_keys)
            return "OK"

        raise GlobalPlatformNativeError(f"Unsupported GlobalPlatform command: {command}")

    @staticmethod
    def parse_command(command: str) -> GlobalPlatformCommand:
        args = shlex.split(command)
        parsed = GlobalPlatformCommand()

        i = 0
        while i < len(args):
            token = args[i]
            if token == "-l":
                parsed.list_verbose = True
            elif token == "-v":
                parsed.list_verbose = True
            elif token == "--install":
                i += 1
                parsed.install_path = args[i]
            elif token == "--create":
                i += 1
                parsed.create_aid = _clean_hex(args[i])
            elif token == "--params":
                i += 1
                parsed.params = _clean_hex(args[i])
            elif token == "--delete":
                i += 1
                parsed.delete_aid = _clean_hex(args[i])
            elif token == "-force":
                parsed.force_delete = True
            elif token == "--key":
                i += 1
                key = args[i]
                if key.lower() != "default":
                    parsed.key_hex = _clean_hex(key)
            elif token == "--unlock":
                parsed.unlock = True
            elif token == "--lock":
                if i + 3 >= len(args):
                    raise GlobalPlatformNativeError("--lock requires ENC MAC DEK keys")
                parsed.lock_keys = (
                    _clean_hex(args[i + 1]),
                    _clean_hex(args[i + 2]),
                    _clean_hex(args[i + 3]),
                )
                i += 3
            i += 1

        return parsed


class _PyGlobalPlatformBackend:
    def __init__(self):
        gp_module = "pyGlobalPlatform.globalplatformlib"
        if importlib.util.find_spec(gp_module) is None:
            raise GlobalPlatformNativeError(
                "pyGlobalPlatform is not installed. Install pyGlobalPlatform/libglobalplatform to use native GP operations."
            )
        from pyGlobalPlatform import globalplatformlib as gp

        self.gp = gp

    def _open(self):
        context = self.gp.establishContext()
        readers = self.gp.listReaders(context)
        if not readers:
            self.gp.releaseContext(context)
            raise GlobalPlatformNativeError("SCARD_E_NO_SMARTCARD")
        card = self.gp.connectCard(context, readers[0], self.gp.SCARD_PROTOCOL_Tx)
        return context, card

    def _authenticate(self, context, card, key_hex: str | None = None):
        key = bytes.fromhex(key_hex) if key_hex else self.gp.DEFAULT_KEY.encode("latin1")
        return self.gp.mutualAuthentication(
            context,
            card,
            key,
            key,
            key,
            key,
            0x00,
            0x00,
            2,
            0x15,
            0x03,
            0x00,
        )

    def _close(self, context, card):
        self.gp.disconnectCard(context, card)
        self.gp.releaseContext(context)

    def list_packages(self, verbose: bool = True):
        context, card = self._open()
        try:
            sec = self._authenticate(context, card)
            data = self.gp.getStatus(context, card, sec, 0x10)
            rows = []
            for entry in data or []:
                aid = ""
                if isinstance(entry, dict):
                    aid = entry.get("AID", "") or entry.get("aid", "")
                elif isinstance(entry, (tuple, list)) and entry:
                    aid = entry[0]
                else:
                    aid = str(entry)
                aid = aid.hex().upper() if isinstance(aid, (bytes, bytearray)) else str(aid).upper()
                rows.append((aid, aid))
            return rows
        finally:
            self._close(context, card)

    def install_cap(self, cap_path: str, create_aid: str | None, install_params: str | None, key_hex: str | None):
        cap = Path(cap_path)
        if not cap.exists():
            raise GlobalPlatformNativeError(f"CAP file not found: {cap}")

        context, card = self._open()
        try:
            sec = self._authenticate(context, card, key_hex=key_hex)
            # libglobalplatform handles CAP parsing internally.
            self.gp.load(context, card, sec, None, str(cap))
            if create_aid:
                aid = bytes.fromhex(create_aid)
                self.gp.installForInstallAndMakeSelectable(
                    context,
                    card,
                    sec,
                    aid,
                    aid,
                    aid,
                    0,
                    0,
                    0,
                    b"",
                    None,
                )
            elif install_params:
                # install params are TLV C9 in GPPro; pass raw params bytes.
                self.gp.installForInstallAndMakeSelectable(
                    context,
                    card,
                    sec,
                    None,
                    None,
                    None,
                    0,
                    0,
                    0,
                    bytes.fromhex(install_params),
                    None,
                )
        finally:
            self._close(context, card)

    def delete_aid(self, aid_hex: str, force: bool, key_hex: str | None = None):
        context, card = self._open()
        try:
            sec = self._authenticate(context, card, key_hex=key_hex)
            self.gp.deleteApplication(context, card, sec, [bytes.fromhex(aid_hex)])
        finally:
            self._close(context, card)

    def unlock_card(self, current_key_hex: str):
        self._set_sc_keys(current_key_hex, ("404142434445464748494A4B4C4D4E4F",) * 3)

    def lock_card(self, enc_hex: str, mac_hex: str, dek_hex: str):
        self._set_sc_keys("404142434445464748494A4B4C4D4E4F", (enc_hex, mac_hex, dek_hex))

    def _set_sc_keys(self, old_key_hex: str, new_keys_hex: tuple[str, str, str]):
        context, card = self._open()
        try:
            sec = self._authenticate(context, card, key_hex=old_key_hex)
            self.gp.putSCKey(
                context,
                card,
                sec,
                0x00,
                0x01,
                bytes.fromhex(new_keys_hex[0]),
                bytes.fromhex(new_keys_hex[0]),
                bytes.fromhex(new_keys_hex[1]),
                bytes.fromhex(new_keys_hex[2]),
            )
        finally:
            self._close(context, card)


def _clean_hex(value: str) -> str:
    return "".join(ch for ch in value if ch.isalnum()).upper()
