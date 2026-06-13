"""****************************************************************************
    GPG Views
****************************************************************************"""
import base64
import hashlib
import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from embit.bip32 import HDKey
from gettext import gettext as _

from seedsigner.gui.components import FontAwesomeIconConstants, GUIConstants, SeedSignerIconConstants
from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    DireWarningScreen,
    LargeIconStatusScreen,
    WarningScreen,
    ErrorScreen,
)
from seedsigner.gui.screens.screen import ButtonOption
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views.seed_views import (
    SeedExportXpubScriptTypeView,
    AccountNumberView,
)
from .view import View, Destination, BackStackView, MainMenuView
# Imported from tools_views for use by _text_qr_done_destination (defined near end of file)
from .tools_views import ToolsMenuView, ToolsTextQRView

logger = logging.getLogger(__name__)


def parse_secret_key_list(colon_output: str):
    """Parse `gpg --list-secret-keys --with-colons` output."""
    keys = []
    cur = None
    for line in colon_output.splitlines():
        parts = line.split(":")
        if parts[0] == "sec":
            created = int(parts[5]) if len(parts) > 5 and parts[5] else None
            cur = {"fpr": None, "uid": None, "created": created}
            keys.append(cur)
        elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
            cur["fpr"] = parts[9]
        elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
            cur["uid"] = parts[9]
    return keys


def parse_subkey_list(colon_output: str):
    """Parse `gpg --list-secret-keys --with-colons` subkey data."""
    subkeys = []
    cur = None
    idx = 0
    for line in colon_output.splitlines():
        parts = line.split(":")
        if parts[0] == "ssb":
            idx += 1
            bits = parts[2]
            algo = parts[3] if len(parts) > 3 else ""
            curve = parts[16].lower() if len(parts) > 16 else ""
            created = int(parts[5]) if len(parts) > 5 and parts[5] else None
            cur = {
                "fpr": None,
                "caps": parts[11].lower(),
                "idx": idx,
                "algo": algo,
                "bits": bits,
                "curve": curve,
                "created": created,
            }
            subkeys.append(cur)
        elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
            cur["fpr"] = parts[9]
    return subkeys


# Bitcoin genesis block time: 2009-01-03 18:15:05 UTC.
# NOTE: As of 2025-09-15, BIP85 on GitHub lists this timestamp with a
# human-readable typo of "2009-01-03 18:05:05" UTC, which has propagated elsewhere.
BIP85_GPG_CREATED_TS = 1231006505


def _normalize_date_input(s: str) -> str:
    """Strip whitespace and replace common non-ASCII dashes with ASCII hyphen.

    Locale or input-method differences can produce fullwidth hyphens (\uff0d),
    en-dashes (\u2013), em-dashes (\u2014), or Unicode minus signs (\u2212)
    instead of the expected ASCII hyphen-minus (U+002D).  Normalizing these
    prevents ``datetime.strptime`` / ``date.fromisoformat`` from raising
    ``ValueError`` on otherwise-valid date strings.
    """
    s = s.strip()
    for ch in "\uff0d\u2013\u2014\u2212":
        s = s.replace(ch, "-")
    return s

# Single BIP85 GPG application number per updated spec.
# Derivation path: m/83696968'/828365'/{key_type}'/{key_bits}'/{key_index}'[/{sub_key}']
BIP85_GPG_APP = 828365

# BIP85 GPG key_type codes
BIP85_GPG_KEY_TYPE_RSA = 0
BIP85_GPG_KEY_TYPE_CURVE25519 = 1
BIP85_GPG_KEY_TYPE_SECP256K1 = 2
BIP85_GPG_KEY_TYPE_NIST = 3
BIP85_GPG_KEY_TYPE_BRAINPOOL = 4

# In-memory registry of BIP85-derived keys
BIP85_DATA = {}


def bip85_export_json():
    import json

    return json.dumps(list(BIP85_DATA.values()), indent=2)


def bip85_import_json(data: str, *, clear: bool = True):
    import json

    entries = json.loads(data)
    if isinstance(entries, dict):
        entries = [entries]
    if clear:
        BIP85_DATA.clear()
    for entry in entries:
        if "primary_fpr" in entry:
            uids = entry.get("uids", [])
            primary = entry.get("primary_uid")
            if primary and primary in uids:
                uids = [primary] + [u for u in uids if u != primary]
                entry["uids"] = uids
            BIP85_DATA[entry["primary_fpr"]] = entry


def bip85_save_data(path):
    from pathlib import Path
    import json

    p = Path(path)
    if p.is_dir():
        for entry in BIP85_DATA.values():
            fname = p / f"BIP85_{entry['seed_fpr']}.json"
            with open(fname, "w", encoding="utf-8") as f:
                json.dump(entry, f, indent=2)
    else:
        with open(p, "w", encoding="utf-8") as f:
            f.write(bip85_export_json())


def bip85_load_data(path):
    from pathlib import Path
    import json

    p = Path(path)
    if p.is_dir():
        entries = []
        for file in p.glob("*.json"):
            try:
                with open(file, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    entries.extend(data)
                else:
                    entries.append(data)
            except Exception:
                continue
        bip85_import_json(json.dumps(entries))
    else:
        with open(p, encoding="utf-8") as f:
            bip85_import_json(f.read())


def parse_uid_list(colon_output: str):
    """Parse `gpg --list-secret-keys --with-colons` UID data."""
    uids = []
    idx = 0
    for line in colon_output.splitlines():
        parts = line.split(":")
        if parts[0] == "uid":
            idx += 1
            uids.append({"uid": parts[9], "idx": idx})
    return uids


def filter_deletable_subkeys(primary_fpr: str, subkeys):
    bip85 = primary_fpr in BIP85_DATA
    logger.info(
        "filter_deletable_subkeys: bip85=%s subkey_count=%s",
        bip85,
        len(subkeys),
    )
    if bip85 and subkeys:
        max_idx = max(sk["idx"] for sk in subkeys)
        logger.info("BIP85 key detected; allowing deletion of index %s only", max_idx)
        return [sk for sk in subkeys if sk["idx"] == max_idx]
    logger.info("Non-BIP85 key or no subkeys; returning all subkeys")
    return subkeys


def _select_import_algo(primary_algo: str, primary_curve: str, subkeys, selected_fprs):
    """Determine the algorithm/curve for card import based on selected subkeys."""
    if selected_fprs:
        fprs = selected_fprs.values() if isinstance(selected_fprs, dict) else selected_fprs
        selected = [sk for sk in subkeys if sk["fpr"] in fprs]
        if not selected:
            return primary_algo, primary_curve
        algos = {sk["algo"] for sk in selected}
        if len(algos) != 1:
            raise ValueError("Selected subkeys use different key types")
        algo = algos.pop()
        curve = ""
        if algo not in ("1", "2", "3"):
            curves = {sk["curve"] for sk in selected}
            if len(curves) != 1:
                raise ValueError("Selected subkeys use different key curves")
            curve = curves.pop()
        return algo, curve
    return primary_algo, primary_curve


class ToolsGPGMenuView(View):
    FILE_OPS = ButtonOption("File Operations")
    IMPORT = ButtonOption("Import Keys")
    EXPORT = ButtonOption("Export Keys")
    VIEW_KEYS = ButtonOption("View Keys")
    MESSAGE = ButtonOption("Secure Messaging")
    SMART_GPG = ButtonOption("SmartGPG")
    ADVANCED = ButtonOption("Advanced")

    def run(self):
        import shutil
        from seedsigner.controller import Controller

        # Check that required dependencies are available
        missing = []
        try:
            import pgpy  # noqa: F401
        except ImportError:
            missing.append("pgpy")
        if not shutil.which("gpg"):
            missing.append("gnupg2")
        if missing:
            self.run_screen(
                ErrorScreen,
                title=_("GPG Tools"),
                status_headline=_("Missing packages"),
                text=_("Required but not installed:\n") + ", ".join(missing),
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        if self.controller.resume_main_flow == self.controller.FLOW__GPG_MESSAGE:
            self.controller.resume_main_flow = None
            return Destination(ToolsGPGDecryptMessageView, skip_current_view=True)

        button_data = [
            self.FILE_OPS,
            self.IMPORT,
            self.EXPORT,
            self.VIEW_KEYS,
            self.MESSAGE,
            self.SMART_GPG,
            self.ADVANCED,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="GPG Tools",
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == self.FILE_OPS:
            return Destination(ToolsGPGFileOpsMenuView)

        elif button_data[selected_menu_num] == self.IMPORT:
            return Destination(ToolsGPGImportMenuView)
        elif button_data[selected_menu_num] == self.EXPORT:
            return Destination(ToolsGPGExportMenuView)
        elif button_data[selected_menu_num] == self.VIEW_KEYS:
            return Destination(ToolsGPGViewKeysView)
        elif button_data[selected_menu_num] == self.MESSAGE:
            return Destination(ToolsGPGMessageMenuView)
        elif button_data[selected_menu_num] == self.SMART_GPG:
            return Destination(ToolsGPGSmartMenuView)
        elif button_data[selected_menu_num] == self.ADVANCED:
            return Destination(ToolsGPGAdvancedMenuView)


class ToolsGPGAdvancedMenuView(View):
    SUBKEY_OPS = ButtonOption("Subkey Operations")
    UID_OPS = ButtonOption("User ID Operations")
    CROSS_CERTIFY = ButtonOption("Cross Certify Keys")
    EXPORT_BUNDLE = ButtonOption("Export Public Key Bundle")
    BIP85_META = ButtonOption("BIP85 Metadata")

    def run(self):
        button_data = [
            self.SUBKEY_OPS,
            self.UID_OPS,
            self.CROSS_CERTIFY,
            self.EXPORT_BUNDLE,
            self.BIP85_META,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Advanced",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = button_data[selected_menu_num]
        if choice == self.SUBKEY_OPS:
            return Destination(ToolsGPGSubkeyMenuView)
        if choice == self.UID_OPS:
            return Destination(ToolsGPGUidMenuView)
        if choice == self.CROSS_CERTIFY:
            return Destination(ToolsGPGCrossCertifyView)
        if choice == self.EXPORT_BUNDLE:
            return Destination(ToolsGPGExportBundleView)
        if choice == self.BIP85_META:
            return Destination(ToolsGPGBip85MetadataMenuView)
        return Destination(ToolsGPGMenuView)


# ---- GPG algorithm code → human-readable name map ---------------------------
_GPG_ALGO_NAMES = {
    "1": "RSA",
    "16": "Elgamal",
    "17": "DSA",
    "18": "ECDH",
    "19": "ECDSA",
    "22": "EdDSA",
}


def _format_fpr_blocks(fpr: str) -> str:
    """Format a hex fingerprint in blocks of 4 characters separated by spaces."""
    return " ".join(fpr[i:i + 4] for i in range(0, len(fpr), 4))


def _gpg_algo_label(algo_code: str, curve: str, bits: str) -> str:
    """Return a short human-readable description for a GPG key algorithm."""
    name = _GPG_ALGO_NAMES.get(algo_code, f"Algo {algo_code}")
    if curve:
        return f"{name} {curve}"
    if bits:
        return f"{name} {bits}"
    return name


class ToolsGPGViewKeysView(View):
    """List GPG secret keys and show fingerprint / metadata."""

    def run(self):
        from subprocess import run as _run
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            WarningScreen,
        )

        result = _run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = parse_secret_key_list(result.stdout)

        # Collect all subkey fingerprints so we can exclude them from the
        # primary key list.  Some GPG configurations may list a subkey with
        # its own ``sec`` record; filtering by fingerprint prevents those
        # entries from appearing as separate keys in the UI.
        all_subkey_fprs = {
            sk["fpr"]
            for sk in parse_subkey_list(result.stdout)
            if sk.get("fpr")
        }
        keys = [k for k in keys if k.get("fpr") not in all_subkey_fprs]

        if not keys:
            self.run_screen(
                WarningScreen,
                title="View Keys",
                status_headline=None,
                text="No secret keys found\nin the GPG keyring.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        buttons = []
        for k in keys:
            label = k["uid"] if k["uid"] else k["fpr"][-16:]
            buttons.append(ButtonOption(label))

        selected = self.run_screen(
            ButtonListScreen,
            title="View Keys",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        key = keys[selected]
        return Destination(
            ToolsGPGKeyDetailsView,
            view_args=dict(fpr=key["fpr"]),
        )


class ToolsGPGKeyDetailsView(View):
    """Show details for a single GPG primary key."""

    SUBKEYS = ButtonOption("Subkeys")

    def __init__(self, fpr: str):
        super().__init__()
        self.fpr = fpr

    def run(self):
        from subprocess import run as _run
        from seedsigner.gui.screens.screen import LargeIconStatusScreen

        detail = _run(
            ["gpg", "--list-secret-keys", "--with-colons", self.fpr],
            capture_output=True,
            text=True,
        )

        # Primary key algorithm info from the ``sec`` line.
        primary_algo = ""
        uid = ""
        for line in detail.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                algo_code = parts[3] if len(parts) > 3 else ""
                bits = parts[2]
                curve = parts[16].lower() if len(parts) > 16 and parts[16] else ""
                primary_algo = _gpg_algo_label(algo_code, curve, bits)
            elif parts[0] == "uid" and not uid:
                uid = parts[9] if len(parts) > 9 and parts[9] else ""
        if not uid:
            uid = self.fpr[-16:]

        subkeys = parse_subkey_list(detail.stdout)

        fpr_display = _format_fpr_blocks(self.fpr)
        lines = [
            uid,
            f"Fpr: {fpr_display}",
            f"Type: {primary_algo}",
        ]

        button_data = []
        if subkeys:
            button_data.append(self.SUBKEYS)

        selected = self.run_screen(
            LargeIconStatusScreen,
            title="Key Details",
            status_icon_size=0,
            status_headline=None,
            text="\n".join(lines),
            show_back_button=True,
            button_data=button_data if button_data else [ButtonOption("Back")],
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data and button_data[selected] == self.SUBKEYS:
            return Destination(
                ToolsGPGKeySubkeysView,
                view_args=dict(fpr=self.fpr),
            )

        return Destination(BackStackView)


class ToolsGPGKeySubkeysView(View):
    """List subkeys of a GPG primary key."""

    def __init__(self, fpr: str):
        super().__init__()
        self.fpr = fpr

    def run(self):
        from subprocess import run as _run
        from seedsigner.gui.screens.screen import ButtonListScreen, WarningScreen

        detail = _run(
            ["gpg", "--list-secret-keys", "--with-colons", self.fpr],
            capture_output=True,
            text=True,
        )
        subkeys = parse_subkey_list(detail.stdout)

        if not subkeys:
            self.run_screen(
                WarningScreen,
                title="Subkeys",
                status_headline=None,
                text="No subkeys found.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        buttons = []
        for sk in subkeys:
            sk_algo = _gpg_algo_label(
                sk["algo"], sk.get("curve", ""), sk["bits"]
            )
            caps = sk.get("caps", "")
            cap_labels = []
            if "s" in caps:
                cap_labels.append("S")
            if "e" in caps:
                cap_labels.append("E")
            if "a" in caps:
                cap_labels.append("A")
            cap_str = ",".join(cap_labels) if cap_labels else caps
            sk_fpr_short = sk["fpr"][-8:] if sk.get("fpr") else "?"
            label = f"{sk_fpr_short} [{cap_str}] {sk_algo}"
            buttons.append(ButtonOption(label))

        selected = self.run_screen(
            ButtonListScreen,
            title="Subkeys",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        sk = subkeys[selected]
        return Destination(
            ToolsGPGSubkeyDetailsView,
            view_args=dict(primary_fpr=self.fpr, subkey_fpr=sk["fpr"]),
        )


class ToolsGPGSubkeyDetailsView(View):
    """Show details for a single GPG subkey."""

    def __init__(self, primary_fpr: str, subkey_fpr: str):
        super().__init__()
        self.primary_fpr = primary_fpr
        self.subkey_fpr = subkey_fpr

    def run(self):
        from subprocess import run as _run
        from seedsigner.gui.screens.screen import LargeIconStatusScreen

        detail = _run(
            ["gpg", "--list-secret-keys", "--with-colons", self.primary_fpr],
            capture_output=True,
            text=True,
        )
        subkeys = parse_subkey_list(detail.stdout)

        sk = None
        for s in subkeys:
            if s.get("fpr") == self.subkey_fpr:
                sk = s
                break

        if sk is None:
            sk = {"fpr": self.subkey_fpr, "algo": "", "bits": "", "caps": ""}

        sk_algo = _gpg_algo_label(
            sk["algo"], sk.get("curve", ""), sk["bits"]
        )
        caps = sk.get("caps", "")
        cap_labels = []
        if "s" in caps:
            cap_labels.append("Sign")
        if "e" in caps:
            cap_labels.append("Encrypt")
        if "a" in caps:
            cap_labels.append("Auth")
        cap_str = ", ".join(cap_labels) if cap_labels else caps

        fpr_display = _format_fpr_blocks(self.subkey_fpr)
        lines = [
            f"Fpr: {fpr_display}",
            f"Type: {sk_algo}",
        ]
        if cap_str:
            lines.append(f"Caps: {cap_str}")

        self.run_screen(
            LargeIconStatusScreen,
            title="Subkey Details",
            status_icon_size=0,
            status_headline=None,
            text="\n".join(lines),
            show_back_button=True,
            button_data=[ButtonOption("Back")],
        )

        return Destination(BackStackView)


class ToolsGPGCrossCertifyView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)

        if len(keys) < 2:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="At least two keys required",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        key_buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        signer_sel = self.run_screen(
            ButtonListScreen,
            title="Signing Key",
            is_button_text_centered=False,
            button_data=key_buttons,
        )
        if signer_sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        signer = keys[signer_sel]

        target_keys = [k for idx, k in enumerate(keys) if idx != signer_sel]
        target_buttons = [
            ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in target_keys
        ]
        target_sel = self.run_screen(
            ButtonListScreen,
            title="Target Key",
            is_button_text_centered=False,
            button_data=target_buttons,
        )
        if target_sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        target = target_keys[target_sel]

        cmd = [
            "gpg",
            "--batch",
            "--yes",
            "--default-key",
            signer["fpr"],
            "--quick-sign-key",
            target["fpr"],
        ]
        result = run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Key cross certified",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
            return Destination(ToolsGPGMenuView)

        logger.error("Cross certification failed: %s", result.stderr.strip())
        self.run_screen(
            WarningScreen,
            title="Error",
            status_headline=None,
            text="Failed to cross certify",
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )
        return Destination(BackStackView)


class ToolsGPGExportBundleView(View):
    def run(self):
        from subprocess import run
        import os
        import time
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            LoadingScreenThread,
            QRDisplayScreen,
        )
        from seedsigner.hardware.microsd import MicroSD
        from seedsigner.models.encode_qr import UrBytesQrEncoder

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        export_option = ButtonOption("Export Bundle")
        cancel_option = ButtonOption("Cancel")
        selected = set()

        while True:
            button_data = []
            for key in keys:
                label = key["uid"] if key["uid"] else key["fpr"][-8:]
                if key["fpr"] in selected:
                    label = "* " + label
                button_data.append(ButtonOption(label))
            button_data.extend([export_option, cancel_option])

            sel = self.run_screen(
                ButtonListScreen,
                title="Select Keys",
                is_button_text_centered=False,
                button_data=button_data,
            )

            if sel == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            if sel < len(keys):
                fpr = keys[sel]["fpr"]
                if fpr in selected:
                    selected.remove(fpr)
                else:
                    selected.add(fpr)
                continue

            choice = button_data[sel]
            if choice is cancel_option:
                return Destination(BackStackView)
            if choice is export_option:
                if len(selected) < 2:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Select at least two keys",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    continue
                break

        fingerprints = [k["fpr"] for k in keys if k["fpr"] in selected]

        exported = run(["gpg", "--armor", "--export", *fingerprints], capture_output=True, text=True)
        if exported.returncode != 0:
            logger.error("Bundle export failed: %s", exported.stderr.strip())
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to export keys",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        dest_buttons = [ButtonOption("microSD"), ButtonOption("Animated QR")]
        dest_sel = self.run_screen(
            ButtonListScreen,
            title="Export to",
            is_button_text_centered=False,
            button_data=dest_buttons,
        )
        if dest_sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if dest_sel == 0:
            if len(self.controller.storage.seeds) > 0:
                ret = self.run_screen(
                    WarningScreen,
                    title="WARNING",
                    status_headline=None,
                    text="These tools write data to the microSD card and may expose loaded secrets.",
                    show_back_button=True,
                    button_data=[ButtonOption("Continue")],
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)

            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"gpg_bundle_{timestamp}.asc"
            filepath = os.path.join(file_list_path, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(exported.stdout)

            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Saved as {filename}",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)

        loading = LoadingScreenThread(text="Encoding...")
        loading.start()
        try:
            qr_encoder = UrBytesQrEncoder(
                data=exported.stdout.encode("utf-8"),
                qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
            )
        finally:
            loading.stop()

        num_codes = qr_encoder.seq_len()
        ret = self.run_screen(
            WarningScreen,
            title="Animated QR",
            status_headline=None,
            text=f"This export requires {num_codes} QR code{'s' if num_codes > 1 else ''}.",
            show_back_button=True,
            button_data=[ButtonOption("Start")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
        return Destination(MainMenuView)


class ToolsGPGBip85MetadataMenuView(View):
    SAVE = ButtonOption("Save BIP85 Data")
    LOAD = ButtonOption("Load BIP85 Data")
    REBUILD = ButtonOption("Rebuild BIP85 Key")

    def run(self):
        button_data = [self.SAVE, self.LOAD, self.REBUILD]
        selected = self.run_screen(
            ButtonListScreen,
            title="BIP85 Metadata",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = button_data[selected]
        if choice == self.SAVE:
            return Destination(ToolsGPGSaveBip85DataView)
        if choice == self.LOAD:
            return Destination(ToolsGPGLoadBip85DataView)
        return Destination(ToolsGPGRebuildBip85KeyView)


class ToolsGPGSaveBip85DataView(View):
    TO_MICROSD = ButtonOption("To MicroSD")
    TO_QR = ButtonOption("To QR")
    TO_SEEDKEEPER = ButtonOption("To Seedkeeper")

    def run(self):
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            QRDisplayScreen,
            LargeIconStatusScreen,
            WarningScreen,
            LoadingScreenThread,
        )
        from seedsigner.models.encode_qr import UrBytesQrEncoder
        from seedsigner.helpers import seedkeeper_utils
        from pysatochip.CardConnector import UnexpectedSW12Error
        from seedsigner.helpers.iso7816 import format_sw_error
        import time

        button_data = [self.TO_MICROSD, self.TO_QR, self.TO_SEEDKEEPER]
        selected = self.run_screen(
            ButtonListScreen,
            title="Save BIP85 Data",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        choice = button_data[selected]
        if choice == self.TO_MICROSD:
            from seedsigner.gui.screens import LargeIconStatusScreen, WarningScreen
            from seedsigner.hardware.microsd import MicroSD
            import os

            if len(self.controller.storage.seeds) > 0:
                ret = self.run_screen(
                    WarningScreen,
                    title="WARNING",
                    status_headline=None,
                    text="These tools write data to the microSD card and may expose loaded secrets.",
                    show_back_button=True,
                    button_data=[ButtonOption("Continue")],
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)
            try:
                bip85_save_data(file_list_path)
                logger.info("BIP85 data saved to %s", os.path.abspath(file_list_path))
                screen = LargeIconStatusScreen
                msg = "BIP85 data saved"
            except Exception:
                screen = WarningScreen
                msg = "Failed to save BIP85 data"
            self.run_screen(
                screen,
                title="Result",
                status_headline=None,
                text=msg,
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
            return Destination(ToolsGPGMenuView)

        if choice == self.TO_QR:
            data = bip85_export_json().encode("utf-8")
            loading = LoadingScreenThread(text="Encoding...")
            loading.start()
            try:
                qr_encoder = UrBytesQrEncoder(
                    data=data,
                    qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
                )
            finally:
                loading.stop()

            num_codes = qr_encoder.seq_len()
            ret = self.run_screen(
                WarningScreen,
                title="Animated QR",
                status_headline=None,
                text=f"This export requires {num_codes} QR code{'s' if num_codes > 1 else ''}.",
                show_back_button=True,
                button_data=[ButtonOption("Start")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
            return Destination(ToolsGPGMenuView)

        # Seedkeeper export
        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
        if not Satochip_Connector:
            return Destination(BackStackView)

        data_bytes = bip85_export_json().encode("utf-8")
        status = Satochip_Connector.card_get_status()[3]
        if status["protocol_minor_version"] == 1:
            if len(data_bytes) > 255:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="BIP85 data too large for Seedkeeper v1",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            secret_list = [len(data_bytes)] + list(data_bytes)
        else:
            secret_list = list(len(data_bytes).to_bytes(2, "big")) + list(data_bytes)

        label = f"BIP85-GPG-{int(time.time())}"
        header = Satochip_Connector.make_header(
            "Data", "Plaintext export allowed", label
        )
        secret_dic = {"header": header, "secret_list": secret_list}

        try:
            fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                Satochip_Connector, secret_dic
            )
        except Exception as e:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        if not fits:
            self.run_screen(
                WarningScreen,
                title="Not Enough Space",
                status_headline=None,
                text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        try:
            loading = LoadingScreenThread(text="Saving Secret\n\n\n\n\n\n")
            loading.start()
            Satochip_Connector.seedkeeper_import_secret(secret_dic)
            loading.stop()
            screen = LargeIconStatusScreen
            msg = "BIP85 data saved"
        except UnexpectedSW12Error as e:
            loading.stop()
            if e.sw1 == 0x6A and e.sw2 == 0x84:
                err_text = "Not enough space on Seedkeeper"
            else:
                err_text = format_sw_error(e.sw1, e.sw2)
            screen = WarningScreen
            msg = err_text
        except Exception:
            loading.stop()
            screen = WarningScreen
            msg = "Failed to save BIP85 data"

        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGLoadBip85DataView(View):
    FROM_MICROSD = ButtonOption("From MicroSD")
    FROM_QR = ButtonOption("From QR")
    FROM_SEEDKEEPER = ButtonOption("From Seedkeeper")

    def run(self):
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            QRDisplayScreen,
            WarningScreen,
            LargeIconStatusScreen,
            LoadingScreenThread,
        )
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.decode_qr import DecodeQR, QRType
        from seedsigner.helpers import seedkeeper_utils
        from urtypes.bytes import Bytes
        import time, binascii

        button_data = [self.FROM_MICROSD, self.FROM_QR, self.FROM_SEEDKEEPER]
        selected = self.run_screen(
            ButtonListScreen,
            title="Load BIP85 Data",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        choice = button_data[selected]
        if choice == self.FROM_MICROSD:
            from seedsigner.gui.screens import LargeIconStatusScreen, WarningScreen
            from seedsigner.hardware.microsd import MicroSD
            import os

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            try:
                bip85_load_data(file_list_path)
                logger.info("BIP85 data loaded from %s", os.path.abspath(file_list_path))
                screen = LargeIconStatusScreen
                msg = "BIP85 data loaded"
            except Exception:
                screen = WarningScreen
                msg = "Failed to load BIP85 data"
            self.run_screen(
                screen,
                title="Result",
                status_headline=None,
                text=msg,
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
            return Destination(ToolsGPGMenuView)

        if choice == self.FROM_QR:
            decoder = DecodeQR()
            ScanScreen(decoder=decoder, instructions_text="Scan BIP85 data").display()
            self.controller.reset_screensaver_timeout()
            time.sleep(0.1)
            if not decoder.is_complete:
                return Destination(BackStackView)
            if decoder.qr_type == QRType.BYTES__UR:
                raw = Bytes.from_cbor(decoder.decoder.result_message().cbor).data
                if isinstance(raw, memoryview):
                    raw = raw.tobytes()
                data_str = raw.decode("utf-8")
            elif decoder.qr_type == QRType.TEXT:
                data_str = decoder.get_text()
            else:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Unsupported QR format",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            bip85_import_json(data_str)
            self.run_screen(
                LargeIconStatusScreen,
                title="Result",
                status_headline=None,
                text="BIP85 data loaded",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
            return Destination(ToolsGPGMenuView)

        # Seedkeeper import
        Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
        if not Satochip_Connector:
            return Destination(BackStackView)

        loading = LoadingScreenThread(text="Listing Secrets\n\n\n\n\n\n")
        loading.start()
        headers = Satochip_Connector.seedkeeper_list_secret_headers()
        loading.stop()

        entries = []
        buttons = []
        for header in headers:
            stype = SEEDKEEPER_DIC_TYPE.get(header["type"], hex(header["type"]))
            rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header["export_rights"], hex(header["export_rights"]))
            label = header["label"]
            if (
                stype == "Data"
                and rights == "Plaintext export allowed"
                and label.startswith("BIP85-GPG-")
            ):
                entries.append(header)
                buttons.append(ButtonOption(label))

        if not entries:
            self.run_screen(
                WarningScreen,
                title="No BIP85 Data",
                status_headline=None,
                text="No BIP85 data on Seedkeeper",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected = self.run_screen(
            ButtonListScreen,
            title="Select BIP85 Data",
            is_button_text_centered=False,
            button_data=buttons,
            show_back_button=True,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        loading = LoadingScreenThread(text="Loading BIP85 Data\n\n\n\n\n\n")
        loading.start()
        secret_dict = Satochip_Connector.seedkeeper_export_secret(entries[selected]["id"], None)
        loading.stop()

        data_bytes = binascii.unhexlify(secret_dict["secret"])[2:]
        bip85_import_json(data_bytes.decode())
        self.run_screen(
            LargeIconStatusScreen,
            title="Result",
            status_headline=None,
            text="BIP85 data loaded",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGRebuildBip85KeyView(View):
    def run(self):
        from embit import bip32
        from pgpy import PGPKey, PGPUID
        from pgpy.constants import (
            PubKeyAlgorithm,
            KeyFlags,
            HashAlgorithm,
            SymmetricKeyAlgorithm,
            CompressionAlgorithm,
        )
        from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
        from pgpy.packet import fields
        from pgpy.packet.types import MPI
        from datetime import datetime, timezone, date
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.gui.screens import LargeIconStatusScreen, WarningScreen
        import re

        if not BIP85_DATA:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No BIP85 data loaded",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        entries = []
        buttons = []
        for entry in BIP85_DATA.values():
            for seed in self.controller.storage.seeds:
                fpr = seed.get_fingerprint(
                    self.settings.get_value(SettingsConstants.SETTING__NETWORK)
                )
                if fpr == entry["seed_fpr"]:
                    entries.append((entry, seed))
                    label = entry["uids"][0] if entry.get("uids") else entry["primary_fpr"]
                    buttons.append(ButtonOption(label))
                    break

        if not entries:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No matching seeds",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected = self.run_screen(
            ButtonListScreen,
            title="Rebuild BIP85 Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        entry, seed = entries[selected]

        key_index = entry["index"]
        key_type_label = entry["key_type"]
        key_type_lookup = dict(_bip85_key_type_choices(include_all=True))
        key_type = key_type_lookup[key_type_label]

        uid_list = entry.get("uids", [])
        if not uid_list:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="BIP85 data missing UIDs",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        primary_uid = entry.get("primary_uid", uid_list[0])

        def parse_uid(uid_str):
            m = re.match(r"^(.*?)(?:\s*<([^>]+)>)?$", uid_str)
            name = m.group(1).strip()
            email = m.group(2)
            return name, email

        created = datetime.fromtimestamp(BIP85_GPG_CREATED_TS, tz=timezone.utc)
        if key_type == "rsa2048":
            expiration_dt = datetime(2029, 12, 31, tzinfo=timezone.utc)
        else:
            expiration_dt = datetime(2035, 12, 31, tzinfo=timezone.utc)
        expires = expiration_dt - created

        # Map primary key type to algorithm details for verification
        algo_map = {
            "ed25519": ("22", "", "ed25519"),
            "secp256k1": ("19", "", "secp256k1"),
            "p256": ("19", "", "nistp256"),
            "brainpoolp256r1": ("19", "", "brainpoolp256r1"),
            "rsa2048": ("1", "2048", ""),
            "rsa3072": ("1", "3072", ""),
            "rsa4096": ("1", "4096", ""),
        }
        primary_algo, primary_bits, primary_curve = algo_map[key_type]

        # Build subkey info for verification
        verify_subkeys = []
        curve_map = {
            "nist p-256": "nistp256",
            "brainpool p-256": "brainpoolp256r1",
            "secp256k1": "secp256k1",
            "ed25519": "ed25519",
        }
        for sk in entry.get("subkeys", []):
            g_idx = sk["index"]
            parts = sk["type"].split()
            if parts[0] == "RSA":
                algo = "1"
                bits = parts[1]
                curve = ""
            else:
                algo = {"ECDH": "18", "ECDSA": "19", "EdDSA": "22"}[parts[0]]
                curve_label = " ".join(parts[1:])
                if curve_label.startswith("ECC "):
                    curve_label = curve_label[4:]
                curve_label_lc = curve_label.lower()
                curve = curve_map.get(curve_label_lc, curve_label_lc)
                if parts[0] == "ECDH" and curve_label_lc == "ed25519":
                    curve = "cv25519"
                bits = ""
            verify_subkeys.append(
                {
                    "idx": g_idx + 1,
                    "algo": algo,
                    "bits": bits,
                    "curve": curve,
                    "fpr": sk.get("fingerprint", ""),
                }
            )

        logger.info(
            "Verifying BIP85 data for %s idx=%s", entry["primary_fpr"], key_index
        )
        if not bip85_verify_existing(
            seed,
            entry["primary_fpr"],
            key_index,
            BIP85_GPG_CREATED_TS,
            primary_algo,
            primary_bits,
            primary_curve,
            verify_subkeys,
        ):
            logger.warning(
                "BIP85 verification failed for %s", entry["primary_fpr"]
            )
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Selected seed/index failed validation",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        root = seed.get_root(self.settings.get_value(SettingsConstants.SETTING__NETWORK))
        KEY_BITS = (
            2048
            if key_type == "rsa2048"
            else 3072
            if key_type == "rsa3072"
            else 4096
            if key_type == "rsa4096"
            else None
        )

        def rsa_to_privpacket(rsa_key):
            priv = fields.RSAPriv()
            priv.n = MPI(rsa_key.n)
            priv.e = MPI(rsa_key.e)
            priv.d = MPI(rsa_key.d)
            priv.p = MPI(rsa_key.p)
            priv.q = MPI(rsa_key.q)
            priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
            priv._compute_chksum()
            return priv

        loading = LoadingScreenThread(text="Rebuilding BIP85 GPG key\n\n\n\n\n\n")
        loading.start()
        try:
            pk = PrivKeyV4()
            if key_type == "secp256k1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_secp256k1_from_root(root, key_index)
            elif key_type == "p256":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_p256_from_root(root, key_index)
            elif key_type == "p384":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_p384_from_root(root, key_index)
            elif key_type == "p521":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_p521_from_root(root, key_index)
            elif key_type == "brainpoolp256r1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index)
            elif key_type == "brainpoolp384r1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_brainpoolp384r1_from_root(root, key_index)
            elif key_type == "brainpoolp512r1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_brainpoolp512r1_from_root(root, key_index)
            elif key_type == "ed25519":
                pk.pkalg = PubKeyAlgorithm.EdDSA
                pk.keymaterial = bip85_ed25519_from_root(root, key_index)
            else:
                rsa_main = bip85_rsa_from_root(root, KEY_BITS, key_index)
                pk.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
                pk.keymaterial = rsa_to_privpacket(rsa_main)
            pk.created = created
            pk.update_hlen()

            pgp_key = PGPKey()
            pgp_key._key = pk

            for uid_str in uid_list:
                name, email = parse_uid(uid_str)
                uid = PGPUID.new(name, email=email)
                pgp_key.add_uid(
                    uid,
                    usage={KeyFlags.Certify, KeyFlags.Sign},
                    hashes=[HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.ZLIB],
                    expires=expires,
                    created=created,
                    primary=(uid_str == primary_uid),
                )

            for sub in entry.get("subkeys", _bip85_subkey_specs("rsa")):
                if isinstance(sub, int):
                    g_idx = sub
                    group_idx = g_idx // 3
                    idx = g_idx % 3
                    specs = _bip85_subkey_specs(
                        {
                            "p256": "nistp256",
                            "p384": "nistp384",
                            "p521": "nistp521",
                            "brainpoolp256r1": "brainpoolP256r1",
                            "brainpoolp384r1": "brainpoolP384r1",
                            "brainpoolp512r1": "brainpoolP512r1",
                            "secp256k1": "secp256k1",
                            "ed25519": "ed25519",
                        }.get(key_type, "rsa")
                    )
                    _, pkalg, usage, *alg = specs[idx]
                    func_map = {
                        "secp256k1": bip85_secp256k1_from_root,
                        "p256": bip85_p256_from_root,
                        "p384": bip85_p384_from_root,
                        "p521": bip85_p521_from_root,
                        "brainpoolp256r1": bip85_brainpoolp256r1_from_root,
                        "brainpoolp384r1": bip85_brainpoolp384r1_from_root,
                        "brainpoolp512r1": bip85_brainpoolp512r1_from_root,
                        "ed25519": bip85_ed25519_from_root,
                    }
                    subpkt = PrivSubKeyV4()
                    subpkt.pkalg = pkalg
                    if key_type in func_map:
                        subpkt.keymaterial = func_map[key_type](
                            root, group_idx, idx, alg[0]
                        )
                    else:
                        rsa_sub = bip85_rsa_from_root(root, KEY_BITS, group_idx, idx)
                        subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
                else:
                    g_idx = sub.get("index", 0)
                    group_idx = g_idx // 3
                    idx = g_idx % 3
                    usage = (
                        {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}
                        if idx == 0
                        else {KeyFlags.Authentication}
                        if idx == 1
                        else {KeyFlags.Sign}
                    )
                    parts = sub.get("type", key_type_label).split()
                    subpkt = PrivSubKeyV4()
                    if parts[0] == "RSA":
                        bits = int(parts[1])
                        subpkt.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
                        rsa_sub = bip85_rsa_from_root(root, bits, group_idx, idx)
                        subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
                    else:
                        alg_name = parts[0]
                        curve_label = " ".join(parts[1:])
                        if curve_label.startswith("ECC "):
                            curve_label = curve_label[4:]
                        curve_label_lc = curve_label.lower()
                        func_map = {
                            "secp256k1": bip85_secp256k1_from_root,
                            "nist p-256": bip85_p256_from_root,
                            "nist p-384": bip85_p384_from_root,
                            "nist p-521": bip85_p521_from_root,
                            "brainpool p-256": bip85_brainpoolp256r1_from_root,
                            "brainpool p-384": bip85_brainpoolp384r1_from_root,
                            "brainpool p-512": bip85_brainpoolp512r1_from_root,
                            "ed25519": bip85_ed25519_from_root,
                        }
                        pkalg_map = {
                            "ECDH": PubKeyAlgorithm.ECDH,
                            "ECDSA": PubKeyAlgorithm.ECDSA,
                            "EdDSA": PubKeyAlgorithm.EdDSA,
                        }
                        subpkt.pkalg = pkalg_map[parts[0]]
                        func = func_map[curve_label_lc]
                        subpkt.keymaterial = func(root, group_idx, idx, alg_name)
                    subpkt.created = created
                    subpkt.update_hlen()
                    subkey = PGPKey()
                    subkey._key = subpkt
                    exp_fpr = sub.get("fingerprint")
                    logger.info(
                        "Derived subkey idx=%s fpr=%s expected=%s",
                        g_idx,
                        subkey.fingerprint,
                        exp_fpr,
                    )
                    if exp_fpr and subkey.fingerprint != exp_fpr:
                        logger.warning(
                            "Subkey fingerprint mismatch at idx=%s: expected %s got %s",
                            g_idx,
                            exp_fpr,
                            subkey.fingerprint,
                        )
                    pgp_key.add_subkey(
                        subkey,
                        usage=usage,
                        hashes=[HashAlgorithm.SHA256],
                        ciphers=[SymmetricKeyAlgorithm.AES256],
                        compression=[CompressionAlgorithm.ZLIB],
                        expires=expires,
                        created=created,
                    )
                    continue

                subpkt.created = created
                subpkt.update_hlen()
                subkey = PGPKey()
                subkey._key = subpkt
                exp_fpr = sub.get("fingerprint") if isinstance(sub, dict) else None
                logger.info(
                    "Derived subkey idx=%s fpr=%s expected=%s",
                    g_idx,
                    subkey.fingerprint,
                    exp_fpr,
                )
                if exp_fpr and subkey.fingerprint != exp_fpr:
                    logger.warning(
                        "Subkey fingerprint mismatch at idx=%s: expected %s got %s",
                        g_idx,
                        exp_fpr,
                        subkey.fingerprint,
                    )
                pgp_key.add_subkey(
                    subkey,
                    usage=usage,
                    hashes=[HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.ZLIB],
                    expires=expires,
                    created=created,
                )

            armored = str(pgp_key)
            result = run(["gpg", "--batch", "--import"], input=armored.encode(), capture_output=True)
        finally:
            loading.stop()

        if result.returncode == 0:
            self.run_screen(
                LargeIconStatusScreen,
                title="Result",
                status_headline=None,
                text="BIP85 key rebuilt",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
        return Destination(ToolsGPGMenuView)


class ToolsGPGSubkeyMenuView(View):
    ADD_SUBKEYS = ButtonOption("Add Subkeys")
    REVOKE_SUBKEYS = ButtonOption("Revoke Subkeys")
    DELETE_SUBKEYS = ButtonOption("Delete Subkeys")
    CHANGE_EXPIRY = ButtonOption("Change Expiry")
    EXPORT_SUBKEY_SECRETS = ButtonOption("Export Subkey Secrets")

    def run(self):
        button_data = [
            self.ADD_SUBKEYS,
            self.REVOKE_SUBKEYS,
            self.DELETE_SUBKEYS,
            self.CHANGE_EXPIRY,
            self.EXPORT_SUBKEY_SECRETS,
        ]

        selected = self.run_screen(
            ButtonListScreen,
            title="Subkey Operations",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        choice = button_data[selected]
        if choice == self.ADD_SUBKEYS:
            return Destination(ToolsGPGAddSubkeysView)
        if choice == self.REVOKE_SUBKEYS:
            return Destination(ToolsGPGRevokeSubkeysView)
        if choice == self.DELETE_SUBKEYS:
            return Destination(ToolsGPGDeleteSubkeysView)
        if choice == self.CHANGE_EXPIRY:
            return Destination(ToolsGPGChangeExpiryView)
        return Destination(ToolsGPGExportSubkeySecretsView)


class ToolsGPGRevokeSubkeysView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import ButtonListScreen, LargeIconStatusScreen, WarningScreen

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
            fingerprint,
        ], capture_output=True, text=True)
        subkeys = parse_subkey_list(result.stdout)
        if not subkeys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No subkeys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        while subkeys:
            sk_buttons = [ButtonOption(f"{sk['fpr'][-8:]} [{sk['caps']}]") for sk in subkeys]
            sk_buttons.append(ButtonOption("Done"))
            sel = self.run_screen(
                ButtonListScreen,
                title="Revoke Subkeys",
                is_button_text_centered=False,
                button_data=sk_buttons,
            )
            if sel == RET_CODE__BACK_BUTTON or sk_buttons[sel] == sk_buttons[-1]:
                break
            sub = subkeys[sel]
            r = gpg_edit_subkey(fingerprint, sub["idx"], "revkey")
            if r.returncode == 0 and fingerprint in BIP85_DATA:
                BIP85_DATA[fingerprint]["revocations"].append(sub["fpr"])
            screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
            msg = "Subkey revoked" if r.returncode == 0 else "Failed to revoke"
            self.run_screen(
                screen,
                title="Result",
                status_headline=None,
                text=msg,
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            result = run([
                "gpg",
                "--list-secret-keys",
                "--with-colons",
                fingerprint,
            ], capture_output=True, text=True)
            subkeys = parse_subkey_list(result.stdout)
        return Destination(ToolsGPGMenuView)


class ToolsGPGDeleteSubkeysView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import ButtonListScreen, LargeIconStatusScreen, WarningScreen

        ret = self.run_screen(
            WarningScreen,
            title="WARNING",
            status_headline=None,
            text="Revoking subkeys is usually preferred\nover deleting them.",
            show_back_button=True,
            button_data=[ButtonOption("I Understand")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
            fingerprint,
        ], capture_output=True, text=True)
        subkeys = parse_subkey_list(result.stdout)
        subkeys = filter_deletable_subkeys(fingerprint, subkeys)
        if not subkeys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No subkeys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        while subkeys:
            sk_buttons = [ButtonOption(f"{sk['fpr'][-8:]} [{sk['caps']}]") for sk in subkeys]
            sk_buttons.append(ButtonOption("Done"))
            sel = self.run_screen(
                ButtonListScreen,
                title="Delete Subkeys",
                is_button_text_centered=False,
                button_data=sk_buttons,
            )
            if sel == RET_CODE__BACK_BUTTON or sk_buttons[sel] == sk_buttons[-1]:
                break
            sub = subkeys[sel]
            r = gpg_edit_subkey(fingerprint, sub["idx"], "delkey")
            screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
            msg = "Subkey deleted" if r.returncode == 0 else "Failed to delete"
            self.run_screen(
                screen,
                title="Result",
                status_headline=None,
                text=msg,
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            result = run([
                "gpg",
                "--list-secret-keys",
                "--with-colons",
                fingerprint,
            ], capture_output=True, text=True)
            if r.returncode == 0 and fingerprint in BIP85_DATA:
                entry = BIP85_DATA[fingerprint]
                entry["subkeys"] = [
                    sk for sk in entry["subkeys"] if sk["fingerprint"] != sub["fpr"]
                ]
            subkeys = parse_subkey_list(result.stdout)
            subkeys = filter_deletable_subkeys(fingerprint, subkeys)
        return Destination(ToolsGPGMenuView)


class ToolsGPGChangeExpiryView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import ButtonListScreen, LargeIconStatusScreen, WarningScreen

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
            fingerprint,
        ], capture_output=True, text=True)
        subkeys = parse_subkey_list(result.stdout)
        if not subkeys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No subkeys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        sk_buttons = [ButtonOption(f"{sk['fpr'][-8:]} [{sk['caps']}]") for sk in subkeys]
        sel = self.run_screen(
            ButtonListScreen,
            title="Select Subkey",
            is_button_text_centered=False,
            button_data=sk_buttons,
        )
        if sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        sub_fpr = subkeys[sel]["fpr"]

        exp_buttons = [
            ButtonOption("1 year"),
            ButtonOption("2 years"),
            ButtonOption("5 years"),
            ButtonOption("Never"),
        ]
        exp_vals = ["1y", "2y", "5y", "0"]
        exp_sel = self.run_screen(
            ButtonListScreen,
            title="Set Expiry",
            is_button_text_centered=False,
            button_data=exp_buttons,
        )
        if exp_sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        expire = exp_vals[exp_sel]
        r = run([
            "gpg",
            "--batch",
            "--yes",
            "--quick-set-expire",
            fingerprint,
            expire,
            sub_fpr,
        ])
        screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
        msg = "Expiry changed" if r.returncode == 0 else "Failed to change expiry"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGExportSubkeySecretsView(View):
    def run(self):
        from subprocess import run
        import os
        import logging
        from seedsigner.hardware.microsd import MicroSD
        from seedsigner.models.encode_qr import UrBytesQrEncoder
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            LoadingScreenThread,
            QRDisplayScreen,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
            fingerprint,
        ], capture_output=True, text=True)
        subkeys = parse_subkey_list(result.stdout)
        if not subkeys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No subkeys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected_fprs: dict[str, str] = {}
        for label, flag in [("Signing", "s"), ("Encryption", "e"), ("Auth", "a")]:
            candidates = [
                sk for sk in subkeys if flag in sk["caps"] and sk["fpr"] not in selected_fprs.values()
            ]
            if not candidates:
                continue
            sk_buttons = [ButtonOption(sk["fpr"][-8:]) for sk in candidates]
            sk_buttons.append(ButtonOption("Skip"))
            sel = self.run_screen(
                ButtonListScreen,
                title=f"{label} Subkey",
                is_button_text_centered=False,
                button_data=sk_buttons,
            )
            if sel == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            if sk_buttons[sel].button_label != "Skip":
                selected_fprs[flag] = candidates[sel]["fpr"]

        if not selected_fprs:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No subkeys selected",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        dest_buttons = [
            ButtonOption("File"),
            ButtonOption("QR"),
            ButtonOption("Smartcard"),
        ]
        dest_sel = self.run_screen(
            ButtonListScreen,
            title="Export As",
            is_button_text_centered=False,
            button_data=dest_buttons,
        )
        if dest_sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if dest_buttons[dest_sel].button_label == "Smartcard":
            return Destination(
                ToolsGPGImportKeyToCardView,
                view_args={"fingerprint": fingerprint, "selected_subkeys": selected_fprs},
            )

        exported = gpg_export_selected_subkeys(fingerprint, list(selected_fprs.values()))
        if exported.returncode != 0:
            logging.getLogger(__name__).error(
                "gpg export failed: %s", exported.stderr.strip()
            )
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to export",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        from seedsigner.gui.screens import tools_screens

        ret_dict = tools_screens.ToolsTextQRTextEntryScreen(
            textToEncode="", title="Passphrase"
        ).display()
        if "is_back_button" in ret_dict:
            return Destination(BackStackView)
        try:
            import re

            passphrase = bytes(
                re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                encoding="raw_unicode_escape",
            ).decode("unicode_escape")
        except UnicodeError:
            passphrase = ret_dict["textToEncode"]

        protected = run(
            [
                "gpg",
                "--armor",
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                passphrase,
                "--symmetric",
                "--cipher-algo",
                "AES256",
            ],
            input=exported.stdout,
            capture_output=True,
            text=True,
        )
        if protected.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to protect export",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        armored = protected.stdout

        if dest_buttons[dest_sel].button_label == "File":
            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)
            filename = fingerprint + "_subkey_secrets.asc"
            filepath = os.path.join(file_list_path, filename)
            with open(filepath, "w") as f:
                f.write(armored)
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Saved as {filename}",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(ToolsGPGMenuView)
        if dest_buttons[dest_sel].button_label == "QR":
            loading = LoadingScreenThread(text="Encoding...")
            loading.start()
            try:
                qr_encoder = UrBytesQrEncoder(
                    data=armored,
                    qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
                )
            finally:
                loading.stop()
            num_codes = qr_encoder.seq_len()
            ret = self.run_screen(
                WarningScreen,
                title="Animated QR",
                status_headline=None,
                text=f"This export requires {num_codes} QR code{'s' if num_codes > 1 else ''}.",
                show_back_button=True,
                button_data=[ButtonOption("Start")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
            return Destination(ToolsGPGMenuView)
        return Destination(BackStackView)


class ToolsGPGUidMenuView(View):
    ADD_UID = ButtonOption("Add User ID")
    EDIT_UID = ButtonOption("Edit User IDs")
    SET_PRIMARY_UID = ButtonOption("Set Primary User ID")
    REVOKE_UID = ButtonOption("Revoke User ID")
    DELETE_UID = ButtonOption("Delete User ID")

    def run(self):
        button_data = [
            self.ADD_UID,
            self.EDIT_UID,
            self.SET_PRIMARY_UID,
            self.REVOKE_UID,
            self.DELETE_UID,
        ]
        selected = self.run_screen(
            ButtonListScreen,
            title="User ID Operations",
            is_button_text_centered=False,
            button_data=button_data,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        choice = button_data[selected]
        if choice == self.ADD_UID:
            return Destination(ToolsGPGAddUidView)
        if choice == self.EDIT_UID:
            return Destination(ToolsGPGEditUidView)
        if choice == self.SET_PRIMARY_UID:
            return Destination(ToolsGPGSetPrimaryUidView)
        if choice == self.REVOKE_UID:
            return Destination(ToolsGPGRevokeUidView)
        return Destination(ToolsGPGDeleteUidView)


class ToolsGPGAddUidView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            tools_screens,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]

        # Preserve the key's original primary UID so that adding an
        # additional UID does not change which one is displayed as primary.
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
            fingerprint,
        ], capture_output=True, text=True)
        uids = parse_uid_list(result.stdout)
        primary_uid = uids[0]["uid"] if uids else None

        def prompt_text(title: str):
            ret_dict = tools_screens.ToolsTextQRTextEntryScreen(textToEncode="", title=title).display()
            if "is_back_button" in ret_dict:
                return None
            try:
                import re

                return bytes(
                    re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                    encoding="raw_unicode_escape",
                ).decode("unicode_escape")
            except UnicodeError:
                return ret_dict["textToEncode"]

        name = prompt_text("Name")
        if name is None:
            return Destination(BackStackView)
        email = prompt_text("Email")
        if email is None:
            return Destination(BackStackView)
        uid_str = f"{name} <{email}>" if email else name

        r = run(["gpg", "--batch", "--quick-add-uid", fingerprint, uid_str])
        if r.returncode == 0 and primary_uid:
            run([
                "gpg",
                "--batch",
                "--quick-set-primary-uid",
                fingerprint,
                primary_uid,
            ])
        if r.returncode == 0 and fingerprint in BIP85_DATA:
            entry = BIP85_DATA[fingerprint]
            entry.setdefault("primary_uid", primary_uid)
            entry["uids"].append(uid_str)
        screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
        msg = "User ID added" if r.returncode == 0 else "Failed to add User ID"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGEditUidView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            tools_screens,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run(["gpg", "--list-secret-keys", "--with-colons", fingerprint], capture_output=True, text=True)
        uids = parse_uid_list(result.stdout)
        if not uids:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No user IDs found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        uid_buttons = [ButtonOption(u["uid"]) for u in uids]
        sel = self.run_screen(
            ButtonListScreen,
            title="Select User ID",
            is_button_text_centered=False,
            button_data=uid_buttons,
        )
        if sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        old_uid = uids[sel]["uid"]

        def prompt_text(title: str, default: str = ""):
            ret_dict = tools_screens.ToolsTextQRTextEntryScreen(textToEncode=default, title=title).display()
            if "is_back_button" in ret_dict:
                return None
            try:
                import re

                return bytes(
                    re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                    encoding="raw_unicode_escape",
                ).decode("unicode_escape")
            except UnicodeError:
                return ret_dict["textToEncode"]

        name = prompt_text("Name")
        if name is None:
            return Destination(BackStackView)
        email = prompt_text("Email")
        if email is None:
            return Destination(BackStackView)
        new_uid = f"{name} <{email}>" if email else name

        r = run(["gpg", "--batch", "--quick-add-uid", fingerprint, new_uid])
        success = r.returncode == 0
        if success:
            run(["gpg", "--batch", "--quick-set-primary-uid", fingerprint, new_uid])
            run(["gpg", "--batch", "--quick-revoke-uid", fingerprint, old_uid])
        screen = LargeIconStatusScreen if success else WarningScreen
        msg = "User ID updated" if success else "Failed to update User ID"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGSetPrimaryUidView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            seed_screens,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run(["gpg", "--list-secret-keys", "--with-colons", fingerprint], capture_output=True, text=True)
        uids = parse_uid_list(result.stdout)
        if not uids:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No user IDs found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        uid_buttons = [ButtonOption(u["uid"]) for u in uids]
        sel = self.run_screen(
            ButtonListScreen,
            title="Set Primary User ID",
            is_button_text_centered=False,
            button_data=uid_buttons,
        )
        if sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        uid = uids[sel]["uid"]

        r = run(["gpg", "--batch", "--quick-set-primary-uid", fingerprint, uid])
        if r.returncode == 0 and fingerprint in BIP85_DATA:
            entry = BIP85_DATA[fingerprint]
            entry["primary_uid"] = uid
            ulist = entry.get("uids", [])
            if uid in ulist:
                ulist.remove(uid)
                ulist.insert(0, uid)
        screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
        msg = "Primary UID set" if r.returncode == 0 else "Failed to set primary UID"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGRevokeUidView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
        )

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run(["gpg", "--list-secret-keys", "--with-colons", fingerprint], capture_output=True, text=True)
        uids = parse_uid_list(result.stdout)
        if not uids:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No user IDs found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        uid_buttons = [ButtonOption(u["uid"]) for u in uids]
        sel = self.run_screen(
            ButtonListScreen,
            title="Revoke User ID",
            is_button_text_centered=False,
            button_data=uid_buttons,
        )
        if sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        uid = uids[sel]["uid"]

        r = run(["gpg", "--batch", "--quick-revoke-uid", fingerprint, uid])
        screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
        msg = "User ID revoked" if r.returncode == 0 else "Failed to revoke User ID"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGDeleteUidView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
        )

        ret = self.run_screen(
            WarningScreen,
            title="WARNING",
            status_headline=None,
            text="Revocation is almost always\npreferable to deleting.",
            show_back_button=True,
            button_data=[ButtonOption("I Understand")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        result = run(["gpg", "--list-secret-keys", "--with-colons"], capture_output=True, text=True)
        keys = parse_secret_key_list(result.stdout)
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]
        result = run(["gpg", "--list-secret-keys", "--with-colons", fingerprint], capture_output=True, text=True)
        uids = parse_uid_list(result.stdout)
        if not uids:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No user IDs found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        uid_buttons = [ButtonOption(u["uid"]) for u in uids]
        sel = self.run_screen(
            ButtonListScreen,
            title="Delete User ID",
            is_button_text_centered=False,
            button_data=uid_buttons,
        )
        if sel == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        uid_str = uids[sel]["uid"]
        idx = uids[sel]["idx"]

        r = gpg_edit_uid(fingerprint, idx, "deluid")
        if r.returncode == 0 and fingerprint in BIP85_DATA:
            entry = BIP85_DATA[fingerprint]
            entry["uids"] = [u for u in entry.get("uids", []) if u != uid_str]
            if entry.get("primary_uid") == uid_str:
                entry["primary_uid"] = entry["uids"][0] if entry["uids"] else None
        screen = LargeIconStatusScreen if r.returncode == 0 else WarningScreen
        msg = "User ID deleted" if r.returncode == 0 else "Failed to delete User ID"
        self.run_screen(
            screen,
            title="Result",
            status_headline=None,
            text=msg,
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(ToolsGPGMenuView)


class ToolsGPGFileOpsMenuView(View):
    ENCRYPT = ButtonOption("Encrypt")
    DECRYPT = ButtonOption("Decrypt")
    SIGN = ButtonOption("Sign")
    VERIFY = ButtonOption("Verify Signature")

    def run(self):
        button_data = [self.ENCRYPT, self.DECRYPT, self.SIGN, self.VERIFY]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="File Operations",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        selected = button_data[selected_menu_num]
        if selected == self.ENCRYPT:
            return Destination(ToolsGPGEncryptFileView)
        if selected == self.DECRYPT:
            return Destination(ToolsGPGDecryptFileView)
        if selected == self.SIGN:
            return Destination(ToolsGPGSignMenuView)
        return Destination(ToolsGPGVerifyFileView)


class ToolsGPGMessageMenuView(View):
    ENCRYPT = ButtonOption("Create Message")
    DECRYPT = ButtonOption("Load Message")

    def run(self):
        button_data = [self.ENCRYPT, self.DECRYPT]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Secure Messaging",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.ENCRYPT:
            return Destination(ToolsGPGEncryptMessageView)
        return Destination(ToolsGPGDecryptMessageView)


class ToolsGPGSignMenuView(View):
    FILE = ButtonOption("File")
    MANIFEST = ButtonOption("Manifest")

    def run(self):
        button_data = [self.FILE, self.MANIFEST]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Sign",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.FILE:
            return Destination(ToolsGPGSignFileView)
        return Destination(ToolsGPGSignManifestView)


class ToolsGPGEncryptMessageView(View):
    def run(self):
        from subprocess import run
        import time
        from seedsigner.helpers import seedkeeper_utils
        from seedsigner.helpers.gpg_message import encrypt_message
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            WarningScreen,
            LoadingScreenThread,
            QRDisplayScreen,
        )
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.gui.screens.tools_screens import ToolsTextQRTextEntryScreen
        from seedsigner.models.decode_qr import DecodeQR
        from seedsigner.models.encode_qr import UrBytesQrEncoder

        result = run([
            "gpg",
            "--list-keys",
            "--with-colons",
        ], capture_output=True, text=True)

        keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "pub":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        SKIP = ButtonOption("Skip")
        buttons = [SKIP]
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            buttons.append(ButtonOption(label))

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if buttons[selected] is SKIP:
            key = None
        else:
            key = keys[selected - 1]

        SRC_TYPE = ButtonOption("Type Message")
        SRC_SEEDKEEPER = ButtonOption("Load Seedkeeper")
        SRC_SCAN = ButtonOption("Scan QR")
        src_buttons = [SRC_TYPE, SRC_SEEDKEEPER, SRC_SCAN]

        src_selected = self.run_screen(
            ButtonListScreen,
            title="Message Source",
            is_button_text_centered=False,
            button_data=src_buttons,
        )

        if src_selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if src_buttons[src_selected] == SRC_TYPE:
            ret_dict = ToolsTextQRTextEntryScreen(textToEncode="", title="Message").display()
            if "is_back_button" in ret_dict:
                return Destination(BackStackView)
            message = ret_dict["textToEncode"]
        elif src_buttons[src_selected] == SRC_SCAN:
            decoder = DecodeQR(is_text=True)
            ScanScreen(decoder=decoder, instructions_text="Scan message").display()
            self.controller.reset_screensaver_timeout()
            time.sleep(0.1)
            if not decoder.is_complete:
                return Destination(BackStackView)
            message = decoder.get_text()
        else:
            Satochip_Connector = seedkeeper_utils.init_satochip(self, init_card_filter=["seedkeeper"])
            if not Satochip_Connector:
                return Destination(BackStackView)

            loading = LoadingScreenThread(text="Listing Secrets\n\n\n\n\n\n")
            loading.start()
            headers = Satochip_Connector.seedkeeper_list_secret_headers()
            loading.stop()

            headers_parsed = []
            buttons = []
            for header in headers:
                stype = SEEDKEEPER_DIC_TYPE.get(header["type"], hex(header["type"]))
                export_rights = SEEDKEEPER_DIC_EXPORT_RIGHTS.get(header["export_rights"], hex(header["export_rights"]))
                if stype == "Data" and export_rights == "Plaintext export allowed":
                    label = header["label"] or "Unnamed"
                    headers_parsed.append((header["id"], label))
                    buttons.append(ButtonOption(label))

            if not headers_parsed:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="No messages found",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            selected_msg = self.run_screen(
                ButtonListScreen,
                title="Select Message",
                is_button_text_centered=False,
                button_data=buttons,
            )
            if selected_msg == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            loading = LoadingScreenThread(text="Loading Secret\n\n\n\n\n\n")
            loading.start()
            secret_dict = Satochip_Connector.seedkeeper_export_secret(headers_parsed[selected_msg][0], None)
            loading.stop()

            secret_list = secret_dict["secret_list"]
            status = Satochip_Connector.card_get_status()[3]
            if status["protocol_minor_version"] == 1:
                length = secret_list[0]
                msg_bytes = bytes(secret_list[1:1 + length])
            else:
                length = (secret_list[0] << 8) + secret_list[1]
                msg_bytes = bytes(secret_list[2:2 + length])
            message = msg_bytes.decode("utf-8")
        signkey_blob = None
        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
        ], capture_output=True, text=True)

        sign_keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                sign_keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        if sign_keys:
            sign_buttons = [ButtonOption("Skip")]
            for sk in sign_keys:
                label = sk["uid"] if sk["uid"] else sk["fpr"][-8:]
                sign_buttons.append(ButtonOption(label))

            selected_sign = self.run_screen(
                ButtonListScreen,
                title="Signing Key",
                is_button_text_centered=False,
                button_data=sign_buttons,
            )

            if selected_sign == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            if selected_sign > 0:
                sign_key = sign_keys[selected_sign - 1]
                exported_sign = run([
                    "gpg",
                    "--armor",
                    "--export-secret-keys",
                    sign_key["fpr"],
                ], capture_output=True, text=True)
                if exported_sign.returncode != 0:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Failed to export signing key",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                signkey_blob = exported_sign.stdout

        if key is not None:
            exported = run([
                "gpg",
                "--armor",
                "--export",
                key["fpr"],
            ], capture_output=True, text=True)
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            pub_blob = exported.stdout
        else:
            pub_blob = None

        try:
            ciphertext = encrypt_message(pub_blob, message, signkey_blob=signkey_blob)
        except ValueError:
            ret_dict = ToolsTextQRTextEntryScreen(textToEncode="", title="Passphrase").display()
            if "is_back_button" in ret_dict:
                return Destination(BackStackView)
            passphrase = ret_dict["textToEncode"]
            try:
                ciphertext = encrypt_message(
                    pub_blob,
                    message,
                    signkey_blob=signkey_blob,
                    signkey_passphrase=passphrase,
                )
            except Exception:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Incorrect passphrase or\nunsupported key type",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
        except Exception:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to encrypt message",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        DEST_QR = ButtonOption("Animated QR")
        DEST_FILE = ButtonOption("microSD")
        dest_buttons = [DEST_QR, DEST_FILE]

        dest_selected = self.run_screen(
            ButtonListScreen,
            title="Export to",
            is_button_text_centered=False,
            button_data=dest_buttons,
        )

        if dest_selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if dest_buttons[dest_selected] == DEST_FILE:
            import os
            from datetime import datetime

            if len(self.controller.storage.seeds) > 0:
                ret = self.run_screen(
                    WarningScreen,
                    title="WARNING",
                    status_headline=None,
                    text="These tools write data to the microSD card and may expose loaded secrets.",
                    show_back_button=True,
                    button_data=[ButtonOption("Continue")],
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)
            filename = f"gpgmsg_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = os.path.join(file_list_path, filename)
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(ciphertext)
            except Exception:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to save file",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Saved as {filename}",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)

        loading = LoadingScreenThread(text="Encoding...")
        loading.start()
        try:
            qr_encoder = UrBytesQrEncoder(
                data=ciphertext.encode("utf-8"),
                qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
            )
        finally:
            loading.stop()

        num_codes = qr_encoder.seq_len()
        ret = self.run_screen(
            WarningScreen,
            title="Animated QR",
            status_headline=None,
            text=f"This export requires {num_codes} QR code{'s' if num_codes > 1 else ''}.",
            show_back_button=True,
            button_data=[ButtonOption("Start")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
        return Destination(MainMenuView)


class ToolsGPGDecryptMessageView(View):
    def run(self):
        from subprocess import run
        from seedsigner.helpers.gpg_message import decrypt_message
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            WarningScreen,
            LargeIconStatusScreen,
            LoadingScreenThread,
            QRDisplayScreen,
        )
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.gui.screens.tools_screens import (
            ToolsTextQRTextEntryScreen,
            ToolsTextQRReviewTextScreen,
        )
        from seedsigner.models.decode_qr import DecodeQR, QRType
        from seedsigner.models.encode_qr import GenericStaticQrEncoder
        from urtypes.bytes import Bytes
        import time

        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
        ], capture_output=True, text=True)

        keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        ciphertext = self.controller.gpg_pending_message
        if ciphertext:
            self.controller.gpg_pending_message = None
        else:
            SRC_SCAN = ButtonOption("Scan QR")
            SRC_FILE = ButtonOption("Load File")
            src_buttons = [SRC_SCAN, SRC_FILE]
            src_selected = self.run_screen(
                ButtonListScreen,
                title="Message Source",
                is_button_text_centered=False,
                button_data=src_buttons,
            )
            if src_selected == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            if src_buttons[src_selected] == SRC_FILE:
                import os
                if len(self.controller.storage.seeds) > 0:
                    ret = self.run_screen(
                        WarningScreen,
                        title="WARNING",
                        status_headline=None,
                        text="These tools load data from the microSD card and may expose loaded secrets.",
                        show_back_button=True,
                        button_data=[ButtonOption("Continue")],
                    )
                    if ret == RET_CODE__BACK_BUTTON:
                        return Destination(BackStackView)

                file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
                os.makedirs(file_list_path, exist_ok=True)
                file_list = [
                    f
                    for f in os.listdir(file_list_path)
                    if (
                        not f.startswith('.')
                        and f != '__MACOSX'
                        and os.path.isfile(os.path.join(file_list_path, f))
                    )
                ]
                buttons = [ButtonOption(file) for file in file_list]
                if not buttons:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="No files found in microsd-images.",
                        show_back_button=False,
                        button_data=[ButtonOption("OK")],
                    )
                    return Destination(BackStackView)
                selected_file_num = self.run_screen(
                    ButtonListScreen,
                    title="Select File",
                    is_button_text_centered=False,
                    button_data=buttons,
                )
                if selected_file_num == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)
                filename = file_list[selected_file_num]
                filepath = os.path.join(file_list_path, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        ciphertext = f.read()
                except Exception:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Failed to load file",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
            else:
                decoder = DecodeQR()
                ScanScreen(decoder=decoder, instructions_text="Scan secure message").display()
                self.controller.reset_screensaver_timeout()
                time.sleep(0.1)
                if not decoder.is_complete:
                    return Destination(BackStackView)

                if decoder.qr_type == QRType.BYTES__UR:
                    raw = Bytes.from_cbor(
                        decoder.decoder.result_message().cbor
                    ).data
                    if isinstance(raw, memoryview):
                        raw = raw.tobytes()
                    if isinstance(raw, (bytes, bytearray)):
                        ciphertext = raw.decode("utf-8")
                    else:
                        ciphertext = raw
                elif decoder.qr_type == QRType.TEXT:
                    ciphertext = decoder.get_text()
                else:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Unsupported QR format",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)

        # gather public keys for signature verification
        pub_result = run([
            "gpg",
            "--list-keys",
            "--with-colons",
        ], capture_output=True, text=True)

        pubkeys = []
        cur = None
        for line in pub_result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "pub":
                cur = {"fpr": None, "uid": None}
                pubkeys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        for pk in pubkeys:
            exp = run([
                "gpg",
                "--armor",
                "--export",
                pk["fpr"],
            ], capture_output=True, text=True)
            pk["blob"] = exp.stdout

        # try without a private key first in case message is unencrypted
        dec_key = None
        try:
            plaintext, signer_fpr, verified = decrypt_message(
                None,
                ciphertext,
                pubkey_blobs=[pk["blob"] for pk in pubkeys],
            )
        except ValueError:
            # message is encrypted; try each available private key
            decrypted = False
            for key in keys:
                exported = run([
                    "gpg",
                    "--armor",
                    "--export-secret-keys",
                    key["fpr"],
                ], capture_output=True, text=True)
                if exported.returncode != 0:
                    continue
                try:
                    plaintext, signer_fpr, verified = decrypt_message(
                        exported.stdout,
                        ciphertext,
                        pubkey_blobs=[pk["blob"] for pk in pubkeys],
                    )
                    dec_key = key
                    decrypted = True
                    break
                except ValueError as e:
                    if "Passphrase required" in str(e):
                        ret_dict = ToolsTextQRTextEntryScreen(
                            textToEncode="", title="Passphrase"
                        ).display()
                        if "is_back_button" in ret_dict:
                            return Destination(BackStackView)
                        passphrase = ret_dict["textToEncode"]
                        try:
                            plaintext, signer_fpr, verified = decrypt_message(
                                exported.stdout,
                                ciphertext,
                                passphrase=passphrase,
                                pubkey_blobs=[pk["blob"] for pk in pubkeys],
                            )
                            dec_key = key
                            decrypted = True
                            break
                        except Exception:
                            continue
                    else:
                        continue
                except Exception:
                    continue

            if not decrypted:
                err_text = (
                    "No private keys found" if not keys else "Failed to decrypt message"
                )
                load = ButtonOption("Load Key")
                cont = ButtonOption("Continue")
                selected = self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=err_text,
                    show_back_button=False,
                    button_data=[load, cont],
                )
                if selected == 0:
                    self.controller.gpg_pending_message = ciphertext
                    self.controller.resume_main_flow = self.controller.FLOW__GPG_MESSAGE
                    return Destination(ToolsGPGImportPrivkeyMenuView)
                return Destination(BackStackView)

        if isinstance(plaintext, (bytes, bytearray, memoryview)):
            plaintext = plaintext.decode("utf-8")

        # normalize line endings to avoid display issues on carriage returns
        plaintext = plaintext.replace("\r\n", "\n").replace("\r", "\n")

        if signer_fpr:
            label = signer_fpr[-8:]
            have_pub = False
            for pk in pubkeys:
                if pk["fpr"] == signer_fpr:
                    have_pub = True
                    label = pk["uid"] if pk["uid"] else pk["fpr"][-8:]
                    break
            if not verified and not have_pub:
                load = ButtonOption("Load Key")
                cont = ButtonOption("Continue")
                selected = self.run_screen(
                    WarningScreen,
                    title="Warning",
                    status_headline=None,
                    text="Missing public key to verify signature",
                    show_back_button=False,
                    button_data=[load, cont],
                )
                if selected == 0:
                    self.controller.gpg_pending_message = ciphertext
                    self.controller.resume_main_flow = self.controller.FLOW__GPG_MESSAGE
                    return Destination(ToolsGPGImportPubkeyMenuView)
            if verified:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"Valid Signature from\n{label}",
                    show_back_button=False,
                    button_data=[ButtonOption("Next")],
                )
            else:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Warning",
                    status_icon_name=SeedSignerIconConstants.WARNING,
                    status_color=GUIConstants.WARNING_COLOR,
                    status_headline=None,
                    text=f"Unverified Signature from\n{label}",
                    show_back_button=False,
                    button_data=[ButtonOption("Next")],
                )

        next_button = ButtonOption("Next")
        self.run_screen(
            ToolsTextQRReviewTextScreen,
            textToEncode=plaintext,
            title="Decrypted Message",
            button_data=[next_button],
            show_back_button=False,
        )

        SAVE = ButtonOption("Save to Seedkeeper")
        SHOW = ButtonOption("Show as QR")
        DONE = ButtonOption("Done")
        button_data = [SAVE, SHOW, DONE]
        selected_option = self.run_screen(
            ButtonListScreen,
            title="Decrypted Message",
            is_button_text_centered=False,
            button_data=button_data,
            show_back_button=False,
        )

        if selected_option == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_option] == SAVE:
            Satochip_Connector = seedkeeper_utils.init_satochip(
                self, init_card_filter=["seedkeeper"]
            )
            if not Satochip_Connector:
                return Destination(BackStackView)

            msg_bytes = plaintext.encode("utf-8")
            status = Satochip_Connector.card_get_status()[3]
            if status['protocol_minor_version'] == 1:
                if len(msg_bytes) > 255:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Message too large for Seedkeeper v1",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                secret_list = [len(msg_bytes)] + list(msg_bytes)
            else:
                secret_list = list(len(msg_bytes).to_bytes(2, "big")) + list(msg_bytes)

            label = f"GPGMsg:{dec_key['fpr'][-8:]}" if dec_key else "GPGMsg"
            header = Satochip_Connector.make_header(
                "Data", "Plaintext export allowed", label
            )
            secret_dic = {"header": header, "secret_list": secret_list}

            try:
                fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                    Satochip_Connector, secret_dic
                )
            except Exception as e:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=str(e),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            if not fits:
                self.run_screen(
                    WarningScreen,
                    title="Not Enough Space",
                    status_headline=None,
                    text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            try:
                loading = LoadingScreenThread(text="Saving Secret\n\n\n\n\n\n")
                loading.start()
                Satochip_Connector.seedkeeper_import_secret(secret_dic)
                loading.stop()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="Message saved to Seedkeeper",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
            except UnexpectedSW12Error as e:
                loading.stop()
                if e.sw1 == 0x6A and e.sw2 == 0x84:
                    err_text = "Not enough space on Seedkeeper for message"
                else:
                    err_text = format_sw_error(e.sw1, e.sw2)
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=err_text,
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
            except Exception:
                loading.stop()
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to save message",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
            return Destination(MainMenuView)

        if button_data[selected_option] == SHOW:
            encoder = GenericStaticQrEncoder(data=plaintext)
            self.run_screen(QRDisplayScreen, qr_encoder=encoder)
            return Destination(MainMenuView)

        return Destination(MainMenuView)


class ToolsGPGImportMenuView(View):
    PUBKEY = ButtonOption("Public Key")
    PRIVKEY = ButtonOption("Private Key")

    def run(self):
        button_data = [self.PUBKEY, self.PRIVKEY]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Import",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.PUBKEY:
            return Destination(ToolsGPGImportPubkeyMenuView)
        return Destination(ToolsGPGImportPrivkeyMenuView)


class ToolsGPGExportMenuView(View):
    PUBKEY = ButtonOption("Public Key")
    PRIVKEY = ButtonOption("Private Key")

    def run(self):
        button_data = [self.PUBKEY, self.PRIVKEY]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Export",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.PUBKEY:
            return Destination(ToolsGPGExportPubkeyView)
        return Destination(ToolsGPGExportPrivkeyView)


class ToolsGPGSmartMenuView(View):
    CARD_INFO = ButtonOption("View Card Info")
    GENERATE_ON_CARD = ButtonOption("Generate On-Card Key")
    CHANGE_ADMIN_PIN = ButtonOption("Change Admin PIN")
    CHANGE_USER_PIN = ButtonOption("Change User PIN")

    def run(self):
        button_data = [
            self.CARD_INFO,
            self.GENERATE_ON_CARD,
            self.CHANGE_ADMIN_PIN,
            self.CHANGE_USER_PIN,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="SmartGPG",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        selected = button_data[selected_menu_num]
        if selected == self.CARD_INFO:
            return Destination(ToolsGPGCardInfoView)
        elif selected == self.GENERATE_ON_CARD:
            return Destination(ToolsGPGGenerateKeyOnCardView)
        elif selected == self.CHANGE_ADMIN_PIN:
            return Destination(ToolsGPGChangeAdminPinView)
        elif selected == self.CHANGE_USER_PIN:
            return Destination(ToolsGPGChangeUserPinView)


class ToolsGPGCardInfoView(View):
    def run(self):
        from subprocess import run

        data = run(["gpg", "--card-status"], capture_output=True, text=True)
        text = data.stdout or data.stderr or "No card info"
        self.run_screen(
            LargeIconStatusScreen,
            title="Card Info",
            status_headline=None,
            text=text[:400],
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return Destination(BackStackView)


class ToolsGPGGenerateKeyOnCardView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        self.loading_screen = LoadingScreenThread(text="Generating key\n\n\n(May take a while)")
        self.loading_screen.start()
        run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--status-fd", "1", "--command-fd", "0", "--edit-card"],
            input="admin\ngenerate\ny\n",
            text=True,
        )
        self.loading_screen.stop()
        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Key generated on card",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return Destination(MainMenuView)


class ToolsGPGChangeAdminPinView(View):
    def run(self):
        from subprocess import run
        from seedsigner.helpers import seedkeeper_utils

        seedkeeper_utils.disconnect_smartcard_connections(self.controller)
        run(["gpgconf", "--reload", "scdaemon"])

        ret = self.run_screen(
            WarningScreen,
            title="Admin PIN Required",
            status_headline=None,
            text="Admin PIN is needed for changing keys and editing card settings.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        old_pin = seedkeeper_utils.prompt_for_pin(self, "Current Admin PIN")
        if old_pin is None:
            return Destination(BackStackView)
        new_pin = seedkeeper_utils.prompt_for_pin(self, "New Admin PIN")
        if new_pin is None:
            return Destination(BackStackView)
        cmds = f"3\n{old_pin}\n{new_pin}\n{new_pin}\nQ\n"
        result = run(
            [
                "gpg",
                "--pinentry-mode",
                "loopback",
                "--status-fd",
                "1",
                "--command-fd",
                "0",
                "--change-pin",
            ],
            input=cmds,
            capture_output=True,
            text=True,
        )
        output = (result.stdout or "") + (result.stderr or "")
        success = "PIN changed" in output or "SC_OP_SUCCESS" in result.stdout
        failed = "SC_OP_FAILURE" in result.stdout or not success
        if failed:
            self.run_screen(
                LargeIconStatusScreen,
                title="Failed",
                status_headline=None,
                text="Admin PIN change failed",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)
        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="PIN updated. Please remove and re-insert the card.",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return Destination(MainMenuView)


class ToolsGPGChangeUserPinView(View):
    def run(self):
        from subprocess import run
        from seedsigner.helpers import seedkeeper_utils

        seedkeeper_utils.disconnect_smartcard_connections(self.controller)

        ret = self.run_screen(
            WarningScreen,
            title="Insert Card",
            status_headline=None,
            text="Remove and re-insert the smartcard, then press Continue.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        run(["gpgconf", "--reload", "scdaemon"])

        ret = self.run_screen(
            WarningScreen,
            title="User PIN Required",
            status_headline=None,
            text="User PIN is needed for signing and using on-card keys.",
            show_back_button=True,
            button_data=[ButtonOption("Continue")],
        )
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        old_pin = seedkeeper_utils.prompt_for_pin(self, "Current User PIN")
        if old_pin is None:
            return Destination(BackStackView)
        new_pin = seedkeeper_utils.prompt_for_pin(self, "New User PIN")
        if new_pin is None:
            return Destination(BackStackView)
        cmds = f"1\n{old_pin}\n{new_pin}\n{new_pin}\nQ\n"
        result = run(
            [
                "gpg",
                "--pinentry-mode",
                "loopback",
                "--status-fd",
                "1",
                "--command-fd",
                "0",
                "--change-pin",
            ],
            input=cmds,
            capture_output=True,
            text=True,
        )
        output = (result.stdout or "") + (result.stderr or "")
        success = "PIN changed" in output or "SC_OP_SUCCESS" in result.stdout
        failed = "SC_OP_FAILURE" in result.stdout or not success
        if failed:
            self.run_screen(
                LargeIconStatusScreen,
                title="Failed",
                status_headline=None,
                text="User PIN change failed",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)
        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="PIN updated. Please remove and re-insert the card.",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )
        return Destination(MainMenuView)


class ToolsGPGEncryptFileView(View):
    def run(self):
        from subprocess import run
        import os
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            WarningScreen,
            LargeIconStatusScreen,
            LoadingScreenThread,
        )
        from seedsigner.gui.screens.tools_screens import ToolsTextQRTextEntryScreen

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)
        file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
            )
        ]
        buttons = [ButtonOption(file) for file in file_list]
        if not buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected_file = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected_file == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        filename = file_list[selected_file]
        filepath = os.path.join(file_list_path, filename)
        try:
            # Sanity-check that the file is readable before invoking gpg
            with open(filepath, "rb"):
                pass
        except Exception as e:
            logger.exception("Failed to load file %s", filepath)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=f"Failed to load file:\n{e}",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        result = run([
            "gpg",
            "--list-keys",
            "--with-colons",
        ], capture_output=True, text=True)
        keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "pub":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]
        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No public keys found",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)
        key_buttons = [ButtonOption(k["uid"] if k["uid"] else k["fpr"][-8:]) for k in keys]
        selected_key = self.run_screen(
            ButtonListScreen,
            title="Select Recipient",
            is_button_text_centered=False,
            button_data=key_buttons,
        )
        if selected_key == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        rec_key = keys[selected_key]

        result = run([
            "gpg",
            "--list-secret-keys",
            "--with-colons",
        ], capture_output=True, text=True)
        skeys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                skeys.append(cur)
            elif parts[0] == "fpr" and cur is not None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]
        SKIP = ButtonOption("Skip")
        sign_buttons = [SKIP]
        for k in skeys:
            label = k["uid"] if k["uid"] else k["fpr"][-8:]
            sign_buttons.append(ButtonOption(label))
        selected_sign = self.run_screen(
            ButtonListScreen,
            title="Sign with",
            is_button_text_centered=False,
            button_data=sign_buttons,
        )
        if selected_sign == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        sign_key = None
        if sign_buttons[selected_sign] is not SKIP:
            sign_key = skeys[selected_sign - 1]

        outname = f"{filename}.gpg"

        def gpg_encrypt(passphrase: str | None = None):
            self.loading_screen = LoadingScreenThread(
                text=_("Encrypting File") + "\n\n\n\n\n\n" + _("(May take a while)")
            )
            self.loading_screen.start()
            cmd = [
                "gpg",
                "--batch",
                "--yes",
                "--trust-model",
                "always",
                "--output",
                outname,
                "--armor",
            ]
            if passphrase is not None:
                cmd.extend(["--pinentry-mode", "loopback", "--passphrase", passphrase])
            if sign_key is not None:
                cmd.extend(["--local-user", sign_key["fpr"], "--sign"])
            cmd.extend(["--recipient", rec_key["fpr"], "--encrypt", filename])
            result = run(cmd, capture_output=True, text=True, cwd=file_list_path)
            self.loading_screen.stop()
            return result

        result = gpg_encrypt()
        if result.returncode != 0 and sign_key is not None:
            # Likely needs a passphrase for the signing key
            ret_dict = ToolsTextQRTextEntryScreen(textToEncode="", title="Passphrase").display()
            if "is_back_button" in ret_dict:
                return Destination(BackStackView)
            passphrase = ret_dict["textToEncode"]
            result = gpg_encrypt(passphrase)

        if result.returncode != 0:
            logger.warning("gpg encrypt failed: %s", result.stderr)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to encrypt file",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text=f"Saved as {outname}",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(MainMenuView)


class ToolsGPGDecryptFileView(View):
    def run(self):
        from subprocess import run
        import os
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            WarningScreen,
            LargeIconStatusScreen,
            LoadingScreenThread,
        )
        from seedsigner.gui.screens.tools_screens import ToolsTextQRTextEntryScreen

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)
        file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
            )
        ]
        buttons = [ButtonOption(file) for file in file_list]
        if not buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)
        selected_file = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected_file == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        filename = file_list[selected_file]
        filepath = os.path.join(file_list_path, filename)
        try:
            with open(filepath, "rb"):
                pass
        except Exception as e:
            logger.exception("Failed to load file %s", filepath)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=f"Failed to load file:\n{e}",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        outname = f"{filename}.dec"

        def gpg_decrypt(passphrase: str | None = None):
            self.loading_screen = LoadingScreenThread(
                text=_("Decrypting File") + "\n\n\n\n\n\n" + _("(May take a while)")
            )
            self.loading_screen.start()
            cmd = [
                "gpg",
                "--batch",
                "--yes",
                "--output",
                outname,
                "--decrypt",
                "--status-fd",
                "1",
            ]
            if passphrase is not None:
                cmd.extend(["--pinentry-mode", "loopback", "--passphrase", passphrase])
            cmd.append(filename)
            result = run(cmd, capture_output=True, text=True, cwd=file_list_path)
            self.loading_screen.stop()
            return result

        def parse_status(output: str):
            need_passphrase = False
            missing_priv = False
            signer_fpr = None
            verified = False
            missing_pub = False
            for line in output.splitlines():
                if not line.startswith("[GNUPG:]"):
                    continue
                parts = line[9:].split()
                tag = parts[0]
                if tag in {"NEED_PASSPHRASE", "MISSING_PASSPHRASE", "BAD_PASSPHRASE"}:
                    need_passphrase = True
                elif tag == "NO_SECKEY":
                    missing_priv = True
                elif tag == "NO_PUBKEY":
                    missing_pub = True
                    if len(parts) > 1:
                        signer_fpr = parts[1]
                elif tag == "BADSIG":
                    signer_fpr = parts[1]
                    verified = False
                elif tag == "VALIDSIG":
                    signer_fpr = parts[1]
                    verified = True
            return need_passphrase, missing_priv, signer_fpr, verified, missing_pub

        result = gpg_decrypt()
        need_pw, missing_priv, signer_fpr, verified, missing_pub = parse_status(result.stdout)

        if result.returncode != 0 and need_pw:
            ret_dict = ToolsTextQRTextEntryScreen(textToEncode="", title="Passphrase").display()
            if "is_back_button" in ret_dict:
                return Destination(BackStackView)
            passphrase = ret_dict["textToEncode"]
            result = gpg_decrypt(passphrase)
            need_pw, missing_priv, signer_fpr, verified, missing_pub = parse_status(result.stdout)

        if result.returncode != 0:
            if missing_priv:
                load = ButtonOption("Load Key")
                cont = ButtonOption("Continue")
                selected = self.run_screen(
                    WarningScreen,
                    title="Warning",
                    status_headline=None,
                    text="Missing private key to decrypt",
                    show_back_button=False,
                    button_data=[load, cont],
                )
                if selected == 0:
                    return Destination(ToolsGPGImportPrivkeyMenuView)
            logger.warning("gpg decrypt failed: %s", result.stderr)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to decrypt file",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        if signer_fpr:
            pub_result = run([
                "gpg",
                "--list-keys",
                "--with-colons",
            ], capture_output=True, text=True)
            pubkeys = []
            cur = None
            for line in pub_result.stdout.splitlines():
                parts = line.split(":")
                if parts[0] == "pub":
                    cur = {"fpr": None, "uid": None}
                    pubkeys.append(cur)
                elif parts[0] == "fpr" and cur is not None:
                    cur["fpr"] = parts[9]
                elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                    cur["uid"] = parts[9]
            label = signer_fpr[-8:]
            have_pub = False
            for pk in pubkeys:
                if pk["fpr"] == signer_fpr:
                    have_pub = True
                    label = pk["uid"] if pk["uid"] else pk["fpr"][-8:]
                    break
            if (not verified or missing_pub) and not have_pub:
                load = ButtonOption("Load Key")
                cont = ButtonOption("Continue")
                selected = self.run_screen(
                    WarningScreen,
                    title="Warning",
                    status_headline=None,
                    text="Missing public key to verify signature",
                    show_back_button=False,
                    button_data=[load, cont],
                )
                if selected == 0:
                    return Destination(ToolsGPGImportPubkeyMenuView)
            if verified:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text=f"Valid Signature from\n{label}",
                    show_back_button=False,
                    button_data=[ButtonOption("Next")],
                )
            else:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Warning",
                    status_icon_name=SeedSignerIconConstants.WARNING,
                    status_color=GUIConstants.WARNING_COLOR,
                    status_headline=None,
                    text=f"Unverified Signature from\n{label}",
                    show_back_button=False,
                    button_data=[ButtonOption("Next")],
                )

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text=f"Saved as {outname}",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )
        return Destination(MainMenuView)


class ToolsGPGVerifyFileView(View):
    CHECK_SHA256 = ButtonOption("Check SHA256Sum")
    def run(self):
        from subprocess import run
        import hashlib, shutil
        from pathlib import Path
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")]
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        if not self.controller.gpg_keys_imported:
            gpg_dir = Path(__file__).resolve().parent.parent.parent.parent / "gpg_keys"
            self.loading_screen = LoadingScreenThread(text="Importing GPG Keys\n\n\n\n\n\n(May take a while)")
            self.loading_screen.start()
            key_files = [str(p) for p in gpg_dir.glob("*.asc")]
            if key_files:
                run(["gpg", "--import", *key_files])
            self.loading_screen.stop()
            self.controller.gpg_keys_imported = True

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)

        # Get only the visible, valid files
        visible_file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                    not f.startswith('.') and  # Ignore hidden files (like .DS_Store)
                    f != '__MACOSX' and  # Ignore specific macOS metadata folder
                    os.path.isfile(os.path.join(file_list_path, f))  # Only include actual files
            )
        ]

        # Build button options
        verify_file_buttons = [ButtonOption(f) for f in visible_file_list]

        if not verify_file_buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        # Show selection screen
        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=verify_file_buttons
        )

        # Handle cancel
        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        # Use the same filtered list to get the selected filename
        verify_file_name = visible_file_list[selected_file_num]
        logger.info("Selected: %s", verify_file_name)
        filechecked = verify_file_name[:-4] if verify_file_name.endswith(".sig") else verify_file_name

        self.loading_screen = LoadingScreenThread(
            text="Checking Signature\n\n\n\n\n\n(May take a while)"
        )
        self.loading_screen.start()

        cmd = ["gpg", "--verify"]
        if verify_file_name.endswith(".sig"):
            cmd.append(verify_file_name)
            if (file_list_path / filechecked).exists():
                cmd.append(filechecked)
        else:
            sig_candidate = verify_file_name + ".sig"
            if (file_list_path / sig_candidate).exists():
                cmd.extend([sig_candidate, verify_file_name])
            else:
                cmd.append(verify_file_name)

        try:
            data = run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(file_list_path),
            )
        except FileNotFoundError as exc:
            self.loading_screen.stop()
            logger.warning("gpg verify failed: %s", exc)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="GPG not found",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        self.loading_screen.stop()

        result = data.stderr.split("\n")

        valid_sig = False
        failed_reason = "Check Failed"
        valid_sig_keyid = ""
        for line in result:
            if "gpg: assuming signed data in " in line:
                filechecked = line[30:-1]
            elif "Primary key fingerprint:" in line:
                valid_sig_keyid += "\n" + line[-20:]
            elif "Good signature from" in line:
                valid_sig = True
            elif "gpg: no signature found" in line:
                failed_reason = "No GPG signature found in file"
            elif "BAD signature from" in line:
                valid_sig = False
                failed_reason = "Invalid Signature\nfor file..."
                break
            elif "can't hash datafile: No data" in line:
                valid_sig = False
                failed_reason = "Can't find\ncorresponding file for\nthis signature..."

        if valid_sig:
            button_data = []
            # There are a bunch of different naming conventions that different projects use...
            manifest_filenames = ["manifest", # Sparrow uses this
                                  "sha256", # Seedsigner uses this
                                  "shasums"] # Liana uses this naming convention
            if any(manifest_filename in verify_file_name for manifest_filename in manifest_filenames):
                button_data.append(self.CHECK_SHA256)

            button_data.append(ButtonOption("Done"))

            ret = self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="Valid Signature(s) from" + valid_sig_keyid,
                    show_back_button=False,
                    button_data=button_data
                )
            
            if button_data[ret] == self.CHECK_SHA256:
                verified_files = []
                failed_files = []
                missing_files = []

                if shutil.which("sha256sum"):
                    from seedsigner.models.settings import Settings

                    if Settings.HOSTNAME == Settings.SEEDSIGNER_OS:
                        sha256_cmd = ["sha256sum", "-c", filechecked]
                    else:
                        sha256_cmd = ["sha256sum", "--check", filechecked, "--ignore-missing"]

                    self.loading_screen = LoadingScreenThread(
                        text="Checking SHA256\n\n\n\n\n\n(This takes a while)"
                    )
                    self.loading_screen.start()

                    data = run(
                        sha256_cmd,
                        capture_output=True,
                        text=True,
                        cwd=file_list_path,
                    )

                    self.loading_screen.stop()

                    result_stdout = data.stdout.split("\n")
                    result_stderr = data.stderr.split("\n")
                    for line in result_stdout:
                        if ": OK" in line:
                            verified_files.append(line[:-4])
                        elif ": FAILED" in line:
                            failed_files.append(line[:-8])

                    for line in result_stderr:
                        if "No such file or directory" in line:
                            missing_files.append(line[23:-28])
                else:
                    self.loading_screen = LoadingScreenThread(text="Checking SHA256\n\n\n\n\n\n(This takes a while)")
                    self.loading_screen.start()
                    manifest_path = file_list_path / filechecked
                    with open(manifest_path, "r") as mf:
                        for line in mf:
                            line = line.strip()
                            if not line:
                                continue
                            parts = line.split()
                            if len(parts) < 2:
                                continue
                            checksum, name = parts[0], parts[-1].lstrip("*")
                            file_path = file_list_path / name
                            if file_path.exists():
                                h = hashlib.sha256()
                                with open(file_path, "rb") as f:
                                    for chunk in iter(lambda: f.read(65536), b""):
                                        h.update(chunk)
                                if h.hexdigest().lower() == checksum.lower():
                                    verified_files.append(name)
                                else:
                                    failed_files.append(name)
                            else:
                                missing_files.append(name)
                    self.loading_screen.stop()

                for file in missing_files:
                    try:
                        failed_files.remove(file)
                    except ValueError:
                        pass

                if len(failed_files) > 0:
                    failed_files_string = "\n".join(str(x) for x in failed_files)
                    self.run_screen(
                        WarningScreen,
                        title="WARNING",
                        status_headline=None,
                        text="Incorrect SHA256 for " + failed_files_string,
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")]
                    )
                elif len(verified_files) > 0:
                    verified_files_string = "\n".join(str(x) for x in verified_files)
                    self.run_screen(
                        LargeIconStatusScreen,
                        title="Success",
                        status_headline=None,
                        text="Matched SHA256 for " + verified_files_string,
                        show_back_button=False,
                        button_data=[ButtonOption("Done")]
                    )
                else:
                    self.run_screen(
                        WarningScreen,
                        title="WARNING",
                        status_headline=None,
                        text="No files from this checksum list found...",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")]
                    )
        else:

            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text=failed_reason,
                show_back_button=True,
            )


        return Destination(MainMenuView)


class ToolsGPGSignFileView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)

        file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
            )
        ]

        buttons = [ButtonOption(file) for file in file_list]

        if not buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        filename = file_list[selected_file_num]

        # Gather available private keys for signing
        result = run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = parse_secret_key_list(result.stdout)

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        key_buttons = []
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            key_buttons.append(ButtonOption(label))

        selected_key = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=key_buttons,
        )

        if selected_key == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        key = keys[selected_key]

        self.loading_screen = LoadingScreenThread(text="Signing File\n\n\n\n\n\n(May take a while)")
        self.loading_screen.start()
        result = run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--local-user",
                key["fpr"],
                "--output",
                f"{filename}.sig",
                "--armor",
                "--detach-sign",
                filename,
            ],
            cwd=file_list_path,
            capture_output=True,
            text=True,
        )
        self.loading_screen.stop()

        if result.returncode != 0:
            logger.warning("gpg sign failed: %s", result.stderr)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to sign file",
                show_back_button=False,
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text=f"Signature saved as {filename}.sig",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )

        return Destination(MainMenuView)


class ToolsGPGSignManifestView(View):
    def run(self):
        from subprocess import run
        import hashlib, shutil
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)

        manifest_name = "sha256.txt"

        file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
                and not f.endswith('.sig')
                and f != manifest_name
            )
        ]

        file_list.sort()

        if not file_list:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(text="Generating Manifest\n\n\n\n\n\n(May take a while)")
        self.loading_screen.start()

        if shutil.which("sha256sum"):
            result = run(
                ["sha256sum", *file_list],
                cwd=file_list_path,
                capture_output=True,
                text=True,
            )
            manifest_content = result.stdout
        else:
            lines = []
            for fname in file_list:
                h = hashlib.sha256()
                with open(file_list_path / fname, "rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
                lines.append(f"{h.hexdigest()}  {fname}")
            manifest_content = "\n".join(lines) + "\n"

        (file_list_path / manifest_name).write_text(manifest_content)
        self.loading_screen.stop()

        key_result = run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = []
        cur = None
        for line in key_result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        key_buttons = []
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            key_buttons.append(ButtonOption(label))

        selected_key = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=key_buttons,
        )

        if selected_key == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        key = keys[selected_key]

        self.loading_screen = LoadingScreenThread(text="Signing File\n\n\n\n\n\n(May take a while)")
        self.loading_screen.start()
        result = run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--local-user",
                key["fpr"],
                "--output",
                f"{manifest_name}.sig",
                "--armor",
                "--detach-sign",
                manifest_name,
            ],
            cwd=file_list_path,
            capture_output=True,
            text=True,
        )
        self.loading_screen.stop()

        if result.returncode != 0:
            logger.warning("gpg sign failed: %s", result.stderr)
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to sign manifest",
                show_back_button=False,
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text=f"Manifest saved as {manifest_name} and {manifest_name}.sig",
            show_back_button=False,
            button_data=[ButtonOption("Done")],
        )

        return Destination(MainMenuView)


def _check_future_key_creation(view, key_blob: str) -> None:
    """Warn if the key's creation date is in the future and offer to set system time."""
    from subprocess import run
    from pgpy import PGPKey

    try:
        key, _ = PGPKey.from_blob(key_blob)
    except Exception:
        return

    import time

    if key.created and key.created.timestamp() > time.time():
        formatted = key.created.strftime("%Y-%m-%d %H:%M:%S")
        ret = view.run_screen(
            WarningScreen,
            title="Future Date",
            status_headline=None,
            text=f"Key date {formatted} is in the future.\nUpdate system time?",
            show_back_button=False,
            button_data=[ButtonOption("Update"), ButtonOption("Skip")],
        )
        if ret == 0:
            run(["date", "-s", formatted], capture_output=True)
            # Reset activity-based timers since system time changed
            view.controller.reset_screensaver_timeout()

class ToolsGPGImportPubkeyMenuView(View):
    LOAD_QR = ButtonOption("From QR")
    LOAD_FILE = ButtonOption("From File")
    LOAD_SEEDKEEPER = ButtonOption("From Seedkeeper")

    def run(self):
        button_data = [self.LOAD_QR, self.LOAD_FILE, self.LOAD_SEEDKEEPER]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Import GPG Pubkey",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.LOAD_QR:
            return Destination(ToolsGPGLoadPubkeyQRView)
        if button_data[selected_menu_num] == self.LOAD_FILE:
            return Destination(ToolsGPGImportPubkeyFileView)
        if button_data[selected_menu_num] == self.LOAD_SEEDKEEPER:
            return Destination(ToolsGPGImportPubkeySeedkeeperView)


class ToolsGPGLoadPubkeyQRView(View):
    def run(self):
        from subprocess import run
        from urtypes.bytes import Bytes
        from seedsigner.gui.screens.screen import WarningScreen, LargeIconStatusScreen
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.decode_qr import DecodeQR, QRType
        import time

        decoder = DecodeQR()
        ScanScreen(decoder=decoder, instructions_text="Scan public key").display()
        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)
        if not decoder.is_complete:
            return Destination(BackStackView)

        if decoder.qr_type == QRType.BYTES__UR:
            raw = Bytes.from_cbor(decoder.decoder.result_message().cbor).data
            if isinstance(raw, memoryview):
                raw = raw.tobytes()
            if isinstance(raw, (bytes, bytearray)):
                key_blob = raw.decode("utf-8")
            else:
                key_blob = raw
        elif decoder.qr_type == QRType.TEXT:
            key_blob = decoder.get_text()
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Unsupported QR format",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        _check_future_key_creation(self, key_blob)

        imported = run(["gpg", "--import"], input=key_blob, capture_output=True, text=True)
        if imported.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Pubkey imported",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)


class ToolsGPGImportPubkeyFileView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")]
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)

        verify_file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
            )
        ]

        verify_file_buttons = [ButtonOption(file) for file in verify_file_list]

        if not verify_file_buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=verify_file_buttons
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        verify_file_name = verify_file_list[selected_file_num]
        logger.info("Selected: %s", verify_file_name)
        filepath = os.path.join(file_list_path, verify_file_name)
        with open(filepath, "r") as f:
            key_blob = f.read()

        _check_future_key_creation(self, key_blob)

        data = run(["gpg", "--import", filepath], capture_output=True, text=True)

        result = data.stderr.split("\n")
        certs_not_changed = 0
        certs_imported = 0
        certs_processed = 0
        for line in result:
            if "not changed" in line:
                certs_not_changed += 1
                certs_processed += 1
            elif " imported" in line:
                certs_imported += 1
                certs_processed += 1

        self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Imported:" + str(certs_imported) + "\nNot Changed:" + str(certs_not_changed),
                show_back_button=False,
                button_data=[ButtonOption("Continue")]
            )

        return Destination(ToolsGPGMenuView)


class ToolsGPGImportPubkeySeedkeeperView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        Satochip_Connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["seedkeeper"]
        )
        if not Satochip_Connector:
            return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(text="Listing Keys\n\n\n\n\n\n")
        self.loading_screen.start()
        headers = Satochip_Connector.seedkeeper_list_secret_headers()
        self.loading_screen.stop()

        status = Satochip_Connector.card_get_status()[3]

        secret_ids = []
        buttons = []
        for header in headers:
            stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))
            label = header.get('label', '')
            if stype == "Data" and label.startswith("GPGPub:"):
                display_label = label[len("GPGPub:") :]
                secret_ids.append(header['id'])
                buttons.append(ButtonOption(display_label))

        if not buttons:
            self.run_screen(
                WarningScreen,
                title="No Keys",
                status_headline=None,
                text="No GPG public keys on Seedkeeper",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        sid = secret_ids[selected]

        self.loading_screen = LoadingScreenThread(text="Loading Key\n\n\n\n\n\n")
        self.loading_screen.start()
        secret_dict = Satochip_Connector.seedkeeper_export_secret(sid, None)
        self.loading_screen.stop()

        raw = secret_dict['secret_list']
        if status['protocol_minor_version'] == 1:
            length = raw[0]
            key_bytes = bytes(raw[1:1 + length])
        else:
            length = (raw[0] << 8) + raw[1]
            key_bytes = bytes(raw[2:2 + length])
        pubkey = key_bytes.decode("utf-8")

        _check_future_key_creation(self, pubkey)

        imported = run(
            ["gpg", "--import"],
            input=pubkey,
            capture_output=True,
            text=True,
        )
        if imported.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Pubkey imported",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)


class ToolsGPGImportPrivkeyMenuView(View):
    GENERATE_NEW = ButtonOption("Generate New")
    LOAD_BIP85_KEY = ButtonOption("Derive BIP85")
    LOAD_QR = ButtonOption("From QR")
    LOAD_FILE = ButtonOption("From File")
    LOAD_SEEDKEEPER = ButtonOption("From Seedkeeper")

    def run(self):
        button_data = [
            self.GENERATE_NEW,
            self.LOAD_BIP85_KEY,
            self.LOAD_QR,
            self.LOAD_FILE,
            self.LOAD_SEEDKEEPER,
        ]

        selected_menu_num = self.run_screen(
            ButtonListScreen,
            title="Import GPG Privkey",
            is_button_text_centered=False,
            button_data=button_data,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == self.GENERATE_NEW:
            return Destination(ToolsGPGGenerateKeyView)
        if button_data[selected_menu_num] == self.LOAD_BIP85_KEY:
            return Destination(ToolsGPGLoadBIP85KeyView)
        if button_data[selected_menu_num] == self.LOAD_QR:
            return Destination(ToolsGPGLoadPrivkeyQRView)
        if button_data[selected_menu_num] == self.LOAD_FILE:
            return Destination(ToolsGPGLoadPrivkeyFileView)
        if button_data[selected_menu_num] == self.LOAD_SEEDKEEPER:
            return Destination(ToolsGPGLoadPrivkeySeedkeeperView)


class ToolsGPGLoadPrivkeyQRView(View):
    def run(self):
        from subprocess import run
        from urtypes.bytes import Bytes
        from seedsigner.gui.screens.screen import WarningScreen, LargeIconStatusScreen
        from seedsigner.gui.screens.scan_screens import ScanScreen
        from seedsigner.models.decode_qr import DecodeQR, QRType
        import time

        decoder = DecodeQR()
        ScanScreen(decoder=decoder, instructions_text="Scan private key").display()
        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)
        if not decoder.is_complete:
            return Destination(BackStackView)

        if decoder.qr_type == QRType.BYTES__UR:
            raw = Bytes.from_cbor(decoder.decoder.result_message().cbor).data
            if isinstance(raw, memoryview):
                raw = raw.tobytes()
            if isinstance(raw, (bytes, bytearray)):
                key_blob = raw.decode("utf-8")
            else:
                key_blob = raw
        elif decoder.qr_type == QRType.TEXT:
            key_blob = decoder.get_text()
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Unsupported QR format",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        _check_future_key_creation(self, key_blob)

        imported = run(["gpg", "--import"], input=key_blob, capture_output=True, text=True)
        if imported.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Privkey imported",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)


class ToolsGPGLoadPrivkeyFileView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens import tools_screens

        if len(self.controller.storage.seeds) > 0:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="These tools load data from the microSD card and may expose loaded secrets.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
        os.makedirs(file_list_path, exist_ok=True)

        file_list = [
            f
            for f in os.listdir(file_list_path)
            if (
                not f.startswith('.')
                and f != '__MACOSX'
                and os.path.isfile(os.path.join(file_list_path, f))
            )
        ]

        buttons = [ButtonOption(file) for file in file_list]

        if not buttons:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No files found in microsd-images.",
                show_back_button=False,
                button_data=[ButtonOption("OK")],
            )
            return Destination(BackStackView)

        selected_file_num = self.run_screen(
            ButtonListScreen,
            title="Select File",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected_file_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        filename = file_list[selected_file_num]
        filepath = os.path.join(file_list_path, filename)

        ret_dict = tools_screens.ToolsTextQRTextEntryScreen(
            textToEncode="", title="Passphrase"
        ).display()
        if "is_back_button" in ret_dict:
            return Destination(BackStackView)

        try:
            import re

            passphrase = bytes(
                re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                encoding="raw_unicode_escape",
            ).decode("unicode_escape")
        except UnicodeError:
            passphrase = ret_dict["textToEncode"]

        decrypted = run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                passphrase,
                "--decrypt",
                filepath,
            ],
            capture_output=True,
            text=True,
        )
        if decrypted.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to decrypt key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        _check_future_key_creation(self, decrypted.stdout)

        imported = run(
            ["gpg", "--import"],
            input=decrypted.stdout,
            capture_output=True,
            text=True,
        )
        if imported.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Privkey imported",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)


class ToolsGPGLoadPrivkeySeedkeeperView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread

        Satochip_Connector = seedkeeper_utils.init_satochip(
            self, init_card_filter=["seedkeeper"]
        )
        if not Satochip_Connector:
            return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(text="Listing Keys\n\n\n\n\n\n")
        self.loading_screen.start()
        headers = Satochip_Connector.seedkeeper_list_secret_headers()
        self.loading_screen.stop()

        status = Satochip_Connector.card_get_status()[3]

        secret_ids = []
        buttons = []
        for header in headers:
            stype = SEEDKEEPER_DIC_TYPE.get(header['type'], hex(header['type']))
            label = header.get('label', '')
            if stype == "Data" and label.startswith("GPGPriv:"):
                display_label = label[len("GPGPriv:") :]
                secret_ids.append(header['id'])
                buttons.append(ButtonOption(display_label))

        if not buttons:
            self.run_screen(
                WarningScreen,
                title="No Keys",
                status_headline=None,
                text="No GPG private keys on Seedkeeper",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )
        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        sid = secret_ids[selected]

        self.loading_screen = LoadingScreenThread(text="Loading Key\n\n\n\n\n\n")
        self.loading_screen.start()
        secret_dict = Satochip_Connector.seedkeeper_export_secret(sid, None)
        self.loading_screen.stop()

        raw = secret_dict['secret_list']
        if status['protocol_minor_version'] == 1:
            length = raw[0]
            key_bytes = bytes(raw[1:1 + length])
        else:
            length = (raw[0] << 8) + raw[1]
            key_bytes = bytes(raw[2:2 + length])
        privkey = key_bytes.decode("utf-8")

        _check_future_key_creation(self, privkey)

        imported = run(
            ["gpg", "--import"],
            input=privkey,
            capture_output=True,
            text=True,
        )
        if imported.returncode != 0:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Privkey imported",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)


def bip85_rsa_from_root(root, bits: int, index: int, sub_index: int | None = None):
    """Generate a deterministic RSA key from BIP85 entropy.

    Uses PyCryptodome's ``RSA.generate(bits, randfunc=drng.read)`` as the
    reference algorithm, matching the BIP85 spec example
    ``RSA.generate_key(4096, drng_reader.read)``.  Alternative RSA
    implementations MUST consume the DRNG byte-stream identically to
    PyCryptodome to ensure cross-implementation determinism.
    """
    from embit import bip85
    from Cryptodome.PublicKey import RSA
    from seedsigner.helpers.bip85_drng import BIP85DRNG

    # Enforce a minimum RSA key size to avoid weak keys.
    if bits < MIN_RSA_KEY_BITS:
        bits = MIN_RSA_KEY_BITS

    path = [BIP85_GPG_KEY_TYPE_RSA, bits, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP, path)
    drng = BIP85DRNG.new(entropy)
    return RSA.generate(bits, randfunc=drng.read)


def bip85_ed25519_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "EdDSA"
):
    from embit import bip85
    from seedsigner.helpers.ec_point import ed25519_pub_from_seed, curve25519_pub_from_seed
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_KEY_TYPE_CURVE25519, 256, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP, path)
    d_bytes = entropy[:32]
    if alg == "EdDSA":
        priv = fields.EdDSAPriv()
        priv.oid = EllipticCurveOID.Ed25519
        pub_bytes = ed25519_pub_from_seed(d_bytes)
        priv.p = fields.ECPoint.from_values(
            priv.oid.key_size,
            fields.ECPointFormat.Native,
            pub_bytes,
        )
        priv.s = fields.MPI(int.from_bytes(d_bytes, "big"))
    else:
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.Curve25519
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
        pub_bytes = curve25519_pub_from_seed(d_bytes)
        priv.p = fields.ECPoint.from_values(
            priv.oid.key_size,
            fields.ECPointFormat.Native,
            pub_bytes,
        )
        # Clamp the Cv25519 scalar per RFC 7748 §5: clear the three low
        # bits of LE byte 0, clear bit 255, set bit 254.  Without
        # clamping gpg-agent rejects the key on export ("Bad secret
        # key").  Clamping is idempotent and doesn't change the derived
        # public key (from_private_bytes clamps internally).
        # The MPI must use little-endian conversion (matching pgpy's
        # native Cv25519 convention), NOT big-endian.
        d_clamped = bytearray(d_bytes)
        d_clamped[0] &= 248      # LE byte 0: clear bits 0-2
        d_clamped[31] &= 127     # LE byte 31: clear bit 255
        d_clamped[31] |= 64      # LE byte 31: set bit 254
        priv.s = fields.MPI(int.from_bytes(d_clamped, "little"))
    priv._compute_chksum()
    return priv


def gpg_quick_addkey(fingerprint: str, alg: str, usage: str):
    cmd = [
        "gpg",
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--quick-addkey",
        fingerprint,
        alg,
        usage,
    ]
    return subprocess.run(cmd)


def gpg_edit_subkey(fingerprint: str, idx: int, action: str):
    cmd = [
        "gpg",
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--command-fd",
        "0",
        "--status-fd",
        "2",
        "--edit-key",
        fingerprint,
    ]
    if action == "revkey":
        # Confirm revocation, supply a default reason code of 0 (no reason),
        # send an empty description, confirm the summary, then save.
        script = f"key {idx}\nrevkey\ny\n0\n\ny\nsave\n"
    else:
        script = f"key {idx}\n{action}\ny\nsave\n"
    return subprocess.run(cmd, input=script, text=True)


def gpg_edit_uid(fingerprint: str, idx: int, action: str):
    cmd = [
        "gpg",
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--command-fd",
        "0",
        "--status-fd",
        "2",
        "--edit-key",
        fingerprint,
    ]
    script = f"uid {idx}\n{action}\ny\nsave\n"
    return subprocess.run(cmd, input=script, text=True)


def gpg_export_selected_subkeys(fingerprint: str, sub_fprs: list[str]):
    """Export selected secret subkeys with a stubbed primary key.

    ``gpg --export-secret-subkeys`` strips the primary secret key material while
    including the full secret data for the requested subkeys.  Older GPG
    releases may not support the ``keep-subkey`` filter, but individual subkeys
    can still be targeted by appending ``!`` to each desired key ID.  This
    helper builds that command and returns the completed process.
    """

    keyids = [f[-16:] + "!" for f in sub_fprs]
    cmd = [
        "gpg",
        "--armor",
        "--export-options=export-minimal",
        "--export-secret-subkeys",
        fingerprint,
        *keyids,
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def _normalize_bip85_alg(alg: str) -> str:
    """Map user-facing algorithm identifiers to canonical values."""

    if not alg:
        return alg
    alias = {
        "p256": "nistp256",
        "p384": "nistp384",
        "p521": "nistp521",
    }
    alg_lower = alg.lower()
    return alias.get(alg_lower, alg_lower)


def _bip85_subkey_specs(alg):
    from pgpy.constants import PubKeyAlgorithm, KeyFlags

    alg = _normalize_bip85_alg(alg)
    if alg == "ed25519":
        return [
            (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
            (1, PubKeyAlgorithm.EdDSA, {KeyFlags.Authentication, KeyFlags.Sign}, "EdDSA"),
            (2, PubKeyAlgorithm.EdDSA, {KeyFlags.Sign}, "EdDSA"),
        ]
    if alg in ["secp256k1", "nistp256", "nistp384", "nistp521", "brainpoolp256r1", "brainpoolp384r1", "brainpoolp512r1"]:
        return [
            (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
            (1, PubKeyAlgorithm.ECDSA, {KeyFlags.Authentication, KeyFlags.Sign}, "ECDSA"),
            (2, PubKeyAlgorithm.ECDSA, {KeyFlags.Sign}, "ECDSA"),
        ]
    return [
        (0, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}),
        (1, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Authentication, KeyFlags.Sign}),
        (2, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Sign}),
    ]


def bip85_verify_existing(
    seed,
    fingerprint: str,
    key_index: int,
    created_ts: int,
    primary_algo: str,
    primary_bits: str,
    primary_curve: str,
    subkeys,
) -> bool:
    from embit import bip32
    from pgpy import PGPKey
    from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
    from pgpy.constants import PubKeyAlgorithm
    from pgpy.packet import fields
    from pgpy.packet.types import MPI
    from Cryptodome.PublicKey import RSA
    from datetime import datetime, timezone

    logger.info(
        "bip85_verify_existing: fpr(last8)=%s index=%s",
        "redacted" if fingerprint else "None",
        key_index,
    )
    if hasattr(seed, "get_root"):
        root = seed.get_root()
    else:
        root = bip32.HDKey.from_seed(seed.seed_bytes)
    created = datetime.fromtimestamp(created_ts, tz=timezone.utc)
    primary_curve = _normalize_bip85_alg(primary_curve)

    def rsa_to_privpacket(rsa_key: RSA.RsaKey) -> fields.RSAPriv:
        priv = fields.RSAPriv()
        priv.n = MPI(rsa_key.n)
        priv.e = MPI(rsa_key.e)
        priv.d = MPI(rsa_key.d)
        priv.p = MPI(rsa_key.p)
        priv.q = MPI(rsa_key.q)
        priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
        priv._compute_chksum()
        return priv

    pk = PrivKeyV4()
    if primary_algo in ("1", "2", "3"):
        pk.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
        try:
            bits = int(primary_bits) if primary_bits else MIN_RSA_KEY_BITS
        except (TypeError, ValueError):
            bits = MIN_RSA_KEY_BITS
        if bits < MIN_RSA_KEY_BITS:
            bits = MIN_RSA_KEY_BITS
        rsa_main = bip85_rsa_from_root(root, bits, key_index)
        pk.keymaterial = rsa_to_privpacket(rsa_main)
    elif primary_curve == "secp256k1":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_secp256k1_from_root(root, key_index)
    elif primary_curve == "nistp256":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_p256_from_root(root, key_index)
    elif primary_curve == "nistp384":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_p384_from_root(root, key_index)
    elif primary_curve == "nistp521":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_p521_from_root(root, key_index)
    elif primary_curve == "brainpoolp256r1":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index)
    elif primary_curve == "brainpoolp384r1":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_brainpoolp384r1_from_root(root, key_index)
    elif primary_curve == "brainpoolp512r1":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_brainpoolp512r1_from_root(root, key_index)
    elif primary_curve == "ed25519":
        pk.pkalg = PubKeyAlgorithm.EdDSA
        pk.keymaterial = bip85_ed25519_from_root(root, key_index)
    else:
        logger.warning(
            "Unsupported primary key params: algo=%s bits=%s curve=%s",
            primary_algo,
            primary_bits,
            primary_curve,
        )
        return False
    pk.created = created
    pk.update_hlen()
    primary = PGPKey()
    primary._key = pk
    if primary.fingerprint != fingerprint:
        logger.warning(
            "Primary key fingerprint mismatch during BIP85 verification"
        )
        return False

    for sk in subkeys:
        logger.info("Validating subkey idx=%s fpr=%s", sk["idx"], sk["fpr"])
        j = sk["idx"] - 1
        group_idx = j // 3
        sub_index = j % 3
        subpkt = PrivSubKeyV4()
        algo = sk["algo"]
        curve = _normalize_bip85_alg(sk["curve"])
        bits = int(sk.get("bits", "0") or "0")
        if algo in ("1", "2", "3"):
            subpkt.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
            rsa_sub = bip85_rsa_from_root(root, bits, group_idx, sub_index)
            subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
        elif curve == "secp256k1":
            subpkt.pkalg = PubKeyAlgorithm.ECDH if algo == "18" else PubKeyAlgorithm.ECDSA
            alg_name = "ECDH" if algo == "18" else "ECDSA"
            subpkt.keymaterial = bip85_secp256k1_from_root(root, group_idx, sub_index, alg_name)
        elif curve == "nistp256":
            subpkt.pkalg = PubKeyAlgorithm.ECDH if algo == "18" else PubKeyAlgorithm.ECDSA
            alg_name = "ECDH" if algo == "18" else "ECDSA"
            subpkt.keymaterial = bip85_p256_from_root(root, group_idx, sub_index, alg_name)
        elif curve == "nistp384":
            subpkt.pkalg = PubKeyAlgorithm.ECDH if algo == "18" else PubKeyAlgorithm.ECDSA
            alg_name = "ECDH" if algo == "18" else "ECDSA"
            subpkt.keymaterial = bip85_p384_from_root(root, group_idx, sub_index, alg_name)
        elif curve == "nistp521":
            subpkt.pkalg = PubKeyAlgorithm.ECDH if algo == "18" else PubKeyAlgorithm.ECDSA
            alg_name = "ECDH" if algo == "18" else "ECDSA"
            subpkt.keymaterial = bip85_p521_from_root(root, group_idx, sub_index, alg_name)
        elif curve == "brainpoolp256r1":
            subpkt.pkalg = PubKeyAlgorithm.ECDH if algo == "18" else PubKeyAlgorithm.ECDSA
            alg_name = "ECDH" if algo == "18" else "ECDSA"
            subpkt.keymaterial = bip85_brainpoolp256r1_from_root(root, group_idx, sub_index, alg_name)
        elif curve == "brainpoolp384r1":
            subpkt.pkalg = PubKeyAlgorithm.ECDH if algo == "18" else PubKeyAlgorithm.ECDSA
            alg_name = "ECDH" if algo == "18" else "ECDSA"
            subpkt.keymaterial = bip85_brainpoolp384r1_from_root(root, group_idx, sub_index, alg_name)
        elif curve == "brainpoolp512r1":
            subpkt.pkalg = PubKeyAlgorithm.ECDH if algo == "18" else PubKeyAlgorithm.ECDSA
            alg_name = "ECDH" if algo == "18" else "ECDSA"
            subpkt.keymaterial = bip85_brainpoolp512r1_from_root(root, group_idx, sub_index, alg_name)
        elif curve == "cv25519":
            if algo != "18":
                logger.warning(
                    "Unsupported subkey params at idx=%s: algo=%s curve=%s bits=%s",
                    sk["idx"],
                    algo,
                    curve,
                    bits,
                )
                return False
            subpkt.pkalg = PubKeyAlgorithm.ECDH
            subpkt.keymaterial = bip85_ed25519_from_root(root, group_idx, sub_index, "ECDH")
        elif curve == "ed25519":
            subpkt.pkalg = PubKeyAlgorithm.EdDSA if algo == "22" else PubKeyAlgorithm.ECDH
            alg_name = "EdDSA" if algo == "22" else "ECDH"
            subpkt.keymaterial = bip85_ed25519_from_root(root, group_idx, sub_index, alg_name)
        else:
            logger.warning(
                "Unsupported subkey params at idx=%s: algo=%s curve=%s bits=%s",
                sk["idx"],
                algo,
                curve,
                bits,
            )
            return False
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        if subkey.fingerprint != sk["fpr"]:
            logger.warning(
                "Subkey fingerprint mismatch at idx=%s: expected %s got %s",
                sk["idx"],
                sk["fpr"],
                subkey.fingerprint,
            )
            return False
    logger.info("Primary and subkeys validated successfully")
    return True


from typing import Optional, List, Dict


def bip85_add_subkeys(
    fingerprint: str, alg: str, key_index: int, start_index: int, seed
) -> Optional[List[Dict]]:
    from subprocess import run
    from embit import bip32
    from pgpy import PGPKey
    from pgpy.constants import (
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
    )
    from pgpy.pgp import PrivSubKeyV4
    from pgpy.packet import fields
    from pgpy.packet.types import MPI
    from Cryptodome.PublicKey import RSA

    logger.debug(
        "bip85_add_subkeys: alg=%s key_index=%s start_index=%s",
        alg,
        key_index,
        start_index,
    )
    if hasattr(seed, "get_root"):
        root = seed.get_root()
    else:
        root = bip32.HDKey.from_seed(seed.seed_bytes)

    export = run(
        ["gpg", "--armor", "--export-secret-keys", fingerprint],
        capture_output=True,
        text=True,
    )
    pgp_key, _ = PGPKey.from_blob(export.stdout)
    created = pgp_key._key.created
    expires = pgp_key.expires_at

    KEY_BITS = (
        2048
        if alg == "rsa2048"
        else 3072
        if alg == "rsa3072"
        else 4096
        if alg == "rsa4096"
        else None
    )

    def rsa_to_privpacket(rsa_key: RSA.RsaKey) -> fields.RSAPriv:
        priv = fields.RSAPriv()
        priv.n = MPI(rsa_key.n)
        priv.e = MPI(rsa_key.e)
        priv.d = MPI(rsa_key.d)
        priv.p = MPI(rsa_key.p)
        priv.q = MPI(rsa_key.q)
        priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
        priv._compute_chksum()
        return priv

    alg_canon = _normalize_bip85_alg(alg)
    subkey_specs = _bip85_subkey_specs(alg)
    type_map = {
        "nistp256": "ECC NIST P-256",
        "p256": "ECC NIST P-256",
        "nistp384": "ECC NIST P-384",
        "p384": "ECC NIST P-384",
        "nistp521": "ECC NIST P-521",
        "p521": "ECC NIST P-521",
        "brainpoolp256r1": "ECC Brainpool P-256",
        "brainpoolP256r1": "ECC Brainpool P-256",
        "brainpoolp384r1": "ECC Brainpool P-384",
        "brainpoolP384r1": "ECC Brainpool P-384",
        "brainpoolp512r1": "ECC Brainpool P-512",
        "brainpoolP512r1": "ECC Brainpool P-512",
        "secp256k1": "ECC secp256k1",
        "ed25519": "ECC Ed25519",
        "rsa2048": "RSA 2048",
        "rsa3072": "RSA 3072",
        "rsa4096": "RSA 4096",
    }
    alg_label = type_map.get(alg_canon, type_map.get(alg, alg))

    added = []
    for offset, pkalg, usage, *alg_name in subkey_specs:
        sub_index = (start_index % 3) + offset
        global_index = start_index + offset
        subpkt = PrivSubKeyV4()
        subpkt.pkalg = pkalg
        if alg_canon == "secp256k1":
            subpkt.keymaterial = bip85_secp256k1_from_root(root, key_index, sub_index, alg_name[0])
        elif alg_canon == "nistp256":
            subpkt.keymaterial = bip85_p256_from_root(root, key_index, sub_index, alg_name[0])
        elif alg_canon == "nistp384":
            subpkt.keymaterial = bip85_p384_from_root(root, key_index, sub_index, alg_name[0])
        elif alg_canon == "nistp521":
            subpkt.keymaterial = bip85_p521_from_root(root, key_index, sub_index, alg_name[0])
        elif alg_canon == "brainpoolp256r1":
            subpkt.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index, sub_index, alg_name[0])
        elif alg_canon == "brainpoolp384r1":
            subpkt.keymaterial = bip85_brainpoolp384r1_from_root(root, key_index, sub_index, alg_name[0])
        elif alg_canon == "brainpoolp512r1":
            subpkt.keymaterial = bip85_brainpoolp512r1_from_root(root, key_index, sub_index, alg_name[0])
        elif alg_canon == "ed25519":
            subpkt.keymaterial = bip85_ed25519_from_root(root, key_index, sub_index, alg_name[0])
        else:
            rsa_sub = bip85_rsa_from_root(root, KEY_BITS, key_index, sub_index)
            subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        pgp_key.add_subkey(
            subkey,
            usage=usage,
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
            expires=expires,
        )
        alg_name_str = alg_name[0] if alg_name else pkalg.name
        sub_type = alg_label if alg_canon.startswith("rsa") else f"{alg_name_str} {alg_label}"
        added.append({"index": global_index, "type": sub_type, "fingerprint": subkey.fingerprint})

    armored = str(pgp_key)
    r = run(
        ["gpg", "--batch", "--import-options", "merge-only", "--import"],
        input=armored.encode(),
        capture_output=True,
    )
    return added if r.returncode == 0 else None


def loose_add_subkeys(fingerprint: str, alg: str) -> bool:
    """Generate and merge random subkeys for algorithms unsupported by GPG."""
    from subprocess import run
    from contextlib import nullcontext
    from pgpy import PGPKey
    from pgpy.constants import (
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
        EllipticCurveOID,
    )

    alg_canon = _normalize_bip85_alg(alg)
    curve_map = {
        "secp256k1": EllipticCurveOID.SECP256K1,
        "nistp256": EllipticCurveOID.NIST_P256,
        "nistp384": EllipticCurveOID.NIST_P384,
        "nistp521": EllipticCurveOID.NIST_P521,
        "brainpoolp256r1": EllipticCurveOID.Brainpool_P256,
        "brainpoolp384r1": EllipticCurveOID.Brainpool_P384,
        "brainpoolp512r1": EllipticCurveOID.Brainpool_P512,
    }
    curve = curve_map[alg_canon]

    export = run(
        ["gpg", "--armor", "--export-secret-keys", fingerprint],
        capture_output=True,
        text=True,
    )
    pgp_key, _ = PGPKey.from_blob(export.stdout)
    created = pgp_key._key.created
    expires = pgp_key.expires_at

    subkey_specs = _bip85_subkey_specs(alg)
    ctx = pgp_key.unlock("") if pgp_key.is_protected else nullcontext()
    with ctx:
        for _, pkalg, usage, *rest in subkey_specs:
            subkey = PGPKey.new(pkalg, curve)
            subkey._key.created = created
            subkey._key.update_hlen()
            pgp_key.add_subkey(
                subkey,
                usage=usage,
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
            )

    armored = str(pgp_key)
    r = run(
        ["gpg", "--batch", "--import-options", "merge-only", "--import"],
        input=armored.encode(),
        capture_output=True,
    )
    return r.returncode == 0

def bip85_secp256k1_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA"
):
    from embit import bip85
    from seedsigner.helpers.ec_point import secp256k1_pub_xy
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_KEY_TYPE_SECP256K1, 256, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP, path)
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    # Bit-mask to curve bit length (no-op for byte-aligned curves) then
    # reduce into [1, order-1] only when the masked value is out of range.
    d = int.from_bytes(entropy[:32], "big") & ((1 << 256) - 1)
    if d == 0 or d >= order:
        d = (d % (order - 1)) + 1
    pub_x, pub_y = secp256k1_pub_xy(d)
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.SECP256K1
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.SECP256K1
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pub_x),
        fields.MPI(pub_y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def bip85_p256_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA"
):
    from embit import bip85
    from seedsigner.helpers.ec_point import nist_pub_xy
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_KEY_TYPE_NIST, 256, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP, path)
    # Avoid relying on cryptography's ``group_order`` attribute since
    # some versions (such as those bundled with seedsigner-os) do not
    # expose it. Instead, use the well-known group order for P-256.
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    # Bit-mask to curve bit length (no-op for byte-aligned curves) then
    # reduce into [1, order-1] only when the masked value is out of range.
    d = int.from_bytes(entropy[:32], "big") & ((1 << 256) - 1)
    if d == 0 or d >= order:
        d = (d % (order - 1)) + 1
    pub_x, pub_y = nist_pub_xy("P-256", d)
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.NIST_P256
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.NIST_P256
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pub_x),
        fields.MPI(pub_y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def bip85_brainpoolp256r1_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA",
):
    from embit import bip85
    from seedsigner.helpers.ec_point import brainpool_pub_xy
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_KEY_TYPE_BRAINPOOL, 256, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP, path)
    # Hardcode BrainpoolP256r1 group order to avoid relying on attributes
    # that may be missing in some cryptography builds.
    order = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
    # Bit-mask to curve bit length (no-op for byte-aligned curves) then
    # reduce into [1, order-1] only when the masked value is out of range.
    d = int.from_bytes(entropy[:32], "big") & ((1 << 256) - 1)
    if d == 0 or d >= order:
        d = (d % (order - 1)) + 1
    pub_x, pub_y = brainpool_pub_xy(256, d)
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.Brainpool_P256
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.Brainpool_P256
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pub_x),
        fields.MPI(pub_y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def bip85_p384_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA"
):
    from embit import bip85
    from seedsigner.helpers.ec_point import nist_pub_xy
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_KEY_TYPE_NIST, 384, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP, path)
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
    # Bit-mask to curve bit length (no-op for byte-aligned curves) then
    # reduce into [1, order-1] only when the masked value is out of range.
    d = int.from_bytes(entropy[:48], "big") & ((1 << 384) - 1)
    if d == 0 or d >= order:
        d = (d % (order - 1)) + 1
    pub_x, pub_y = nist_pub_xy("P-384", d)
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.NIST_P384
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.NIST_P384
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pub_x),
        fields.MPI(pub_y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def bip85_p521_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA"
):
    from embit import bip85
    from seedsigner.helpers.ec_point import nist_pub_xy
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields
    from seedsigner.helpers.bip85_drng import BIP85DRNG

    path = [BIP85_GPG_KEY_TYPE_NIST, 521, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP, path)
    # P-521 needs 66 bytes which exceeds the 64-byte HMAC output; use DRNG.
    drng = BIP85DRNG.new(entropy)
    d_bytes = drng.read(66)
    order = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
    # Mask to 521 bits (matching bipsea reference implementation) then
    # reduce into [1, order-1] only when the masked value is out of range.
    d = int.from_bytes(d_bytes, "big") & ((1 << 521) - 1)
    if d == 0 or d >= order:
        d = (d % (order - 1)) + 1
    pub_x, pub_y = nist_pub_xy("P-521", d)
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.NIST_P521
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.NIST_P521
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pub_x),
        fields.MPI(pub_y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def bip85_brainpoolp384r1_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA",
):
    from embit import bip85
    from seedsigner.helpers.ec_point import brainpool_pub_xy
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_KEY_TYPE_BRAINPOOL, 384, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP, path)
    order = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565
    # Bit-mask to curve bit length (no-op for byte-aligned curves) then
    # reduce into [1, order-1] only when the masked value is out of range.
    d = int.from_bytes(entropy[:48], "big") & ((1 << 384) - 1)
    if d == 0 or d >= order:
        d = (d % (order - 1)) + 1
    pub_x, pub_y = brainpool_pub_xy(384, d)
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.Brainpool_P384
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.Brainpool_P384
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pub_x),
        fields.MPI(pub_y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def bip85_brainpoolp512r1_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA",
):
    from embit import bip85
    from seedsigner.helpers.ec_point import brainpool_pub_xy
    from pgpy.constants import EllipticCurveOID
    from pgpy.packet import fields

    path = [BIP85_GPG_KEY_TYPE_BRAINPOOL, 512, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, BIP85_GPG_APP, path)
    order = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069
    # Bit-mask to curve bit length (no-op for byte-aligned curves) then
    # reduce into [1, order-1] only when the masked value is out of range.
    d = int.from_bytes(entropy[:64], "big") & ((1 << 512) - 1)
    if d == 0 or d >= order:
        d = (d % (order - 1)) + 1
    pub_x, pub_y = brainpool_pub_xy(512, d)
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.Brainpool_P512
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.Brainpool_P512
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pub_x),
        fields.MPI(pub_y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def _bip85_key_type_choices(include_all: bool = False) -> list[tuple[str, str]]:
    """Return available key type labels and identifiers for BIP85 GPG keys.

    Parameters
    ----------
    include_all : bool
        When ``True`` return every supported key type regardless of the
        ``SETTING__GPG_KEY_TYPES`` user preference.  Used by the CLI tool
        and import paths that must accept any key type.
    """
    all_types = [
        (label, code)
        for code, label in SettingsConstants.ALL_GPG_KEY_TYPES
    ]
    if include_all:
        return all_types

    from seedsigner.models.settings import Settings
    enabled = Settings.get_instance().get_value(SettingsConstants.SETTING__GPG_KEY_TYPES)
    return [(label, code) for label, code in all_types if code in enabled]


class ToolsGPGLoadBIP85KeyView(View):
    def run(self):
        from embit import bip32
        from pgpy import PGPKey, PGPUID
        from Cryptodome.PublicKey import RSA
        from pgpy.constants import (
            PubKeyAlgorithm,
            KeyFlags,
            HashAlgorithm,
            SymmetricKeyAlgorithm,
            CompressionAlgorithm,
        )
        from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
        from pgpy.packet import fields
        from pgpy.packet.types import MPI
        from datetime import datetime, timezone, date
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.gui.screens import LargeIconStatusScreen, WarningScreen
        from seedsigner.gui.screens import seed_screens, tools_screens

        if len(self.controller.storage.seeds) == 0:
            self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="Load a seed before using\nBIP85 GPG tools.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.run_screen(
            WarningScreen,
            title="WARNING",
            status_headline=None,
            text=(
                "BIP85 GPG key derivation\nis experimental.\n"
                "Record your SeedSigner Version."
            ),
            show_back_button=False,
            button_data=[ButtonOption("I Understand")],
        )

        if len(self.controller.storage.seeds) > 1:
            seed_buttons = []
            for seed in self.controller.storage.seeds:
                button_str = seed.get_fingerprint(
                    self.settings.get_value(SettingsConstants.SETTING__NETWORK)
                )
                seed_buttons.append(
                    ButtonOption(
                        button_str,
                        SeedSignerIconConstants.FINGERPRINT,
                        icon_color="blue",
                    )
                )
            selected_seed = self.run_screen(
                seed_screens.SeedSelectSeedScreen,
                title="Select Seed",
                text="Choose seed for BIP85 key",
                is_button_text_centered=False,
                button_data=seed_buttons,
            )
            if selected_seed == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            seed = self.controller.get_seed(selected_seed)
        else:
            seed = self.controller.get_seed(0)

        ret = seed_screens.SeedBIP85SelectChildIndexScreen(title="Key Index").display()
        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        key_index = int(ret)

        keytype_choices = _bip85_key_type_choices()
        keytype_buttons = [ButtonOption(label) for label, _ in keytype_choices]
        selected_type = self.run_screen(
            ButtonListScreen,
            title="Key Type",
            is_button_text_centered=False,
            button_data=keytype_buttons,
        )
        if selected_type == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        key_type_label = keytype_buttons[selected_type].button_label
        key_type = keytype_choices[selected_type][1]

        if key_type in ["secp256k1", "ed25519"]:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="This key type can't be exported to SmartPGP cards.",
                show_back_button=True,
                button_data=[ButtonOption("I Understand")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        if key_type.startswith("rsa"):
            warn_text = {
                "rsa2048": "Generating an RSA 2048 key can take around 3 minutes on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
                "rsa3072": "Generating an RSA 3072 key can take around 15 minutes on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
                "rsa4096": "Generating an RSA 4096 key can take around an hour on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
            }[key_type]
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text=warn_text,
                show_back_button=True,
                button_data=[ButtonOption("I Understand")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        def prompt_text(title: str, default: str = ""):
            ret_dict = tools_screens.ToolsTextQRTextEntryScreen(
                textToEncode=default, title=title
            ).display()
            if "is_back_button" in ret_dict:
                return None
            try:
                import re
                return bytes(
                    re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                    encoding="raw_unicode_escape",
                ).decode("unicode_escape")
            except UnicodeError:
                return ret_dict["textToEncode"]

        name = prompt_text("Name")
        if name is None:
            return Destination(BackStackView)

        email = prompt_text("Email")
        if email is None:
            return Destination(BackStackView)

        created = datetime.fromtimestamp(BIP85_GPG_CREATED_TS, tz=timezone.utc)
        if key_type == "rsa2048":
            default_expiration = date(2029, 12, 31)
        else:
            default_expiration = date(2035, 12, 31)
        expiration_str = prompt_text(
            "Expiration YYYY-MM-DD", default_expiration.isoformat()
        )
        if expiration_str is None:
            return Destination(BackStackView)
        try:
            if expiration_str.strip() == "":
                expiration_dt = datetime.combine(
                    default_expiration, datetime.min.time(), tzinfo=timezone.utc
                )
            else:
                expiration_dt = datetime.strptime(
                    _normalize_date_input(expiration_str), "%Y-%m-%d"
                ).replace(tzinfo=timezone.utc)
            if expiration_dt <= created:
                raise ValueError
            expires = expiration_dt - created
        except ValueError:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Invalid expiration date",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
        root = seed.get_root(network)
        KEY_BITS = (
            2048
            if key_type == "rsa2048"
            else 3072
            if key_type == "rsa3072"
            else 4096
            if key_type == "rsa4096"
            else None
        )

        def rsa_to_privpacket(rsa_key: RSA.RsaKey) -> fields.RSAPriv:
            priv = fields.RSAPriv()
            priv.n = MPI(rsa_key.n)
            priv.e = MPI(rsa_key.e)
            priv.d = MPI(rsa_key.d)
            priv.p = MPI(rsa_key.p)
            priv.q = MPI(rsa_key.q)
            priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
            priv._compute_chksum()
            return priv

        self.loading_screen = LoadingScreenThread(text="Generating BIP85 GPG key\n\n\n\n\n\n(This takes a while)")
        self.loading_screen.start()
        try:
            pk = PrivKeyV4()
            if key_type == "secp256k1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_secp256k1_from_root(root, key_index)
            elif key_type == "p256":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_p256_from_root(root, key_index)
            elif key_type == "p384":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_p384_from_root(root, key_index)
            elif key_type == "p521":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_p521_from_root(root, key_index)
            elif key_type == "brainpoolp256r1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index)
            elif key_type == "brainpoolp384r1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_brainpoolp384r1_from_root(root, key_index)
            elif key_type == "brainpoolp512r1":
                pk.pkalg = PubKeyAlgorithm.ECDSA
                pk.keymaterial = bip85_brainpoolp512r1_from_root(root, key_index)
            elif key_type == "ed25519":
                pk.pkalg = PubKeyAlgorithm.EdDSA
                pk.keymaterial = bip85_ed25519_from_root(root, key_index)
            else:
                rsa_main = bip85_rsa_from_root(root, KEY_BITS, key_index)
                pk.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
                pk.keymaterial = rsa_to_privpacket(rsa_main)
            pk.created = created
            pk.update_hlen()

            pgp_key = PGPKey()
            pgp_key._key = pk

            uid = PGPUID.new(name, email=email)
            uid_str = uid.userid
            pgp_key.add_uid(
                uid,
                usage={KeyFlags.Certify, KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
                created=created,
            )

            if key_type == "ed25519":
                subkey_specs = [
                    (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
                    (1, PubKeyAlgorithm.EdDSA, {KeyFlags.Authentication}, "EdDSA"),
                    (2, PubKeyAlgorithm.EdDSA, {KeyFlags.Sign}, "EdDSA"),
                ]
            elif key_type in ["secp256k1", "p256", "p384", "p521", "brainpoolp256r1", "brainpoolp384r1", "brainpoolp512r1"]:
                subkey_specs = [
                    (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
                    (1, PubKeyAlgorithm.ECDSA, {KeyFlags.Authentication}, "ECDSA"),
                    (2, PubKeyAlgorithm.ECDSA, {KeyFlags.Sign}, "ECDSA"),
                ]
            else:
                subkey_specs = [
                    (0, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}),
                    (1, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Authentication}),
                    (2, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Sign}),
                ]

            subkey_info_list = []
            for spec in subkey_specs:
                sub_index, pkalg, usage, *alg = spec
                subpkt = PrivSubKeyV4()
                subpkt.pkalg = pkalg
                if key_type == "secp256k1":
                    subpkt.keymaterial = bip85_secp256k1_from_root(root, key_index, sub_index, alg[0])
                elif key_type == "p256":
                    subpkt.keymaterial = bip85_p256_from_root(root, key_index, sub_index, alg[0])
                elif key_type == "p384":
                    subpkt.keymaterial = bip85_p384_from_root(root, key_index, sub_index, alg[0])
                elif key_type == "p521":
                    subpkt.keymaterial = bip85_p521_from_root(root, key_index, sub_index, alg[0])
                elif key_type == "brainpoolp256r1":
                    subpkt.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index, sub_index, alg[0])
                elif key_type == "brainpoolp384r1":
                    subpkt.keymaterial = bip85_brainpoolp384r1_from_root(root, key_index, sub_index, alg[0])
                elif key_type == "brainpoolp512r1":
                    subpkt.keymaterial = bip85_brainpoolp512r1_from_root(root, key_index, sub_index, alg[0])
                elif key_type == "ed25519":
                    subpkt.keymaterial = bip85_ed25519_from_root(root, key_index, sub_index, alg[0])
                else:
                    rsa_sub = bip85_rsa_from_root(root, KEY_BITS, key_index, sub_index)
                    subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
                subpkt.created = created
                subpkt.update_hlen()
                subkey = PGPKey()
                subkey._key = subpkt
                pgp_key.add_subkey(
                    subkey,
                    usage=usage,
                    hashes=[HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.ZLIB],
                    expires=expires,
                    created=created,
                )
                alg_name = alg[0] if alg else pkalg.name
                sub_type = (
                    key_type_label if key_type.startswith("rsa") else f"{alg_name} {key_type_label}"
                )
                subkey_info_list.append(
                    {
                        "index": sub_index,
                        "type": sub_type,
                        "fingerprint": subkey.fingerprint,
                    }
                )

            armored = str(pgp_key)

            result = run(["gpg", "--batch", "--import"], input=armored.encode(), capture_output=True)
        finally:
            self.loading_screen.stop()

        if result.returncode == 0:
            seed_fpr = seed.get_fingerprint(
                self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            )
            BIP85_DATA[pgp_key.fingerprint] = {
                "primary_fpr": pgp_key.fingerprint,
                "seed_fpr": seed_fpr,
                "index": key_index,
                "key_type": key_type_label,
                "ss_version": self.controller.VERSION,
                "uids": [uid_str],
                "primary_uid": uid_str,
                "subkeys": subkey_info_list,
                "revocations": [],
            }
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="BIP85 GPG key imported",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )

        return Destination(ToolsGPGMenuView)




class ToolsGPGAddSubkeysView(View):
    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.gui.screens import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
        )

        result = run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = parse_secret_key_list(result.stdout)

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = []
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            buttons.append(ButtonOption(label))

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        fingerprint = keys[selected]["fpr"]

        result = run(
            ["gpg", "--list-secret-keys", "--with-colons", fingerprint],
            capture_output=True,
            text=True,
        )
        start_index = sum(1 for line in result.stdout.splitlines() if line.startswith("ssb"))
        created_ts = keys[selected]["created"]
        entry = BIP85_DATA.get(fingerprint)
        bip85 = entry is not None
        fingerprint_suffix = fingerprint[-4:] if isinstance(fingerprint, str) and len(fingerprint) >= 4 else fingerprint
        logger.debug(
            "AddSubkeysView: fpr_suffix=%s bip85=%s start_index=%s",
            fingerprint_suffix,
            bip85,
            start_index,
        )
        sec_line = next(l for l in result.stdout.splitlines() if l.startswith("sec"))
        sec_parts = sec_line.split(":")
        primary_bits = sec_parts[2] if len(sec_parts) > 2 else ""
        primary_algo = sec_parts[3] if len(sec_parts) > 3 else ""
        primary_curve = sec_parts[16].lower() if len(sec_parts) > 16 else ""
        subkeys = parse_subkey_list(result.stdout)

        seed = None
        base_index = None
        if bip85:
            logger.debug(
                "BIP85 key detected; searching for seed fingerprint suffix=%s",
                entry["seed_fpr"][-4:] if isinstance(entry["seed_fpr"], str) and len(entry["seed_fpr"]) >= 4 else entry["seed_fpr"],
            )
            network = self.settings.get_value(SettingsConstants.SETTING__NETWORK)
            seed = None
            seed_index = None
            for idx, seed_obj in enumerate(self.controller.storage.seeds):
                if seed_obj.get_fingerprint(network) == entry["seed_fpr"]:
                    seed = seed_obj
                    seed_index = idx
                    break
            if seed is None:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Required seed not loaded",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            logger.debug("Seed matched at index=%s", seed_index)
            base_index = entry["index"]
            if not bip85_verify_existing(
                seed,
                fingerprint,
                base_index,
                created_ts,
                primary_algo,
                primary_bits,
                primary_curve,
                subkeys,
            ):
                logger.debug(
                    "Selected seed/index failed validation (base_index=%s)",
                    base_index,
                )
                corrected = None
                for i in range(base_index - 1, -1, -1):
                    if bip85_verify_existing(
                        seed,
                        fingerprint,
                        i,
                        created_ts,
                        primary_algo,
                        primary_bits,
                        primary_curve,
                        subkeys,
                    ):
                        corrected = i
                        break
                if corrected is None:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Selected seed/index mismatch",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                logger.warning(
                    "Registry index %s mismatched; corrected to %s",
                    base_index,
                    corrected,
                )
                BIP85_DATA[fingerprint]["index"] = corrected
                base_index = corrected
            logger.info("Existing key validated successfully at index %s", base_index)

        key_index = base_index + (start_index // 3) if bip85 else None
        if bip85:
            logger.info(
                "AddSubkeysView: validated base_index=%s resulting key_index=%s",
                base_index,
                key_index,
            )
        keytype_choices = _bip85_key_type_choices()
        keytype_buttons = [ButtonOption(label) for label, _ in keytype_choices]
        selected_type = self.run_screen(
            ButtonListScreen,
            title="Key Type",
            is_button_text_centered=False,
            button_data=keytype_buttons,
        )
        if selected_type == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        _, alg = keytype_choices[selected_type]

        if alg in ["secp256k1", "ed25519"]:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="This key type can't be exported to SmartPGP cards.",
                show_back_button=True,
                button_data=[ButtonOption("I Understand")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(
            text="Generating subkeys\n\n\n\n\n(This takes a while)"
        )
        self.loading_screen.start()
        success = True
        added_info = None
        try:
            if bip85:
                added_info = bip85_add_subkeys(
                    fingerprint, alg, key_index, start_index, seed
                )
                success = added_info is not None
            elif alg.startswith("rsa"):
                for usage in ["encrypt", "sign,auth", "sign"]:
                    r = gpg_quick_addkey(fingerprint, alg, usage)
                    if r.returncode != 0:
                        success = False
                        break
            elif alg == "ed25519":
                cmds = [
                    ("cv25519", "encrypt"),
                    ("ed25519", "sign,auth"),
                    ("ed25519", "sign"),
                ]
                for sub_alg, usage in cmds:
                    r = gpg_quick_addkey(fingerprint, sub_alg, usage)
                    if r.returncode != 0:
                        success = False
                        break
            else:
                success = loose_add_subkeys(fingerprint, alg)
        finally:
            self.loading_screen.stop()

        if success:
            if bip85 and added_info is not None:
                BIP85_DATA[fingerprint]["subkeys"].extend(added_info)
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="Subkeys added",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to add subkeys",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )

        return Destination(ToolsGPGMenuView)


class ToolsGPGGenerateKeyView(View):
    def run(self):
        from pgpy import PGPKey, PGPUID
        from pgpy.constants import (
            PubKeyAlgorithm,
            KeyFlags,
            HashAlgorithm,
            SymmetricKeyAlgorithm,
            CompressionAlgorithm,
            EllipticCurveOID,
        )
        from datetime import datetime, timezone, date
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.gui.screens import (
            LargeIconStatusScreen,
            WarningScreen,
            tools_screens,
        )

        all_keytype_data = [
            (
                "ed25519",
                "ECC Ed25519",
                (PubKeyAlgorithm.EdDSA, EllipticCurveOID.Ed25519),
                True,
            ),
            (
                "p256",
                "ECC NIST P-256",
                (PubKeyAlgorithm.ECDSA, EllipticCurveOID.NIST_P256),
                False,
            ),
            (
                "brainpoolp256r1",
                "ECC Brainpool P-256",
                (PubKeyAlgorithm.ECDSA, EllipticCurveOID.Brainpool_P256),
                False,
            ),
            (
                "rsa2048",
                "RSA 2048",
                (PubKeyAlgorithm.RSAEncryptOrSign, 2048),
                False,
            ),
            (
                "rsa3072",
                "RSA 3072",
                (PubKeyAlgorithm.RSAEncryptOrSign, 3072),
                False,
            ),
            (
                "rsa4096",
                "RSA 4096",
                (PubKeyAlgorithm.RSAEncryptOrSign, 4096),
                False,
            ),
            (
                "secp256k1",
                "ECC secp256k1",
                (PubKeyAlgorithm.ECDSA, EllipticCurveOID.SECP256K1),
                True,
            ),
        ]
        enabled = self.settings.get_value(SettingsConstants.SETTING__GPG_KEY_TYPES)
        keytype_data = [
            (label, params, warn)
            for code, label, params, warn in all_keytype_data
            if code in enabled
        ]
        if not keytype_data:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No GPG key types enabled.\nEnable types in Settings.",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)
        keytype_buttons = [ButtonOption(label) for label, _, _ in keytype_data]
        selected_type = self.run_screen(
            ButtonListScreen,
            title="Key Type",
            is_button_text_centered=False,
            button_data=keytype_buttons,
        )
        if selected_type == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        _, (alg, param), warn_export_blocked = keytype_data[selected_type]

        if warn_export_blocked:
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text="This key type can't be exported to SmartPGP cards.",
                show_back_button=True,
                button_data=[ButtonOption("I Understand")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        if alg == PubKeyAlgorithm.RSAEncryptOrSign:
            warn_text = {
                2048: "Generating an RSA 2048 key can take around 3 minutes on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
                3072: "Generating an RSA 3072 key can take around 15 minutes on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
                4096: "Generating an RSA 4096 key can take around an hour on a Pi Zero.\nNIST or Brainpool keys are faster and smaller.",
            }[param]
            ret = self.run_screen(
                WarningScreen,
                title="WARNING",
                status_headline=None,
                text=warn_text,
                show_back_button=True,
                button_data=[ButtonOption("I Understand")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

        def prompt_text(title: str, default: str = ""):
            ret_dict = tools_screens.ToolsTextQRTextEntryScreen(
                textToEncode=default, title=title
            ).display()
            if "is_back_button" in ret_dict:
                return None
            try:
                import re

                return bytes(
                    re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                    encoding="raw_unicode_escape",
                ).decode("unicode_escape")
            except UnicodeError:
                return ret_dict["textToEncode"]

        name = prompt_text("Name")
        if name is None:
            return Destination(BackStackView)

        email = prompt_text("Email")
        if email is None:
            return Destination(BackStackView)

        created = datetime.now(timezone.utc)
        if alg == PubKeyAlgorithm.RSAEncryptOrSign and param == 2048:
            default_expiration = date(2029, 12, 31)
        else:
            default_expiration = date(2035, 12, 31)
        expiration_str = prompt_text(
            "Expiration YYYY-MM-DD", default_expiration.isoformat()
        )
        if expiration_str is None:
            return Destination(BackStackView)
        try:
            if expiration_str.strip() == "":
                expiration_dt = datetime.combine(
                    default_expiration, datetime.min.time(), tzinfo=timezone.utc
                )
            else:
                expiration_dt = datetime.strptime(
                    _normalize_date_input(expiration_str), "%Y-%m-%d"
                ).replace(tzinfo=timezone.utc)
            if expiration_dt <= created:
                raise ValueError
            expires = expiration_dt - created
        except ValueError:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Invalid expiration date",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        self.loading_screen = LoadingScreenThread(
            text="Generating GPG key\n\n\n\n\n\n(This takes a while)"
        )
        self.loading_screen.start()
        try:
            # PGPKey.new leverages the OS CSPRNG for secure entropy
            master_key = PGPKey.new(alg, param)

            uid = PGPUID.new(name, email=email)
            master_key.add_uid(
                uid,
                usage={KeyFlags.Certify, KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
            )

            if alg == PubKeyAlgorithm.RSAEncryptOrSign:
                sub_enc = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, param)
                sub_auth = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, param)
                sub_sign = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, param)
            elif alg == PubKeyAlgorithm.EdDSA:
                sub_enc = PGPKey.new(PubKeyAlgorithm.ECDH, EllipticCurveOID.Curve25519)
                sub_auth = PGPKey.new(PubKeyAlgorithm.EdDSA, param)
                sub_sign = PGPKey.new(PubKeyAlgorithm.EdDSA, param)
            else:
                curve = param
                sub_enc = PGPKey.new(PubKeyAlgorithm.ECDH, curve)
                sub_auth = PGPKey.new(PubKeyAlgorithm.ECDSA, curve)
                sub_sign = PGPKey.new(PubKeyAlgorithm.ECDSA, curve)

            master_key.add_subkey(
                sub_enc,
                usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
            )
            master_key.add_subkey(
                sub_auth,
                usage={KeyFlags.Authentication},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
            )
            master_key.add_subkey(
                sub_sign,
                usage={KeyFlags.Sign},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB],
                expires=expires,
            )

            armored = str(master_key)
            result = run(
                ["gpg", "--batch", "--import"],
                input=armored.encode(),
                capture_output=True,
            )
        finally:
            self.loading_screen.stop()

        if result.returncode == 0:
            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text="GPG key generated",
                show_back_button=False,
                button_data=[ButtonOption("Done")],
            )
        else:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )

        return Destination(MainMenuView)


class ToolsGPGExportPubkeyView(View):
    def run(self):
        from subprocess import run
        import os
        import platform
        from seedsigner.models.encode_qr import UrBytesQrEncoder
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            LoadingScreenThread,
            QRDisplayScreen,
        )

        result = run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = []
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            buttons.append(ButtonOption(label))

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        key = keys[selected]
        base_label = key["uid"] if key["uid"] else key["fpr"][-8:]

        dest_buttons = [
            ButtonOption("microSD"),
            ButtonOption("Animated QR"),
            ButtonOption("Seedkeeper"),
            ButtonOption("OpenGPG Card"),
        ]
        dest_selected = self.run_screen(
            ButtonListScreen,
            title="Export to",
            is_button_text_centered=False,
            button_data=dest_buttons,
        )

        if dest_selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if dest_selected == 0:
            if len(self.controller.storage.seeds) > 0:
                ret = self.run_screen(
                    WarningScreen,
                    title="WARNING",
                    status_headline=None,
                    text="These tools write data to the microSD card and may expose loaded secrets.",
                    show_back_button=True,
                    button_data=[ButtonOption("Continue")],
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)

            filename = key["fpr"] + ".asc"
            filepath = os.path.join(file_list_path, filename)
            exported = run(
                ["gpg", "--armor", "--output", filepath, "--export", key["fpr"]],
                capture_output=True,
                text=True,
            )
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Saved as {filename}",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)
        elif dest_selected == 1:
            exported = run(
                ["gpg", "--armor", "--export", key["fpr"]],
                capture_output=True,
            )
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            loading = LoadingScreenThread(text="Encoding...")
            loading.start()
            try:
                qr_encoder = UrBytesQrEncoder(
                    data=exported.stdout,
                    qr_density=self.settings.get_value(SettingsConstants.SETTING__QR_DENSITY),
                )
            finally:
                loading.stop()

            num_codes = qr_encoder.seq_len()
            ret = self.run_screen(
                WarningScreen,
                title="Animated QR",
                status_headline=None,
                text=f"This export requires {num_codes} QR code{'s' if num_codes > 1 else ''}.",
                show_back_button=True,
                button_data=[ButtonOption("Start")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)

            self.run_screen(QRDisplayScreen, qr_encoder=qr_encoder)
            return Destination(MainMenuView)
        else:
            exported = run(
                ["gpg", "--armor", "--export", key["fpr"]],
                capture_output=True,
                text=True,
            )
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            Satochip_Connector = seedkeeper_utils.init_satochip(
                self, init_card_filter=["seedkeeper"]
            )
            if not Satochip_Connector:
                return Destination(BackStackView)

            pubkey_bytes = exported.stdout.encode("utf-8")
            label = f"GPGPub:{base_label}"
            status = Satochip_Connector.card_get_status()[3]
            if status['protocol_minor_version'] == 1:
                if len(pubkey_bytes) > 255:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Pubkey too large for Seedkeeper v1",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                secret_list = [len(pubkey_bytes)] + list(pubkey_bytes)
            else:
                secret_list = list(len(pubkey_bytes).to_bytes(2, "big")) + list(pubkey_bytes)

            header = Satochip_Connector.make_header(
                "Data", "Plaintext export allowed", label
            )
            secret_dic = {"header": header, "secret_list": secret_list}

            try:
                fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                    Satochip_Connector, secret_dic
                )
            except Exception as e:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=str(e),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            if not fits:
                self.run_screen(
                    WarningScreen,
                    title="Not Enough Space",
                    status_headline=None,
                    text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            try:
                self.loading_screen = LoadingScreenThread(
                    text="Saving Secret\n\n\n\n\n\n",
                )
                self.loading_screen.start()
                Satochip_Connector.seedkeeper_import_secret(secret_dic)
                self.loading_screen.stop()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="Pubkey saved to Seedkeeper",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(MainMenuView)
            except UnexpectedSW12Error as e:
                self.loading_screen.stop()
                if e.sw1 == 0x6A and e.sw2 == 0x84:
                    error_text = "Not enough space on Seedkeeper for key"
                else:
                    error_text = format_sw_error(e.sw1, e.sw2)
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=error_text,
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            except Exception:
                self.loading_screen.stop()
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)


class ToolsGPGExportPrivkeyView(View):
    def run(self):
        from subprocess import run
        import os
        import platform
        from seedsigner.gui.screens.screen import (
            ButtonListScreen,
            LargeIconStatusScreen,
            WarningScreen,
            LoadingScreenThread,
        )
        from seedsigner.gui.screens import tools_screens

        result = run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
        )
        keys = []
        cur = None
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                cur = {"fpr": None, "uid": None}
                keys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur.get("fpr") is None:
                cur["fpr"] = parts[9]
            elif parts[0] == "uid" and cur is not None and cur.get("uid") is None:
                cur["uid"] = parts[9]

        if not keys:
            self.run_screen(
                WarningScreen,
                title="Error",
                status_headline=None,
                text="No private keys found",
                show_back_button=False,
                button_data=[ButtonOption("I Understand")],
            )
            return Destination(BackStackView)

        buttons = []
        for key in keys:
            label = key["uid"] if key["uid"] else key["fpr"][-8:]
            buttons.append(ButtonOption(label))

        selected = self.run_screen(
            ButtonListScreen,
            title="Select Key",
            is_button_text_centered=False,
            button_data=buttons,
        )

        if selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        key = keys[selected]
        base_label = key["uid"] if key["uid"] else key["fpr"][-8:]

        dest_buttons = [
            ButtonOption("microSD"),
            ButtonOption("Seedkeeper"),
            ButtonOption("OpenGPG Card"),
        ]
        dest_selected = self.run_screen(
            ButtonListScreen,
            title="Export to",
            is_button_text_centered=False,
            button_data=dest_buttons,
        )

        if dest_selected == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if dest_selected == 0:
            if len(self.controller.storage.seeds) > 0:
                ret = self.run_screen(
                    WarningScreen,
                    title="WARNING",
                    status_headline=None,
                    text="These tools write data to the microSD card and may expose loaded secrets.",
                    show_back_button=True,
                    button_data=[ButtonOption("Continue")],
                )
                if ret == RET_CODE__BACK_BUTTON:
                    return Destination(BackStackView)

            file_list_path = MicroSD.get_microsd_dir() / "microsd-images"
            os.makedirs(file_list_path, exist_ok=True)

            ret_dict = tools_screens.ToolsTextQRTextEntryScreen(
                textToEncode="", title="Passphrase"
            ).display()
            if "is_back_button" in ret_dict:
                return Destination(BackStackView)
            try:
                import re

                passphrase = bytes(
                    re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                    encoding="raw_unicode_escape",
                ).decode("unicode_escape")
            except UnicodeError:
                passphrase = ret_dict["textToEncode"]

            filename = key["fpr"] + "_private.gpg"
            filepath = os.path.join(file_list_path, filename)
            exported = run(
                ["gpg", "--armor", "--export-secret-keys", key["fpr"]],
                capture_output=True,
                text=True,
            )
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            protected = run(
                [
                    "gpg",
                    "--armor",
                    "--batch",
                    "--yes",
                    "--pinentry-mode",
                    "loopback",
                    "--passphrase",
                    passphrase,
                    "--symmetric",
                    "--cipher-algo",
                    "AES256",
                    "--output",
                    filepath,
                ],
                input=exported.stdout,
                capture_output=True,
                text=True,
            )
            if protected.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to protect key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            self.run_screen(
                LargeIconStatusScreen,
                title="Success",
                status_headline=None,
                text=f"Saved as {filename}",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(MainMenuView)
        elif dest_selected == 1:
            exported = run(
                ["gpg", "--armor", "--export-secret-keys", key["fpr"]],
                capture_output=True,
                text=True,
            )
            if exported.returncode != 0:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            Satochip_Connector = seedkeeper_utils.init_satochip(
                self, init_card_filter=["seedkeeper"]
            )
            if not Satochip_Connector:
                return Destination(BackStackView)

            privkey_bytes = exported.stdout.encode("utf-8")
            label = f"GPGPriv:{base_label}"
            status = Satochip_Connector.card_get_status()[3]
            if status['protocol_minor_version'] == 1:
                if len(privkey_bytes) > 255:
                    self.run_screen(
                        WarningScreen,
                        title="Error",
                        status_headline=None,
                        text="Privkey too large for Seedkeeper v1",
                        show_back_button=False,
                        button_data=[ButtonOption("I Understand")],
                    )
                    return Destination(BackStackView)
                secret_list = [len(privkey_bytes)] + list(privkey_bytes)
            else:
                secret_list = list(len(privkey_bytes).to_bytes(2, "big")) + list(privkey_bytes)

            header = Satochip_Connector.make_header(
                "Data", "Plaintext export allowed", label
            )
            secret_dic = {"header": header, "secret_list": secret_list}

            try:
                fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
                    Satochip_Connector, secret_dic
                )
            except Exception as e:
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=str(e),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            if not fits:
                self.run_screen(
                    WarningScreen,
                    title="Not Enough Space",
                    status_headline=None,
                    text=seedkeeper_utils.format_seedkeeper_space_error(required_bytes, free_bytes),
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)

            try:
                self.loading_screen = LoadingScreenThread(
                    text="Saving Secret\n\n\n\n\n\n",
                )
                self.loading_screen.start()
                Satochip_Connector.seedkeeper_import_secret(secret_dic)
                self.loading_screen.stop()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Success",
                    status_headline=None,
                    text="Privkey saved to Seedkeeper",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(MainMenuView)
            except UnexpectedSW12Error as e:
                self.loading_screen.stop()
                if e.sw1 == 0x6A and e.sw2 == 0x84:
                    error_text = "Not enough space on Seedkeeper for key"
                else:
                    error_text = format_sw_error(e.sw1, e.sw2)
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text=error_text,
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
            except Exception:
                self.loading_screen.stop()
                self.run_screen(
                    WarningScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to export key",
                    show_back_button=False,
                    button_data=[ButtonOption("I Understand")],
                )
                return Destination(BackStackView)
        else:
            return Destination(
                ToolsGPGImportKeyToCardView,
                view_args={"fingerprint": key["fpr"]},
            )


class ToolsGPGImportKeyToCardView(View):
    def __init__(self, fingerprint: str, selected_subkeys=None):
        super().__init__()
        self.fingerprint = fingerprint
        self.selected_subkeys = selected_subkeys
        self.loading_screen = None

    def _stop_loading_screen(self):
        loading = getattr(self, "loading_screen", None)
        if loading:
            try:
                loading.stop()
            finally:
                self.loading_screen = None

    def _clear_cached_admin_pin(self):
        controller = getattr(self, "controller", None)
        if not controller:
            return
        if hasattr(controller, "GPG_Admin_PIN"):
            controller.GPG_Admin_PIN = None
        try:
            seedkeeper_utils.disconnect_smartcard_connections(controller)
        except Exception:
            logger.debug("Failed to reset smartcard connections after admin PIN error", exc_info=True)

    def run(self):
        from subprocess import run
        from seedsigner.gui.screens.screen import LoadingScreenThread
        from seedsigner.helpers import seedkeeper_utils

        seedkeeper_utils.disconnect_smartcard_connections(self.controller)
        run(["gpgconf", "--reload", "scdaemon"])

        card_status = run(["gpg", "--card-status"], capture_output=True, text=True)
        status_out = (card_status.stdout or "") + (card_status.stderr or "")
        admin_pin = self.controller.GPG_Admin_PIN
        if "[none]" in status_out:
            ret = self.run_screen(
                WarningScreen,
                title="Default PINs",
                status_headline=None,
                text="Card uses default PINs. You'll set new Admin and User PINs before import.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            ret = self.run_screen(
                WarningScreen,
                title="Admin PIN Required",
                status_headline=None,
                text="Admin PIN is needed for changing keys and editing card settings.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            new_admin = seedkeeper_utils.prompt_for_pin(self, "New Admin PIN")
            if new_admin is None:
                return Destination(BackStackView)
            admin_cmds = f"3\n12345678\n{new_admin}\n{new_admin}\nQ\n"
            admin_res = run(
                [
                    "gpg",
                    "--pinentry-mode",
                    "loopback",
                    "--status-fd",
                    "1",
                    "--command-fd",
                    "0",
                    "--change-pin",
                ],
                input=admin_cmds,
                capture_output=True,
                text=True,
            )
            out = (admin_res.stdout or "") + (admin_res.stderr or "")
            success = "PIN changed" in out or "SC_OP_SUCCESS" in admin_res.stdout
            if "SC_OP_FAILURE" in admin_res.stdout or not success:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Failed",
                    status_headline=None,
                    text="Admin PIN change failed",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)
            self.controller.GPG_Admin_PIN = new_admin
            admin_pin = new_admin

            ret = self.run_screen(
                WarningScreen,
                title="User PIN Required",
                status_headline=None,
                text="User PIN is needed for signing and using on-card keys.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            new_user = seedkeeper_utils.prompt_for_pin(self, "New User PIN")
            if new_user is None:
                return Destination(BackStackView)
            user_cmds = f"1\n123456\n{new_user}\n{new_user}\nQ\n"
            user_res = run(
                [
                    "gpg",
                    "--pinentry-mode",
                    "loopback",
                    "--status-fd",
                    "1",
                    "--command-fd",
                    "0",
                    "--change-pin",
                ],
                input=user_cmds,
                capture_output=True,
                text=True,
            )
            out = (user_res.stdout or "") + (user_res.stderr or "")
            success = "PIN changed" in out or "SC_OP_SUCCESS" in user_res.stdout
            if "SC_OP_FAILURE" in user_res.stdout or not success:
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Failed",
                    status_headline=None,
                    text="User PIN change failed",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)

            run(["gpgconf", "--reload", "scdaemon"])

        if admin_pin is None:
            ret = self.run_screen(
                WarningScreen,
                title="Admin PIN Required",
                status_headline=None,
                text="Admin PIN is needed for changing keys and editing card settings.",
                show_back_button=True,
                button_data=[ButtonOption("Continue")],
            )
            if ret == RET_CODE__BACK_BUTTON:
                return Destination(BackStackView)
            admin_pin = seedkeeper_utils.prompt_for_pin(self, "Admin PIN")
            if admin_pin is None:
                return Destination(BackStackView)
            self.controller.GPG_Admin_PIN = admin_pin

        result = run(
            ["gpg", "--list-secret-keys", "--with-colons", self.fingerprint],
            capture_output=True,
            text=True,
        )
        primary_caps = ""
        subkeys = []
        cur = None
        algo = ""
        primary_bits = ""
        curve = ""
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                primary_caps = parts[11].lower()
                primary_bits = parts[2] if len(parts) > 2 else ""
                algo = parts[3] if len(parts) > 3 else ""
                if len(parts) > 16:
                    curve = parts[16].lower()
            elif parts[0] == "ssb":
                bits = parts[2] if len(parts) > 2 else ""
                cur = {
                    "caps": parts[11].lower(),
                    "fpr": None,
                    "algo": parts[3] if len(parts) > 3 else "",
                    "bits": bits,
                    "curve": parts[16].lower() if len(parts) > 16 else "",
                }
                subkeys.append(cur)
            elif parts[0] == "fpr" and cur is not None and cur["fpr"] is None:
                cur["fpr"] = parts[9]

        try:
            algo_to_check, curve_to_check = _select_import_algo(
                algo, curve, subkeys, self.selected_subkeys
            )
        except ValueError as e:
            self.run_screen(
                LargeIconStatusScreen,
                title="Error",
                status_headline=None,
                text=str(e),
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(BackStackView)

        logger.info(
            "SmartPGP import selection: primary algo=%s bits=%s curve=%s -> %s/%s",
            algo,
            primary_bits,
            curve,
            algo_to_check,
            curve_to_check,
        )

        if algo_to_check not in ("1", "2", "3"):
            curve_map = {
                "nistp256": "p256",
                "nistp384": "p384",
                "nistp521": "p521",
                "brainpoolp256r1": "bp256",
                "brainpoolp384r1": "bp384",
                "brainpoolp512r1": "bp512",
            }
            cmd_suffix = curve_map.get(curve_to_check)
            if not cmd_suffix:
                logger.error(
                    "Unsupported SmartPGP key curve '%s' for algo %s", curve_to_check, algo_to_check
                )
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Error",
                    status_headline=None,
                    text="Unsupported key type",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)
            try:
                from seedsigner.helpers.smartpgp.highlevel import (
                    CardConnectionContext,
                    AdminPINFailed,
                )

                try:
                    ctx = CardConnectionContext()
                    ctx.admin_pin = admin_pin
                    logger.info(
                        "Verifying SmartPGP admin PIN before switching to %s (%s)",
                        cmd_suffix,
                        curve_to_check,
                    )
                    ctx.connect()
                    ctx.verify_admin_pin()
                except AdminPINFailed:
                    logger.warning("SmartPGP card rejected admin PIN during verification")
                    self._stop_loading_screen()
                    self._clear_cached_admin_pin()
                    self.run_screen(
                        LargeIconStatusScreen,
                        title="Error",
                        status_headline=None,
                        text="Incorrect admin PIN",
                        show_back_button=False,
                        button_data=[ButtonOption("Continue")],
                    )
                    return Destination(BackStackView)
                except Exception as e:
                    logger.exception("SmartPGP admin PIN pre-check failed: %s", e)
                    self._stop_loading_screen()
                    self.run_screen(
                        LargeIconStatusScreen,
                        title="Error",
                        status_headline=None,
                        text="Failed to set card key type",
                        show_back_button=False,
                        button_data=[ButtonOption("Continue")],
                    )
                    return Destination(BackStackView)

                logger.info(
                    "Attempting to switch SmartPGP card to %s (%s)", cmd_suffix, curve_to_check
                )
                getattr(ctx, f"cmd_switch_{cmd_suffix}")()
            except AdminPINFailed:
                logger.warning("SmartPGP card rejected admin PIN during switch")
                self._stop_loading_screen()
                self._clear_cached_admin_pin()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Error",
                    status_headline=None,
                    text="Incorrect admin PIN",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)
            except Exception as e:
                logger.exception("SmartPGP switch failed: %s", e)
                self._stop_loading_screen()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Error",
                    status_headline=None,
                    text="Failed to set card key type",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)
            run(["gpgconf", "--reload", "scdaemon"])

        slot_map = {"s": "1", "e": "2", "a": "3"}
        cmds = ["toggle\n"]
        if isinstance(self.selected_subkeys, dict):
            for flag in ("s", "e", "a"):
                fpr = self.selected_subkeys.get(flag)
                if not fpr:
                    continue
                idx = next(
                    (i for i, sk in enumerate(subkeys, start=1) if sk["fpr"] == fpr),
                    None,
                )
                if idx is None:
                    continue
                cmds.append(f"key {idx}\nkeytocard\n{slot_map[flag]}\nkey {idx}\n")
        else:
            used_slots = set()
            sign_idx = next(
                (
                    i
                    for i, sk in enumerate(subkeys, start=1)
                    if "s" in sk["caps"]
                    and (not self.selected_subkeys or sk["fpr"] in self.selected_subkeys)
                ),
                None,
            )
            if sign_idx is not None:
                cmds.append(f"key {sign_idx}\nkeytocard\n1\nkey {sign_idx}\n")
                used_slots.add("1")
            elif "s" in primary_caps:
                cmds.extend(["keytocard\n", "y\n", "1\n"])
                used_slots.add("1")
            for idx, sk in enumerate(subkeys, start=1):
                caps = sk["caps"]
                if idx == sign_idx:
                    continue
                if self.selected_subkeys and sk["fpr"] not in self.selected_subkeys:
                    continue
                slot = next(
                    (
                        slot_map[c]
                        for c in "sea"
                        if c in caps and slot_map[c] not in used_slots
                    ),
                    None,
                )
                if slot:
                    cmds.append(f"key {idx}\nkeytocard\n{slot}\nkey {idx}\n")
                    used_slots.add(slot)
        cmds.append("quit\ny\n")
        edit_commands = "".join(cmds)
        logger.info("GPG edit commands:\n%s", edit_commands)

        self.loading_screen = LoadingScreenThread(
            text="Importing key to card\n\n\n(May take a while)",
        )
        self.loading_screen.start()

        result = run(
            [
                "gpg",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                admin_pin,
                "--command-fd",
                "0",
                "--status-fd",
                "1",
                "--expert",
                "--edit-key",
                self.fingerprint,
            ],
            input=edit_commands,
            capture_output=True,
            text=True,
        )
        logger.info("GPG edit-key import exited with code %s", result.returncode)
        if result.stderr:
            logger.debug("GPG stderr: %s", result.stderr)
        if result.returncode != 0:
            from seedsigner.helpers.smartpgp_import import (
                import_keys_with_smartpgp,
                SmartPGPAdminPinError,
            )

            logger.info(
                "Falling back to SmartPGP importer for %s", self.fingerprint
            )
            try:
                if import_keys_with_smartpgp(
                    self.fingerprint, admin_pin, self.selected_subkeys
                ):
                    self._stop_loading_screen()
                    self.run_screen(
                        LargeIconStatusScreen,
                        title="Success",
                        status_headline=None,
                        text="Key imported to card",
                        show_back_button=False,
                        button_data=[ButtonOption("Continue")],
                    )
                    return Destination(ToolsGPGMenuView)
            except SmartPGPAdminPinError:
                self._stop_loading_screen()
                self._clear_cached_admin_pin()
                self.run_screen(
                    LargeIconStatusScreen,
                    title="Error",
                    status_headline=None,
                    text="Incorrect admin PIN",
                    show_back_button=False,
                    button_data=[ButtonOption("Continue")],
                )
                return Destination(BackStackView)
            except Exception as e:
                logger.exception("SmartPGP fallback failed: %s", e)
            self._stop_loading_screen()
            self.run_screen(
                LargeIconStatusScreen,
                title="Error",
                status_headline=None,
                text="Failed to import key",
                show_back_button=False,
                button_data=[ButtonOption("Continue")],
            )
            return Destination(BackStackView)

        self._stop_loading_screen()
        self.run_screen(
            LargeIconStatusScreen,
            title="Success",
            status_headline=None,
            text="Key imported to card",
            show_back_button=False,
            button_data=[ButtonOption("Continue")],
        )

        return Destination(ToolsGPGMenuView)

class ToolsTextQRTextEntryView(View):
    def __init__(self, textToEncode: str = ""):
        super().__init__()
        self.textToEncode = textToEncode


    def run(self):
        ret_dict = ToolsTextQRTextEntryScreen(textToEncode=self.textToEncode, title=_("Text to Encode")).display()

        try:
            import re
            self.textToEncode = bytes(
                re.sub(r"\\(?!u)", r"\\\\", ret_dict["textToEncode"]),
                encoding="raw_unicode_escape"
            ).decode("unicode_escape")

        except UnicodeError:
            self.textToEncode = ret_dict["textToEncode"]

        if "is_back_button" in ret_dict:
            if len(self.textToEncode) > 0:
                return Destination(
                    ToolsTextQRTextEntryExitDialogView,
                    view_args=dict(text=self.textToEncode),
                    skip_current_view=True
                )
            else:
                return Destination(BackStackView)

        else:
            return Destination(
                ToolsTextQRReviewTextView,
                view_args=dict(text=self.textToEncode),
                skip_current_view=True
            )



class ToolsTextQRTextEntryExitDialogView(View):
    EDIT = ButtonOption("Edit text")
    DISCARD = ButtonOption("Discard text", button_label_color="red")

    def __init__(self, text: str):
        super().__init__()
        self.text = text


    def run(self):
        button_data = [self.EDIT, self.DISCARD]
        
        selected_menu_num = self.run_screen(
            WarningScreen,
            title=_("Discard text?"),
            status_headline=None,
            text=f"Your current text entry will be erased",
            show_back_button=False,
            button_data=button_data
        )

        if button_data[selected_menu_num] == self.EDIT:
            return Destination(
                ToolsTextQRTextEntryView,
                view_args=dict(textToEncode=self.text),
                skip_current_view=True
            )

        elif button_data[selected_menu_num] == self.DISCARD:
            return Destination(BackStackView)


class ToolsTextQRReviewTextView(View):
    def __init__(self, text: str):
        super().__init__()
        self.text = text


    def run(self):
        ENCODE = ButtonOption("Generate QR code")
        EDIT = ButtonOption("Edit text")

        button_data = [ENCODE, EDIT]

        selected_menu_num = self.run_screen(
            ToolsTextQRReviewTextScreen,
            textToEncode=self.text,
            title=_("Text to Encode"),
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        if button_data[selected_menu_num] == ENCODE:
            from seedsigner.helpers.qr import QR
            num_modules = QR().qrsize(data=self.text)
            if num_modules <= 33:
                return Destination(
                    ToolsTextQRTranscribeModePromptView,
                    view_args=dict(text=self.text, num_modules=num_modules)
                )
            else:
                return Destination(
                    ToolsTextQRFullScreenModeView,
                    view_args=dict(text=self.text)
                )

        elif button_data[selected_menu_num] == EDIT:
            return Destination(
                ToolsTextQRTextEntryView,
                view_args=dict(textToEncode=self.text),
                skip_current_view=True
            )



def _text_qr_done_destination(return_to_home: bool = False) -> Destination:
    if return_to_home:
        return Destination(ToolsMenuView, clear_history=True)
    return Destination(ToolsTextQRView, clear_history=True)


class ToolsTextQRTranscribeModePromptView(View):
    def __init__(self, text: str, num_modules: int, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.num_modules = num_modules
        self.return_to_home = return_to_home


    def run(self):
        TRANSCRIBE = ButtonOption("Transcribe mode")
        FULLSCREEN = ButtonOption("FullScreen mode")

        button_data = [TRANSCRIBE, FULLSCREEN]

        selected_menu_num = self.run_screen(
            ToolsTextQRTranscribeModePromptScreen,
            title=_("Transcribe Mode ?"),
            is_button_text_centered=False,
            button_data=button_data
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_num] == TRANSCRIBE:
            return Destination(
                ToolsTextQRTranscribeModeView,
                view_args=dict(text=self.text, num_modules=self.num_modules, return_to_home=self.return_to_home)
            )

        elif button_data[selected_menu_num] == FULLSCREEN:
            return Destination(
                ToolsTextQRFullScreenModeView,
                view_args=dict(text=self.text, return_to_home=self.return_to_home)
            )



class ToolsTextQRTranscribeModeView(View):
    def __init__(self, text: str, num_modules: int, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.num_modules = num_modules
        self.return_to_home = return_to_home


    def run(self):
        ret = ToolsTranscribeTextQRWholeQRScreen(
            qr_data=self.text,
            num_modules=self.num_modules
        ).display()

        if ret == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        else:
            return Destination(
                ToolsTranscribeTextQRZoomedInView,
                view_args=dict(text=self.text, num_modules=self.num_modules, return_to_home=self.return_to_home)
            )



class ToolsTextQRFullScreenModeView(View):
    def __init__(self, text: str, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.return_to_home = return_to_home

    def run(self):
        from seedsigner.gui.screens.screen import QRDisplayScreen
        encoder_args = dict(data=self.text)
        e = GenericStaticQrEncoder(**encoder_args)
        QRDisplayScreen(qr_encoder=e).display()
        return _text_qr_done_destination(self.return_to_home)



class ToolsTranscribeTextQRZoomedInView(View):
    def __init__(self, text: str, num_modules: int, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.num_modules = num_modules
        self.return_to_home = return_to_home


    def run(self):

        ToolsTranscribeTextQRZoomedInScreen(
            qr_data=self.text,
            num_modules=self.num_modules
        ).display()

        return Destination(
            ToolsTranscribeTextQRConfirmQRPromptView,
            view_args=dict(text=self.text, return_to_home=self.return_to_home)
        )



class ToolsTranscribeTextQRConfirmQRPromptView(View):
    def __init__(self, text: str, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.return_to_home = return_to_home


    def run(self):
        SCAN = ButtonOption("Confirm text QR code")
        DONE = ButtonOption("Done")
        button_data = [SCAN, DONE]

        selected_menu_option = ToolsTranscribeTextQRConfirmQRPromptScreen(
            title=_("Confirm Text QR ?"),
            button_data=button_data
        ).display()

        if selected_menu_option == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)

        elif button_data[selected_menu_option] == SCAN:
            return Destination(ToolsTranscribeTextQRConfirmScanView, view_args=dict(text=self.text, return_to_home=self.return_to_home))

        elif button_data[selected_menu_option] == DONE:
            return _text_qr_done_destination(self.return_to_home)



class ToolsTranscribeTextQRConfirmScanView(View):
    def __init__(self, text: str, return_to_home: bool = False):
        super().__init__()
        self.text = text
        self.return_to_home = return_to_home


    def run(self):
        decoder = DecodeQR(is_text=True)
        ScanScreen(
            instructions_text=_("Scan text QR code"),
            decoder=decoder
        ).display()

        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)

        if decoder.is_complete:
            if decoder.get_text() != self.text:
                DireWarningScreen(
                    title=_("Confirm Text QR Code"),
                    status_headline=_("Error!"),
                    text=_("Your transcribed text QR code does not match your original text!"),
                    show_back_button=False,
                    button_data=[ButtonOption("Review text QR code")],
                ).display()

                return Destination(BackStackView)
            
            else:
                LargeIconStatusScreen(
                    title=_("Confirm Text QR Code"),
                    status_headline=_("Success!"),
                    text=_("Your transcribed text QR code successfully scanned and yielded the same text."),
                    show_back_button=False,
                    button_data=[ButtonOption("OK")],
                ).display()

                return _text_qr_done_destination(self.return_to_home)

        else:
            DireWarningScreen(
                title=_("Confirm Text QR"),
                status_headline=_("Error!"),
                text=_("Your transcribed text QR code could not be read!"),
                show_back_button=False,
                button_data=[ButtonOption("Review text QR code")],
            ).display()

            return Destination(BackStackView)



class ToolsTextQRScanQRCodeView(View):
    def run(self):

        decoder = DecodeQR(is_text=True)
        ScanScreen(decoder=decoder, instructions_text=_("Scan text QR code")).display()

        self.controller.reset_screensaver_timeout()
        time.sleep(0.1)

        if decoder.is_complete:
            return Destination(
                ToolsTextQRReviewTextView2,
                view_args=dict(text=decoder.get_text()),
                skip_current_view=True
            )

        elif decoder.is_nonUTF8:
            DireWarningScreen(
                title=_("Error!"),
                show_back_button=False,
                status_headline="Invalid Text QR Code",
                text=f"Non UTF-8 data detected."
            ).display()
            return Destination(BackStackView)

        else:
            return Destination(BackStackView)



class ToolsTextQRReviewTextView2(View):
    def __init__(self, text: str):
        super().__init__()
        self.text = text


    def run(self):
        EDIT = ButtonOption("Edit & Generate QR code")
        DONE = ButtonOption("Done")

        button_data = [EDIT, DONE]

        selected_menu_num = self.run_screen(
            ToolsTextQRReviewTextScreen,
            textToEncode=self.text,
            title=_("Decoded Text"),
            button_data=button_data,
            show_back_button=False,
        )

        if button_data[selected_menu_num] == EDIT:
            return Destination(
                ToolsTextQRTextEntryView,
                view_args=dict(textToEncode=self.text)
            )

        elif button_data[selected_menu_num] == DONE:
            return Destination(BackStackView)

