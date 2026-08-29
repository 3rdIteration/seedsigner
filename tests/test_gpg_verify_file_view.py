"""View-level tests for ToolsGPGVerifyFileView signature verification."""
import base  # noqa: F401 -- ensure hardware mocks
from types import SimpleNamespace

import pytest

from seedsigner.gui.screens import (
    RET_CODE__BACK_BUTTON,
    ButtonListScreen,
    LargeIconStatusScreen,
    WarningScreen,
)
# Import tools_views first: it establishes the module load order that breaks
# the gpg_views <-> password_generator_views circular import.
from seedsigner.views import tools_views  # noqa: F401
import seedsigner.views.gpg_views as gpg_views
from seedsigner.views.gpg_views import ToolsGPGVerifyFileView, _parse_gpg_verify_status


QLRD_FPR = "B4281DDDFBBD207BFA4113138974C90299326322"  # Krux
EMZY_FPR = "9EDAFF80E080659604F4A76B2EBB056FD847F8A7"  # Electrum + Bitcoin Core
AVACHOW_FPR = "152812300785C96444D3334D17565732E08E5E41"  # Bitcoin Core
SPARROW_FPR = "D4D0D3202FC06849A257B38DE94618334C674B40"  # Sparrow
UNKNOWN_FPR = "1111111111111111111111111111111111111111"


def _validsig(fpr):
    return f"[GNUPG:] VALIDSIG {fpr} 2026-08-15 14:12:48 +0000 1789000000 0 10 1 1\n"


class _FakeLoadingScreen:
    def __init__(self, text=None):
        pass

    def start(self):
        pass

    def stop(self):
        pass


def _make_view(monkeypatch, tmp_path, files):
    """Build a ToolsGPGVerifyFileView with hardware/gpg dependencies stubbed."""
    for name in files:
        (tmp_path / name).write_bytes(b"test data")

    monkeypatch.setattr(
        gpg_views, "resolve_microsd_images_dir", lambda: tmp_path
    )
    monkeypatch.setattr(
        "seedsigner.gui.screens.screen.LoadingScreenThread", _FakeLoadingScreen
    )

    view = object.__new__(ToolsGPGVerifyFileView)
    view.controller = SimpleNamespace(
        storage=SimpleNamespace(seeds=[]),
        gpg_keys_imported=True,
    )
    return view


def _make_fake_run_screen(captured, select_index=None):
    def fake_run_screen(self, screen, *args, **kwargs):
        captured.append({"screen": screen, "kwargs": kwargs})
        if screen is ButtonListScreen and select_index is not None:
            return select_index
        # Default: press Done/OK when present, else the first button.
        for i, button in enumerate(kwargs.get("button_data") or []):
            label = (
                getattr(button, "button_label", None)
                or getattr(button, "text", None)
                or str(button)
            )
            if label in ("Done", "OK"):
                return i
        return 0

    return fake_run_screen


def _run_view(monkeypatch, tmp_path, files, gpg_stdout, gpg_stderr="", select_index=None):
    captured = []
    view = _make_view(monkeypatch, tmp_path, files)
    monkeypatch.setattr(
        ToolsGPGVerifyFileView, "run_screen",
        _make_fake_run_screen(captured, select_index),
    )

    gpg_calls = []

    def fake_subprocess_run(cmd, **kwargs):
        gpg_calls.append(cmd)
        return SimpleNamespace(stdout=gpg_stdout, stderr=gpg_stderr)

    monkeypatch.setattr("subprocess.run", fake_subprocess_run)

    view.run()
    return captured, gpg_calls


def _screens_of_type(captured, screen_cls):
    return [c for c in captured if c["screen"] is screen_cls]


class TestTrustedSigner:
    def test_known_project_trusted_key_shows_success(self, monkeypatch, tmp_path):
        captured, gpg_calls = _run_view(
            monkeypatch, tmp_path,
            ["krux-v26.08.0.zip", "krux-v26.08.0.zip.sig"],
            gpg_stdout=_validsig(QLRD_FPR),
        )

        # Signature and data file passed to gpg with status-fd enabled.
        assert gpg_calls[0][:3] == ["gpg", "--status-fd=1", "--verify"]
        assert "krux-v26.08.0.zip.sig" in gpg_calls[0]
        assert "krux-v26.08.0.zip" in gpg_calls[0]

        # No warning screen; success shows the project and full fingerprint.
        assert _screens_of_type(captured, WarningScreen) == []
        successes = _screens_of_type(captured, LargeIconStatusScreen)
        assert len(successes) == 1
        kwargs = successes[0]["kwargs"]
        assert kwargs["status_headline"] == "Krux Firmware"
        assert "B428 1DDD FBBD 207B FA41 1313 8974 C902 9932 6322" in kwargs["text"]

    def test_multi_sig_file_trusted_if_any_signer_is(self, monkeypatch, tmp_path):
        # Bitcoin Core SHA256SUMS is signed by many maintainers; one trusted
        # signer (Ava Chow) plus an unknown key still counts as trusted.
        captured, _ = _run_view(
            monkeypatch, tmp_path,
            ["SHA256SUMS", "SHA256SUMS.asc"],
            gpg_stdout=_validsig(AVACHOW_FPR) + _validsig(UNKNOWN_FPR),
            select_index=1,  # select SHA256SUMS (the data file)
        )

        assert _screens_of_type(captured, WarningScreen) == []
        successes = _screens_of_type(captured, LargeIconStatusScreen)
        assert successes[0]["kwargs"]["status_headline"] == "Bitcoin Core"


class TestUntrustedSigner:
    def test_cross_project_key_shows_blocking_warning_then_success(
        self, monkeypatch, tmp_path
    ):
        # Sparrow's key "signing" a Liana file.
        captured, _ = _run_view(
            monkeypatch, tmp_path,
            ["liana-15.0.exe", "liana-15.0.exe.sig"],
            gpg_stdout=_validsig(SPARROW_FPR),
        )

        warnings = _screens_of_type(captured, WarningScreen)
        assert len(warnings) == 1
        text = warnings[0]["kwargs"]["text"]
        assert "Liana Wallet" in text
        assert "Sparrow Wallet" in text
        assert any(
            getattr(b, "button_label", None) == "I Understand"
            for b in warnings[0]["kwargs"]["button_data"]
        )

        # After acknowledging, the success screen still shows the key.
        successes = _screens_of_type(captured, LargeIconStatusScreen)
        assert len(successes) == 1
        assert successes[0]["kwargs"]["status_headline"] is None
        assert "D4D0 D320" in successes[0]["kwargs"]["text"]

    def test_unknown_key_for_known_project_warns(self, monkeypatch, tmp_path):
        captured, _ = _run_view(
            monkeypatch, tmp_path,
            ["krux-v26.08.0.zip", "krux-v26.08.0.zip.sig"],
            gpg_stdout=_validsig(UNKNOWN_FPR),
        )

        warnings = _screens_of_type(captured, WarningScreen)
        assert len(warnings) == 1
        text = warnings[0]["kwargs"]["text"]
        assert "unknown key" in text
        assert "Krux Firmware" in text

    def test_unknown_project_and_unknown_key_is_neutral(self, monkeypatch, tmp_path):
        captured, _ = _run_view(
            monkeypatch, tmp_path,
            ["mystery-app-1.0.zip", "mystery-app-1.0.zip.sig"],
            gpg_stdout=_validsig(UNKNOWN_FPR),
        )

        # No warning; success screen without a project headline.
        assert _screens_of_type(captured, WarningScreen) == []
        successes = _screens_of_type(captured, LargeIconStatusScreen)
        assert len(successes) == 1
        assert successes[0]["kwargs"]["status_headline"] is None

    def test_ambiguous_manifest_with_untracked_signer_is_neutral(
        self, monkeypatch, tmp_path
    ):
        # Bare SHA256SUMS matches both Specter and Bitcoin Core; an untracked
        # signer cannot disambiguate, so no project attribution or warning.
        captured, _ = _run_view(
            monkeypatch, tmp_path,
            ["SHA256SUMS", "SHA256SUMS.asc"],
            gpg_stdout=_validsig(UNKNOWN_FPR),
            select_index=1,
        )

        assert _screens_of_type(captured, WarningScreen) == []
        successes = _screens_of_type(captured, LargeIconStatusScreen)
        assert successes[0]["kwargs"]["status_headline"] is None


class TestFailurePaths:
    def test_no_pubkey_shows_error(self, monkeypatch, tmp_path):
        captured, _ = _run_view(
            monkeypatch, tmp_path,
            ["krux-v26.08.0.zip", "krux-v26.08.0.zip.sig"],
            gpg_stdout="[GNUPG:] NO_PUBKEY ABCDEF0123456789\n",
        )

        errors = _screens_of_type(captured, WarningScreen)
        assert len(errors) == 1
        assert "Signing key not found" in errors[0]["kwargs"]["text"]
        assert _screens_of_type(captured, LargeIconStatusScreen) == []

    def test_bad_signature_shows_error(self, monkeypatch, tmp_path):
        captured, _ = _run_view(
            monkeypatch, tmp_path,
            ["krux-v26.08.0.zip", "krux-v26.08.0.zip.sig"],
            gpg_stdout=f"[GNUPG:] ERRSIG {QLRD_FPR} 1 1 0\n",
        )

        errors = _screens_of_type(captured, WarningScreen)
        assert len(errors) == 1
        assert "Invalid Signature" in errors[0]["kwargs"]["text"]

    def test_no_signature_found_shows_error(self, monkeypatch, tmp_path):
        captured, _ = _run_view(
            monkeypatch, tmp_path,
            ["krux-v26.08.0.zip"],
            gpg_stdout="",
            gpg_stderr="gpg: no signature found\n",
        )

        errors = _screens_of_type(captured, WarningScreen)
        assert len(errors) == 1
        assert "No GPG signature found" in errors[0]["kwargs"]["text"]


class TestSignaturePairing:
    def test_asc_signature_is_used_when_no_sig_exists(self, monkeypatch, tmp_path):
        _, gpg_calls = _run_view(
            monkeypatch, tmp_path,
            ["liana-15.0-shasums.txt", "liana-15.0-shasums.txt.asc"],
            gpg_stdout=_validsig("5B63F3B97699C7EEF3B040B19B7F629A53E77B83"),
            select_index=0,  # select the data file
        )

        assert "liana-15.0-shasums.txt.asc" in gpg_calls[0]
        assert "liana-15.0-shasums.txt" in gpg_calls[0]

    def test_sig_preferred_over_asc(self, monkeypatch, tmp_path):
        _, gpg_calls = _run_view(
            monkeypatch, tmp_path,
            ["krux-v26.08.0.zip", "krux-v26.08.0.zip.sig", "krux-v26.08.0.zip.asc"],
            gpg_stdout=_validsig(QLRD_FPR),
            select_index=0,  # select the data file
        )

        assert "krux-v26.08.0.zip.sig" in gpg_calls[0]
        assert "krux-v26.08.0.zip.asc" not in gpg_calls[0]

    def test_selected_sig_without_data_file_errors_without_gpg(
        self, monkeypatch, tmp_path
    ):
        captured, gpg_calls = _run_view(
            monkeypatch, tmp_path,
            ["orphan-file.sig"],
            gpg_stdout="",
        )

        assert gpg_calls == []
        errors = _screens_of_type(captured, WarningScreen)
        assert len(errors) == 1
        assert "corresponding file" in errors[0]["kwargs"]["text"]

    def test_clearsigned_file_verified_directly(self, monkeypatch, tmp_path):
        # COLDCARD's signatures.txt is clearsigned: no detached sig alongside.
        _, gpg_calls = _run_view(
            monkeypatch, tmp_path,
            ["signatures.txt"],
            gpg_stdout=_validsig("4589779ADFC14F3327534EA8A3A31BAD5A2A5B10"),
        )

        assert gpg_calls[0][-1] == "signatures.txt"
        assert len(gpg_calls[0]) == 4  # gpg --status-fd=1 --verify signatures.txt


class TestParser:
    def test_parse_collects_multiple_validsig(self):
        result = _parse_gpg_verify_status(
            _validsig(QLRD_FPR) + _validsig(AVACHOW_FPR), ""
        )
        assert result["valid_fprs"] == [QLRD_FPR, AVACHOW_FPR]
        assert not result["bad_sig"]
        assert not result["no_pubkey"]

    def test_parse_ignores_non_status_lines(self):
        result = _parse_gpg_verify_status(
            "gpg: assuming signed data in foo\n[GNUPG:] VALIDSIG " + QLRD_FPR + "\n",
            "",
        )
        assert result["valid_fprs"] == [QLRD_FPR]

    def test_parse_normalizes_to_uppercase(self):
        result = _parse_gpg_verify_status(
            f"[GNUPG:] VALIDSIG {QLRD_FPR.lower()} 2026-01-01\n", ""
        )
        assert result["valid_fprs"] == [QLRD_FPR]
