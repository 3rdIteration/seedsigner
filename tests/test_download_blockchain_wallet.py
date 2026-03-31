"""Tests for extract-scripts/download_blockchain_wallet.py.

Uses ``unittest.mock`` to stub out HTTP calls so the tests run without
network access and complete quickly.
"""

import json
import sys
import types
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest import mock

import pytest

# Import the script as a module from the extract-scripts directory.
_EXTRACT_SCRIPTS_DIR = str(Path(__file__).resolve().parents[1] / "extract-scripts")
if _EXTRACT_SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _EXTRACT_SCRIPTS_DIR)

import download_blockchain_wallet as dw  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(body: dict | str, code: int = 200) -> mock.MagicMock:
    """Create a mock HTTP response object."""
    raw = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body.encode("utf-8")
    resp = mock.MagicMock()
    resp.read.return_value = raw
    resp.status = code
    resp.__enter__ = mock.MagicMock(return_value=resp)
    resp.__exit__ = mock.MagicMock(return_value=False)
    return resp


def _http_error(body: dict | str, code: int = 500) -> urllib.error.HTTPError:
    """Create an HTTPError whose .read() returns *body*."""
    raw = json.dumps(body).encode("utf-8") if isinstance(body, dict) else body.encode("utf-8")
    err = urllib.error.HTTPError(
        url="https://blockchain.info/test",
        code=code,
        msg="error",
        hdrs={},
        fp=BytesIO(raw),
    )
    return err


# ---------------------------------------------------------------------------
# UUID validation
# ---------------------------------------------------------------------------

class TestGuidValidation:
    def test_valid_guid(self):
        assert dw._GUID_RE.match("1e8ecc37-c6dc-4cad-a574-af8490d40a91")

    def test_valid_guid_uppercase(self):
        assert dw._GUID_RE.match("1E8ECC37-C6DC-4CAD-A574-AF8490D40A91")

    def test_invalid_guid(self):
        assert not dw._GUID_RE.match("not-a-uuid")

    def test_empty_string(self):
        assert not dw._GUID_RE.match("")


# ---------------------------------------------------------------------------
# BlockchainSession
# ---------------------------------------------------------------------------

class TestBlockchainSession:
    def test_read_error_body_json(self):
        body = {"initial_error": "bad request"}
        err = _http_error(body, code=400)
        result = dw.BlockchainSession.read_error_body(err)
        assert result == body

    def test_read_error_body_plain_text(self):
        err = _http_error("plain text", code=500)
        result = dw.BlockchainSession.read_error_body(err)
        assert result == "plain text"


# ---------------------------------------------------------------------------
# get_session_token
# ---------------------------------------------------------------------------

class TestGetSessionToken:
    def test_success(self):
        session = dw.BlockchainSession()
        with mock.patch.object(session, "post_json", return_value={"token": "abc-123"}):
            assert dw.get_session_token(session) == "abc-123"

    def test_missing_token_raises(self):
        session = dw.BlockchainSession()
        with mock.patch.object(session, "post_json", return_value={}):
            with pytest.raises(RuntimeError, match="Unexpected session response"):
                dw.get_session_token(session)


# ---------------------------------------------------------------------------
# fetch_wallet
# ---------------------------------------------------------------------------

class TestFetchWallet:
    def test_success_with_inner_payload(self):
        inner = json.dumps({"pbkdf2_iterations": 5000, "version": 3, "payload": "ENCRYPTED_DATA"})
        resp = {"auth_type": 0, "payload": inner}
        session = dw.BlockchainSession()
        with mock.patch.object(session, "get_json", return_value=resp):
            result = dw.fetch_wallet(session, "tok", "guid")
        assert result["status"] == "success"
        assert result["payload"] == "ENCRYPTED_DATA"

    def test_success_plain_payload(self):
        resp = {"auth_type": 0, "payload": "JUST_A_STRING"}
        session = dw.BlockchainSession()
        with mock.patch.object(session, "get_json", return_value=resp):
            result = dw.fetch_wallet(session, "tok", "guid")
        assert result["status"] == "success"
        assert result["payload"] == "JUST_A_STRING"

    def test_2fa_required(self):
        resp = {"auth_type": 4}
        session = dw.BlockchainSession()
        with mock.patch.object(session, "get_json", return_value=resp):
            result = dw.fetch_wallet(session, "tok", "guid")
        assert result["status"] == "2fa"
        assert result["auth_type"] == 4

    def test_email_auth_required(self):
        body = {"initial_error": "Authorization Required. Check your email."}
        session = dw.BlockchainSession()
        with mock.patch.object(session, "get_json", side_effect=_http_error(body, 403)):
            result = dw.fetch_wallet(session, "tok", "guid")
        assert result["status"] == "email"

    def test_unknown_wallet(self):
        body = {"initial_error": "Unknown Wallet Identifier"}
        session = dw.BlockchainSession()
        with mock.patch.object(session, "get_json", side_effect=_http_error(body, 500)):
            result = dw.fetch_wallet(session, "tok", "guid")
        assert result["status"] == "error"
        assert "does not exist" in result["message"]

    def test_no_payload_field(self):
        resp = {"auth_type": 0}
        session = dw.BlockchainSession()
        with mock.patch.object(session, "get_json", return_value=resp):
            result = dw.fetch_wallet(session, "tok", "guid")
        assert result["status"] == "error"


# ---------------------------------------------------------------------------
# fetch_wallet_2fa
# ---------------------------------------------------------------------------

class TestFetchWallet2fa:
    def test_success(self):
        resp = {"payload": "ENCRYPTED_DATA"}
        session = dw.BlockchainSession()
        with mock.patch.object(session, "post_json", return_value=resp):
            result = dw.fetch_wallet_2fa(session, "tok", "guid", "123456")
        assert result["status"] == "success"
        assert result["payload"] == "ENCRYPTED_DATA"

    def test_error_locked(self):
        body = {"initial_error": "Account locked."}
        session = dw.BlockchainSession()
        with mock.patch.object(session, "post_json", side_effect=_http_error(body, 403)):
            result = dw.fetch_wallet_2fa(session, "tok", "guid", "000000")
        assert result["status"] == "error"
        assert result["is_locked"] is True

    def test_error_with_attempts_left(self):
        body = "3 login attempts left"
        session = dw.BlockchainSession()
        with mock.patch.object(session, "post_json", side_effect=_http_error(body, 403)):
            result = dw.fetch_wallet_2fa(session, "tok", "guid", "000000")
        assert result["status"] == "error"
        assert result["is_locked"] is False


# ---------------------------------------------------------------------------
# poll_for_email_auth
# ---------------------------------------------------------------------------

class TestPollForEmailAuth:
    def test_poll_success(self):
        session = dw.BlockchainSession()
        responses = [{"guid": None}, {"guid": None}, {"guid": "found-it"}]
        with mock.patch.object(session, "get_json", side_effect=responses):
            with mock.patch("download_blockchain_wallet.time.sleep"):
                dw.poll_for_email_auth(session, "tok", timeout=60)

    def test_poll_timeout(self):
        session = dw.BlockchainSession()
        with mock.patch.object(session, "get_json", return_value={"guid": None}):
            with mock.patch("download_blockchain_wallet.time.sleep"):
                with mock.patch("download_blockchain_wallet.time.monotonic", side_effect=[0, 0, 999]):
                    with pytest.raises(TimeoutError):
                        dw.poll_for_email_auth(session, "tok", timeout=10)


# ---------------------------------------------------------------------------
# download_wallet (integration of all steps)
# ---------------------------------------------------------------------------

class TestDownloadWallet:
    def test_simple_flow(self):
        inner = json.dumps({"payload": "THE_PAYLOAD"})
        session_resp = {"token": "session-tok"}
        wallet_resp = {"auth_type": 0, "payload": inner}

        with mock.patch("download_blockchain_wallet.BlockchainSession") as MockSession:
            inst = MockSession.return_value
            inst.post_json.return_value = session_resp
            inst.get_json.return_value = wallet_resp

            payload = dw.download_wallet("00000000-0000-0000-0000-000000000000")
            assert payload == "THE_PAYLOAD"


# ---------------------------------------------------------------------------
# CLI: main
# ---------------------------------------------------------------------------

class TestMain:
    def test_invalid_uuid_exits(self):
        with pytest.raises(SystemExit) as exc_info:
            with mock.patch("sys.argv", ["prog", "bad-uuid"]):
                dw.main()
        assert exc_info.value.code == 1

    def test_no_save_prints(self, capsys):
        inner = json.dumps({"payload": "PAYLOAD_DATA"})

        with mock.patch("download_blockchain_wallet.BlockchainSession") as MockSession:
            inst = MockSession.return_value
            inst.post_json.return_value = {"token": "tok"}
            inst.get_json.return_value = {"auth_type": 0, "payload": inner}
            with mock.patch("sys.argv", ["prog", "--no-save", "00000000-0000-0000-0000-000000000000"]):
                dw.main()

        captured = capsys.readouterr()
        assert "PAYLOAD_DATA" in captured.out

    def test_save_to_file(self, tmp_path):
        inner = json.dumps({"payload": "SAVED_DATA"})
        output_file = tmp_path / "out.aes.json"

        with mock.patch("download_blockchain_wallet.BlockchainSession") as MockSession:
            inst = MockSession.return_value
            inst.post_json.return_value = {"token": "tok"}
            inst.get_json.return_value = {"auth_type": 0, "payload": inner}
            with mock.patch("sys.argv", ["prog", "-o", str(output_file), "00000000-0000-0000-0000-000000000000"]):
                dw.main()

        assert output_file.read_text() == "SAVED_DATA"
