#!/usr/bin/env python3
"""Download encrypted wallet payload (wallet.aes.json) from Blockchain.com.

This script replaces the old download-blockchain-wallet.py that stopped
working when Blockchain.com added Cloudflare DDOS protections.  It uses
only the Python standard library (no third-party packages required).

Usage:
    python3 download_blockchain_wallet.py [WALLET_ID]

If WALLET_ID is omitted you will be prompted to enter it.  The script
walks through the same authentication flow that the Blockchain.com web
app uses:

    1. Obtain a session token.
    2. Request the wallet payload (may trigger an email-authorisation
       step or require a 2FA code).
    3. Write the encrypted payload to ``wallet.aes.json`` in the current
       directory (or print it to stdout with ``--no-save``).
"""

from __future__ import annotations

import argparse
import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Blockchain.com public API code (same one used by the web wallet).
API_CODE = "1770d5d9-bcea-4d28-ad21-6cbd5be018a8"
BASE_URL = "https://blockchain.info"

# Headers that mimic the Blockchain.com web-app login page.  Including
# Origin and Referer from login.blockchain.com is necessary to pass
# through Cloudflare's DDOS protections on the wallet endpoints.
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json",
    "Origin": "https://login.blockchain.com",
    "Referer": "https://login.blockchain.com/",
}

# Regex for a v4 UUID (wallet identifier format).
_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

_2FA_TYPE_NAMES = {
    1: "Yubikey",
    4: "Google Authenticator",
    5: "SMS",
}


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


class BlockchainSession:
    """Wraps an HTTP opener with a cookie jar so that Cloudflare cookies
    obtained during the ``/sessions`` call are automatically forwarded
    to all subsequent requests."""

    def __init__(self) -> None:
        self._cookie_jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cookie_jar),
        )

    def _request(
        self,
        url: str,
        *,
        method: str = "GET",
        data: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict:
        req = urllib.request.Request(url, data=data, method=method)
        for key, value in _BROWSER_HEADERS.items():
            req.add_header(key, value)
        for key, value in (extra_headers or {}).items():
            req.add_header(key, value)
        with self._opener.open(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def post_json(
        self,
        url: str,
        form: dict | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict:
        encoded = urllib.parse.urlencode(form).encode("utf-8") if form else b""
        return self._request(url, method="POST", data=encoded, extra_headers=extra_headers)

    def get_json(
        self,
        url: str,
        extra_headers: dict[str, str] | None = None,
    ) -> dict:
        return self._request(url, method="GET", extra_headers=extra_headers)

    @staticmethod
    def read_error_body(exc: urllib.error.HTTPError) -> dict | str:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return raw


# ---------------------------------------------------------------------------
# Blockchain.com API interaction
# ---------------------------------------------------------------------------


def get_session_token(session: BlockchainSession) -> str:
    """Obtain a fresh session token from Blockchain.com."""
    data = session.post_json(f"{BASE_URL}/sessions")
    token = data.get("token")
    if not token:
        raise RuntimeError(f"Unexpected session response: {data}")
    return token


def fetch_wallet(session: BlockchainSession, token: str, wallet_id: str) -> dict:
    """Request the wallet payload.

    Returns a dict with a ``status`` key:

    * ``success``  – ``payload`` contains the encrypted wallet string.
    * ``email``    – email authorisation is required before retrying.
    * ``2fa``      – ``auth_type`` (int) indicates which 2FA method is
                     needed.
    * ``error``    – ``message`` describes what went wrong.
    """
    url = (
        f"{BASE_URL}/wallet/{wallet_id}"
        f"?format=json&api_code={API_CODE}"
    )
    auth = {"Authorization": f"Bearer {token}"}
    try:
        data = session.get_json(url, extra_headers=auth)
    except urllib.error.HTTPError as exc:
        body = session.read_error_body(exc)
        if isinstance(body, dict):
            initial_error = body.get("initial_error", "")
        else:
            initial_error = body
        lower = initial_error.lower()
        if "unknown wallet identifier" in lower:
            return {"status": "error", "message": "Wallet ID does not exist."}
        if "authorization required" in lower and "email" in lower:
            return {"status": "email"}
        return {"status": "error", "message": initial_error or str(exc)}

    # The response may indicate 2FA is required (auth_type > 0).
    if data.get("auth_type"):
        return {"status": "2fa", "auth_type": data["auth_type"]}

    # Otherwise the payload should be present.
    payload_str = data.get("payload")
    if payload_str is None:
        return {"status": "error", "message": f"Unexpected wallet response: {data}"}
    # payload_str is itself a JSON string; extract the inner "payload" field.
    try:
        inner = json.loads(payload_str)
        return {"status": "success", "payload": inner.get("payload", payload_str)}
    except (json.JSONDecodeError, ValueError):
        return {"status": "success", "payload": payload_str}


def poll_for_email_auth(
    session: BlockchainSession, token: str, timeout: int = 300
) -> None:
    """Block until the user authorises access via email (or *timeout* seconds
    elapse)."""
    url = (
        f"{BASE_URL}/wallet/poll-for-session-guid"
        f"?format=json&api_code={API_CODE}"
    )
    auth = {"Authorization": f"Bearer {token}"}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data = session.get_json(url, extra_headers=auth)
        except urllib.error.HTTPError:
            time.sleep(3)
            continue
        if data.get("guid"):
            return
        time.sleep(3)
    raise TimeoutError("Timed out waiting for email authorisation.")


def fetch_wallet_2fa(
    session: BlockchainSession, token: str, wallet_id: str, code_2fa: str
) -> dict:
    """Submit a 2FA code and retrieve the wallet payload.

    Returns a dict with ``status`` of ``success`` or ``error``.
    """
    url = f"{BASE_URL}/wallet"
    auth = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    form_data = {
        "api_code": API_CODE,
        "guid": wallet_id,
        "length": str(len(code_2fa)),
        "method": "get-wallet",
        "payload": code_2fa,
    }
    try:
        data = session.post_json(url, form=form_data, extra_headers=auth)
    except urllib.error.HTTPError as exc:
        body = session.read_error_body(exc)
        if isinstance(body, dict):
            msg = body.get("initial_error", str(body))
        elif isinstance(body, str):
            msg = body
        else:
            msg = str(body)
        is_locked = "login attempts left" not in msg.lower()
        return {"status": "error", "message": msg, "is_locked": is_locked}
    payload = data.get("payload")
    if payload is not None:
        return {"status": "success", "payload": payload}
    return {"status": "error", "message": f"Unexpected 2FA response: {data}"}


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------


def download_wallet(wallet_id: str) -> str:
    """Run the full download flow and return the encrypted payload string."""
    http_session = BlockchainSession()

    print("Obtaining session token...")
    token = get_session_token(http_session)
    print("Session token obtained.")

    print(f"Requesting wallet {wallet_id}...")
    result = fetch_wallet(http_session, token, wallet_id)

    # --- email authorisation ---
    if result["status"] == "email":
        print(
            "\nEmail authorisation required.\n"
            "Please check your email and approve the login request."
        )
        poll_for_email_auth(http_session, token)
        print("Email authorisation received!")
        result = fetch_wallet(http_session, token, wallet_id)

    # --- 2FA ---
    if result["status"] == "2fa":
        auth_type = result["auth_type"]
        auth_name = _2FA_TYPE_NAMES.get(auth_type, f"Unknown (type {auth_type})")
        while True:
            code = input(f"Enter your {auth_name} 2FA code: ").strip()
            if not code:
                print("2FA code is required.")
                continue
            result = fetch_wallet_2fa(http_session, token, wallet_id, code)
            if result["status"] == "success":
                break
            print(f"Error: {result['message']}")
            if result.get("is_locked"):
                raise RuntimeError(
                    "Wallet is locked due to too many failed 2FA attempts. "
                    "Please try again later."
                )

    # --- final check ---
    if result["status"] == "error":
        raise RuntimeError(result["message"])

    if result["status"] != "success":
        raise RuntimeError(f"Unexpected result: {result}")

    return result["payload"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download encrypted wallet payload from Blockchain.com"
    )
    parser.add_argument(
        "wallet_id",
        nargs="?",
        default=None,
        help="Blockchain.com Wallet ID (UUID format, e.g. 1e8ecc37-c6dc-4cad-a574-af8490d40a91)",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        default=False,
        help="Print the payload to stdout instead of saving to wallet.aes.json",
    )
    parser.add_argument(
        "-o", "--output",
        default="wallet.aes.json",
        help="Output file name (default: wallet.aes.json)",
    )
    args = parser.parse_args()

    wallet_id = args.wallet_id
    if not wallet_id:
        wallet_id = input("Enter your Blockchain.com Wallet ID: ").strip()

    if not _GUID_RE.match(wallet_id):
        print(
            f"Error: '{wallet_id}' does not look like a valid Wallet ID "
            "(expected UUID format, e.g. 1e8ecc37-c6dc-4cad-a574-af8490d40a91).",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        payload = download_wallet(wallet_id)
    except (RuntimeError, TimeoutError) as exc:
        print(f"\nError: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)

    if args.no_save:
        print("\nEncrypted Wallet Payload:\n")
        print(payload)
    else:
        output_path = args.output
        with open(output_path, "w") as f:
            f.write(str(payload))
        print(f"\nSuccess! Encrypted wallet payload saved to {output_path}")


if __name__ == "__main__":
    main()
