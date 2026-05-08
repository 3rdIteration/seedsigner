#!/usr/bin/env python3
"""End-to-end smoke test for the Keycard ETH stack against a physical card.

Run this on the Pi (or any host with PC/SC + a Keycard reader plugged in)
to validate that the full pipeline works on real hardware.  Nothing here
needs the SeedSigner GUI — it talks straight to the Python helpers.

Usage::

    python scripts/keycard_smoke_test.py \\
        --password 'YourPairingPassword' --pin 123456

    # With sign-verify round-trip (uses VERIFY_PIN):
    python scripts/keycard_smoke_test.py \\
        --password ... --pin 123456 --sign

    # Skip the unpair-on-exit step:
    python scripts/keycard_smoke_test.py --password ... --pin 123456 --keep-pairing

The exit code is 0 only if every step passed.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import traceback

# Make the SeedSigner sources importable regardless of where the script is run from.
_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.normpath(os.path.join(_HERE, "..", "src"))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def _step(label: str) -> None:
    print(f"\n=== {label} ===")


def _ok(message: str = "OK") -> None:
    print(f"  ✓ {message}")


def _fail(message: str) -> None:
    print(f"  ✗ {message}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Keycard hardware smoke test")
    parser.add_argument("--password", help="pairing password (will prompt if omitted)")
    parser.add_argument("--pin", help="6-digit card PIN (will prompt if omitted)")
    parser.add_argument(
        "--path",
        default="m/44'/60'/0'/0/0",
        help="BIP-32 derivation path (default: %(default)s)",
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="also exercise SIGN against a fixed test digest (consumes a PIN attempt on bad PIN)",
    )
    parser.add_argument(
        "--keep-pairing",
        action="store_true",
        help="do not unpair this slot when the test completes",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="seconds to wait for a card in the reader",
    )
    args = parser.parse_args()

    password = args.password or getpass.getpass("Pairing password: ")
    if not password:
        _fail("password is required")
        return 2

    pin = args.pin
    if pin is None and (args.sign or True):
        pin = getpass.getpass("Card PIN (6 digits): ")
    if not pin or not pin.isdigit() or len(pin) != 6:
        _fail("PIN must be exactly 6 digits")
        return 2

    try:
        from seedsigner.helpers.ethereum.address import (
            pubkey_to_address, to_checksum_address,
        )
        from seedsigner.helpers.keycard import commands as kc_cmds
        from seedsigner.helpers.keycard.client import KeycardClient, recover_id_for
        from seedsigner.helpers.keycard.crypto import derive_pairing_secret
        from seedsigner.helpers.keycard.reader import wait_for_card
    except Exception as exc:
        _fail(f"could not import seedsigner helpers: {exc}")
        traceback.print_exc()
        return 3

    pairing = None
    client = None

    try:
        _step("connect")
        connection = wait_for_card(timeout_s=args.timeout)
        client = KeycardClient(connection)
        _ok(f"reader: {connection.getReader()!s}")

        _step("SELECT")
        info = client.select()
        version = f"{(info.app_version >> 8) & 0xFF}.{info.app_version & 0xFF}"
        _ok(f"applet v{version}, {info.free_pairing_slots} free slot(s)")
        _ok(f"instance UID: {info.instance_uid.hex()}")
        _ok(f"key on card: {'yes' if info.key_uid else 'no'}")
        if not info.key_uid:
            _fail("no key on card — run GENERATE_KEY (or LOAD_KEY) first.")
            return 4

        _step("PAIR")
        secret = derive_pairing_secret(password)
        pairing = client.pair(secret)
        _ok(f"slot {pairing.pairing_index} acquired")

        _step("OPEN_SECURE_CHANNEL")
        client.open_secure_channel(pairing)
        _ok("channel established")

        _step("VERIFY_PIN")
        client.verify_pin(pin.encode("ascii"))
        _ok("PIN accepted")

        _step("DERIVE + EXPORT pubkey")
        components = kc_cmds.parse_path(args.path)
        client.derive_key(components)
        export = client.export_pubkey()
        # Pull pubkey from a possible 0xA1 wrapper or a flat TLV stream.
        cursor = 0
        body = export
        if body and body[0] == 0xA1:
            body = body[2:2 + body[1]]
        pubkey = None
        while cursor + 2 <= len(body):
            tag = body[cursor]
            length = body[cursor + 1]
            value = body[cursor + 2:cursor + 2 + length]
            if tag == 0x80 and len(value) == 65 and value[0] == 0x04:
                pubkey = bytes(value)
                break
            cursor += 2 + length
        if pubkey is None:
            _fail("could not parse public key from EXPORT response")
            return 5
        address = to_checksum_address(pubkey_to_address(pubkey))
        _ok(f"pubkey: {pubkey.hex()}")
        _ok(f"ETH address ({args.path}): {address}")

        if args.sign:
            _step("SIGN test digest + recover")
            digest = b"\x11" * 32
            sig = client.sign(digest)
            r_int = int.from_bytes(sig.r, "big")
            s_int = int.from_bytes(sig.s, "big")
            if r_int == 0 or s_int == 0:
                _fail(f"signature has zero component (r={r_int}, s={s_int})")
                return 6
            try:
                rec_id = recover_id_for(pubkey, digest, sig.r, sig.s)
            except Exception as exc:
                _fail(f"recover failed: {exc}")
                return 6
            _ok(f"signature OK; recovery id = {rec_id}")
            if sig.public_key != pubkey:
                _fail("SIGN response pubkey differs from EXPORT pubkey!")
                return 7
            _ok("SIGN response pubkey matches EXPORT pubkey")

        _step("DONE")
        _ok("all checks passed")
        return 0

    except Exception as exc:
        _fail(f"unhandled exception: {exc}")
        traceback.print_exc()
        return 10

    finally:
        if client is not None and pairing is not None and not args.keep_pairing:
            try:
                _step("cleanup: UNPAIR")
                client.unpair(pairing.pairing_index)
                _ok(f"freed slot {pairing.pairing_index}")
            except Exception as exc:
                _fail(f"cleanup unpair failed: {exc}")


if __name__ == "__main__":
    raise SystemExit(main())
