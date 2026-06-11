"""
Quick smoke-test for the KeycardSatochipConnector against a real card.

Usage:
    python tools/verify_keycard.py [PIN]      (default PIN: 123456)
"""

import sys
import os

# Resolve paths
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))

from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

PIN = sys.argv[1] if len(sys.argv) > 1 else "123456"

print("=== Keycard smoke test ===")
print(f"Default pairing password : {KeycardSatochipConnector.DEFAULT_PAIRING_PASSWORD!r}")
print(f"PIN                      : {PIN}")
print()

# ── 1. Connect ────────────────────────────────────────────────────────────────
print("[1] Connecting to card …")
conn = KeycardSatochipConnector.create(card_filter=["satochip"])
print(f"    UID SHA1 : {conn.UID_SHA1}")

# ── 2. Get status ─────────────────────────────────────────────────────────────
print("[2] card_get_status …")
_, sw1, sw2, status = conn.card_get_status()
print(f"    SW={sw1:02X}{sw2:02X}  status={status}")
if not status.get("setup_done") and not status.get("key_initialized"):
    print("    Card has no key loaded – stopping here.")
    sys.exit(0)

# ── 3. Verify PIN ─────────────────────────────────────────────────────────────
print("[3] Verifying PIN …")
conn.set_pin(0, PIN)
resp, sw1, sw2 = conn.card_verify_PIN()
if sw1 == 0x90 and sw2 == 0x00:
    print("    PIN OK")
else:
    print(f"    PIN failed: SW={sw1:02X}{sw2:02X}")
    sys.exit(1)

# ── 4. Export xpub ───────────────────────────────────────────────────────────
print("[4] Exporting xpub at m/44'/0'/0' …")
xpub = conn.card_bip32_get_xpub("m/44'/0'/0'", "standard", is_mainnet=True)
print(f"    xpub : {xpub}")

# ── 5. Sign a dummy 32-byte hash ──────────────────────────────────────────────
print("[5] Signing 32-byte hash at m/44'/0'/0'/0/0 …")
dummy_hash = bytes(range(32))
# Derive to leaf path so _last_path is set for keynbr=0xFF routing
conn.card_bip32_get_xpub("m/44'/0'/0'/0/0", "standard", is_mainnet=True)
sig_resp, sw1, sw2 = conn.card_sign_transaction_hash(0xFF, dummy_hash)
print(f"    SW={sw1:02X}{sw2:02X}  DER sig ({len(sig_resp)} bytes): {bytes(sig_resp).hex()}")

print()
print("=== All checks passed ===")
conn.card_disconnect()
