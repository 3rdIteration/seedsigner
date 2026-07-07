"""
Standalone Keycard benchmark sign test — connects to card, signs a known hash,
and verifies the signature locally so we can debug DER parsing issues.

Usage:
    python tools/test_keycard_benchmark.py [PIN]   (default PIN: 000000)
"""

import sys
import os

# Resolve paths
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))

from embit import ec
from embit.util import secp256k1
from seedsigner.helpers.keycard_connector import KeycardSatochipConnector

PIN = sys.argv[1] if len(sys.argv) > 1 else "000000"
DERIVATION_PATH = "m/84'/0'/0'/0/0"
DUMMY_HASH = bytes(range(32))  # deterministic for reproducibility


def parse_der_and_verify(pubkey_sec: bytes, sig_der: bytes, digest: bytes) -> bool:
    """Parse DER manually and verify via multiple methods."""
    der = bytes(sig_der)
    print(f"  DER length: {len(der)}")
    print(f"  DER hex:    {der.hex()}")

    if len(der) < 8 or der[0] != 0x30 or der[2] != 0x02:
        raise ValueError("malformed DER signature")
    rlen = der[3]
    r = int.from_bytes(der[4 : 4 + rlen], "big")
    idx = 4 + rlen
    if der[idx] != 0x02:
        raise ValueError("malformed DER signature")
    slen = der[idx + 1]
    s = int.from_bytes(der[idx + 2 : idx + 2 + slen], "big")

    print(f"  rlen={rlen}, slen={slen}")
    print(f"  r (hex) = {r:064x}")
    print(f"  s (hex) = {s:064x}")

    # Normalize low-S
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    high_s = s > order // 2
    if high_s:
        s = order - s
        print(f"  s was high-S, normalized to {s:064x}")

    # Mask to 256 bits
    r &= (1 << 256) - 1
    s &= (1 << 256) - 1

    r_bytes = r.to_bytes(32, "big")
    s_bytes = s.to_bytes(32, "big")
    compact = r_bytes + s_bytes
    print(f"  compact length: {len(compact)}")

    # --- Try secp256k1.ecdsa_signature_parse_compact (bytes) ---
    try:
        pk = secp256k1.ec_pubkey_parse(pubkey_sec, len(pubkey_sec))
        sig_obj = secp256k1.ecdsa_signature_parse_compact(compact)
        result = bool(secp256k1.ecdsa_verify(digest, sig_obj, pk))
        print(f"  secp256k1 verify (bytes):    {result}")
    except Exception as e:
        print(f"  secp256k1 verify (bytes) FAILED: {e}")

    # --- Try embit verification ---
    try:
        sig_embit = ec.Signature(compact)
        pubkey_embit = ec.PublicKey.parse(pubkey_sec)
        result_embit = pubkey_embit.verify(sig_embit, digest)
        print(f"  embit verify:                 {result_embit}")
    except Exception as e:
        print(f"  embit verify FAILED: {e}")

    # --- Try pure-Python ECDSA verification via cryptography ---
    try:
        from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature

        if len(pubkey_sec) == 33:
            pub_key = crypto_ec.EllipticCurvePublicKey.from_encoded_point(
                crypto_ec.SECP256K1(), pubkey_sec
            )
        else:
            pub_key = crypto_ec.EllipticCurvePublicKey.from_encoded_point(
                crypto_ec.SECP256K1(), pubkey_sec
            )

        # Verify DER signature directly against raw hash (no additional hashing)
        der_sig = bytes(sig_der)
        pub_key.verify(der_sig, digest, crypto_ec.ECDSA(Prehashed(hashes.SHA256())))
        print(f"  cryptography verify:          True")
    except InvalidSignature:
        print(f"  cryptography verify:          False (InvalidSignature)")
    except ImportError as e:
        print(f"  cryptography not available:   {e}")
    except Exception as e:
        # Try with normalized DER
        try:
            from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
            from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
            from cryptography.hazmat.primitives import hashes
            from cryptography.exceptions import InvalidSignature

            if len(pubkey_sec) == 33:
                pub_key = crypto_ec.EllipticCurvePublicKey.from_encoded_point(
                    crypto_ec.SECP256K1(), pubkey_sec
                )
            else:
                pub_key = crypto_ec.EllipticCurvePublicKey.from_encoded_point(
                    crypto_ec.SECP256K1(), pubkey_sec
                )

            # Build a proper DER signature from our normalized r/s
            def _der_int(value: int) -> bytes:
                b = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
                if b[0] & 0x80:
                    b = b"\x00" + b
                return b"\x02" + bytes([len(b)]) + b

            norm_der = b"\x30" + bytes([len(_der_int(r) + _der_int(s))]) + _der_int(r) + _der_int(s)
            pub_key.verify(norm_der, digest, crypto_ec.ECDSA(Prehashed(hashes.SHA256())))
            print(f"  cryptography verify (norm DER): True")
        except InvalidSignature:
            print(f"  cryptography verify (norm DER): False (InvalidSignature)")
        except Exception as e2:
            print(f"  cryptography verify FAILED: {e2}")

    # --- Try pure-Python ecdsa library ---
    try:
        import ecdsa
        from ecdsa import SECP256k1, VerifyingKey

        vk = VerifyingKey.from_string(pubkey_sec[1:], curve=SECP256k1)  # skip prefix byte
        der_sig = bytes(sig_der)
        result_ecdsa = vk.verify(der_sig, digest, hashfunc=None)
        print(f"  ecdsa library verify:         {result_ecdsa}")
    except ecdsa.BadSignatureError:
        print(f"  ecdsa library verify:         False (BadSignature)")
    except ImportError:
        pass
    except Exception as e:
        print(f"  ecdsa library FAILED: {e}")

    return False


def main():
    print("=== Keycard benchmark sign test ===\n")

    # 1. Connect
    print("[1] Connecting to card...")
    conn = KeycardSatochipConnector.create(card_filter=["satochip"])
    print(f"    UID SHA1: {conn.UID_SHA1}\n")

    # 2. Status
    print("[2] Card status:")
    _, sw1, sw2, status = conn.card_get_status()
    for k, v in status.items():
        print(f"    {k}: {v}")
    print()

    # 3. Verify PIN
    print("[3] Verifying PIN...")
    conn.set_pin(0, PIN)
    resp, sw1, sw2 = conn.card_verify_PIN()
    if sw1 == 0x90 and sw2 == 0x00:
        print("    PIN OK\n")
    else:
        print(f"    PIN failed: SW={sw1:02X}{sw2:02X}\n")
        sys.exit(1)

    # 4. Get pubkey at leaf path via card_bip32_get_extendedkey
    print(f"[4] Getting pubkey from Keycard at {DERIVATION_PATH}...")
    key, chaincode = conn.card_bip32_get_extendedkey(DERIVATION_PATH)
    pubkey_compressed = key.get_public_key_bytes(compressed=True)
    pubkey_uncompressed = key.get_public_key_bytes(compressed=False)
    print(f"    compressed:     {pubkey_compressed.hex()}")
    print(f"    uncompressed:   {pubkey_uncompressed.hex()}")
    print()

    # 5. Sign dummy hash (set _last_path first for 0xFF routing)
    print(f"[5] Signing dummy hash at {DERIVATION_PATH}...")
    conn.card_bip32_get_xpub(DERIVATION_PATH, "p2wpkh", is_mainnet=True)
    sig_resp, sw1, sw2 = conn.card_sign_transaction_hash(0xFF, list(DUMMY_HASH))
    print(f"    SW={sw1:02X}{sw2:02X}")
    print()

    # 6. Verify with compressed pubkey
    print("[6] Verifying signature (compressed pubkey):")
    try:
        parse_der_and_verify(pubkey_compressed, sig_resp, DUMMY_HASH)
    except Exception as e:
        print(f"    ERROR: {e}\n")

    # 7. Verify with uncompressed pubkey
    print("\n[7] Verifying signature (uncompressed pubkey):")
    try:
        parse_der_and_verify(pubkey_uncompressed, sig_resp, DUMMY_HASH)
    except Exception as e:
        print(f"    ERROR: {e}\n")

    # 8. Try embit.PublicKey.parse on compressed key then verify
    print("\n[8] Verifying via embit (parsed from compressed):")
    try:
        pubkey_embit = ec.PublicKey.parse(pubkey_compressed)
        sec_bytes = pubkey_embit.sec()
        print(f"    embit sec(): {sec_bytes.hex()}")
        parse_der_and_verify(sec_bytes, sig_resp, DUMMY_HASH)
    except Exception as e:
        print(f"    ERROR: {e}\n")

    conn.card_disconnect()
    print("\n=== Done ===")


if __name__ == "__main__":
    main()
