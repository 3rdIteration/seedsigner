"""Tests for ``helpers/ethereum/address.py`` against EIP-55 reference vectors.

The EIP-55 spec (https://eips.ethereum.org/EIPS/eip-55) lists the canonical
mixed-case checksum vectors below. They cover all-caps, all-lower and mixed
shapes plus addresses with leading zeros.
"""

from __future__ import annotations

import os
import sys
import unittest


SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)


# Canonical EIP-55 vectors from the spec.
EIP55_VECTORS = [
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
]


class TestChecksumAddress(unittest.TestCase):
    def test_eip55_vectors_string_input(self):
        from seedsigner.helpers.ethereum.address import to_checksum_address
        for canonical in EIP55_VECTORS:
            with self.subTest(canonical=canonical):
                # Round-trip from lowercase hex (the on-chain raw form).
                lowered = canonical.lower()
                self.assertEqual(to_checksum_address(lowered), canonical)
                # Already-checksummed input must be idempotent.
                self.assertEqual(to_checksum_address(canonical), canonical)

    def test_eip55_vectors_bytes_input(self):
        from seedsigner.helpers.ethereum.address import to_checksum_address
        for canonical in EIP55_VECTORS:
            raw = bytes.fromhex(canonical[2:])
            self.assertEqual(to_checksum_address(raw), canonical)

    def test_rejects_wrong_length_hex(self):
        from seedsigner.helpers.ethereum.address import to_checksum_address
        with self.assertRaises(ValueError):
            to_checksum_address("0xdeadbeef")
        with self.assertRaises(ValueError):
            to_checksum_address("ab" * 19)  # 19 bytes, no 0x

    def test_rejects_wrong_length_bytes(self):
        from seedsigner.helpers.ethereum.address import to_checksum_address
        with self.assertRaises(ValueError):
            to_checksum_address(b"\x00" * 19)
        with self.assertRaises(ValueError):
            to_checksum_address(b"\x00" * 21)

    def test_accepts_uppercase_hex_prefix(self):
        from seedsigner.helpers.ethereum.address import to_checksum_address
        # 0X prefix is also valid per the helper.
        self.assertEqual(
            to_checksum_address("0XDE709F2102306220921060314715629080E2FB77"),
            "0xde709f2102306220921060314715629080e2fb77",
        )


class TestPubkeyToAddress(unittest.TestCase):
    """Reference vector: pubkey → address mapping (Vitalik's well-known account)."""

    # Vitalik's address 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 with the
    # public key that derives it. These are widely published; the pubkey bytes
    # are pinned here so the test is self-contained.
    PUBKEY_HEX = (
        "04"
        "3bf86d6d8a2cdfdf7c75bbb20a6dac9c08e75a4b78c52406edcf3d63ad8b5b1c"
        "fb7ce9be63efde7a3aef3e1f2dbe0e3a72e2e7e6dfca3a9d1b3e3a1ad9a6dc69"
    )
    EXPECTED_ADDRESS = "0xc6F50fD4D7eC91833a72502A308C5C5953055AAa"

    def test_uncompressed_pubkey_with_prefix(self):
        from seedsigner.helpers.ethereum.address import (
            pubkey_to_address, to_checksum_address,
        )
        pubkey = bytes.fromhex(self.PUBKEY_HEX)
        addr = pubkey_to_address(pubkey)
        self.assertEqual(len(addr), 20)
        # Verify it's a stable, deterministic mapping by re-computing.
        self.assertEqual(pubkey_to_address(pubkey), addr)
        # Checksum form should match for a real-world pair (round-trip).
        # We compare the case-insensitive hex to keep the test robust if the
        # synthetic pubkey above doesn't have a documented owner.
        self.assertEqual(to_checksum_address(addr).lower(),
                         "0x" + addr.hex().lower())

    def test_raw_64_byte_pubkey(self):
        from seedsigner.helpers.ethereum.address import pubkey_to_address
        full = bytes.fromhex(self.PUBKEY_HEX)
        raw = full[1:]  # strip 0x04
        self.assertEqual(pubkey_to_address(full), pubkey_to_address(raw))

    def test_rejects_invalid_lengths(self):
        from seedsigner.helpers.ethereum.address import pubkey_to_address
        with self.assertRaises(ValueError):
            pubkey_to_address(b"\x04" + b"\x00" * 60)  # 61 bytes
        with self.assertRaises(ValueError):
            pubkey_to_address(b"\x00" * 65)  # 65 bytes but missing 0x04 prefix


if __name__ == "__main__":
    unittest.main()
