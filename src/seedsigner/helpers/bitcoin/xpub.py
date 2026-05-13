"""Build an extended public key + descriptor from raw pubkey + chaincode.

The Keycard ``EXPORT KEY`` APDU returns a compressed pubkey + chain
code (and a parent fingerprint). To make that data immediately useful
to companion wallets we wrap it as:

  1. A standard BIP-32 base58 xpub (so wallets that don't speak
     descriptors can still ingest a raw xpub).
  2. A canonical descriptor:
       ``wpkh([master_fingerprint/84h/0h/0h]xpub.../<0;1>/*)``
     This is what Sparrow / Specter / Nunchuk expect today and what
     ``keycard-shell`` emits.

Mainnet-only at MVP.
"""

from __future__ import annotations

import hashlib

from embit import bip32
from embit.descriptor import Descriptor
from embit.descriptor.checksum import checksum as descriptor_checksum

from . import XPUB_VERSION_MAINNET


def _ripemd160_sha256(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    h = hashlib.new("ripemd160")
    h.update(sha)
    return h.digest()


def pubkey_fingerprint(pubkey_compressed: bytes) -> bytes:
    """Return the 4-byte BIP-32 fingerprint of a compressed pubkey
    (HASH160 truncated to 4 bytes)."""
    if len(pubkey_compressed) != 33:
        raise ValueError("expected 33-byte compressed pubkey")
    return _ripemd160_sha256(pubkey_compressed)[:4]


def build_hdkey(
    *,
    pubkey_compressed: bytes,
    chain_code: bytes,
    depth: int,
    parent_fingerprint: bytes,
    child_number: int,
) -> bip32.HDKey:
    """Construct an ``embit`` HDKey from the parts returned by the
    Keycard ``EXPORT KEY`` APDU."""
    if len(pubkey_compressed) != 33:
        raise ValueError("expected 33-byte compressed pubkey")
    if len(chain_code) != 32:
        raise ValueError("expected 32-byte chain code")
    if len(parent_fingerprint) != 4:
        raise ValueError("expected 4-byte parent fingerprint")

    hdkey = bip32.HDKey.from_seed(b"\x00" * 32)  # cheap initialiser
    hdkey.key = bip32.ec.PublicKey.parse(pubkey_compressed)
    hdkey.chain_code = chain_code
    hdkey.depth = depth
    hdkey.fingerprint = parent_fingerprint
    hdkey.child_number = child_number
    hdkey.version = XPUB_VERSION_MAINNET
    return hdkey


def serialize_xpub(hdkey: bip32.HDKey) -> str:
    """Serialise to a base58 ``xpub...`` string (mainnet version bytes)."""
    return hdkey.to_string(version=XPUB_VERSION_MAINNET)


def wpkh_descriptor(
    *,
    xpub: str,
    master_fingerprint: bytes,
    account_path: str = "84h/0h/0h",
) -> str:
    """Return a canonical receive/change ``wpkh(...)`` descriptor with
    its BIP-380 checksum suffix.

    ``master_fingerprint`` is the *root* fingerprint (4 bytes), not the
    account-key fingerprint.
    """
    if len(master_fingerprint) != 4:
        raise ValueError("expected 4-byte master fingerprint")
    fp_hex = master_fingerprint.hex()
    inner = f"wpkh([{fp_hex}/{account_path}]{xpub}/<0;1>/*)"
    return f"{inner}#{descriptor_checksum(inner)}"


def parse_descriptor(descriptor_str: str) -> Descriptor:
    """Round-trip helper for tests: ``descriptor_checksum`` is permissive
    about its input, this validates the full descriptor structure."""
    return Descriptor.from_string(descriptor_str)
