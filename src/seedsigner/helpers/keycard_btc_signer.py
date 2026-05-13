"""Bridge between the Bitcoin helpers and a paired/unlocked Keycard.

The Keycard is used as a signing oracle: the host derives the digest
(BIP-143 sighash or BIP-137 message digest), the card returns
``(r, s, pubkey)`` via its SIGN APDU, and the host packs the result
into the form a wallet expects (PSBT ``PSBT_IN_PARTIAL_SIG`` for
signing, base64 ``[header || r || s]`` for messages, raw xpub for
account export).

Caller responsibilities, as with the ETH signer:
  (a) select the applet,
  (b) open the secure channel,
  (c) verify the PIN.

This module never touches the PIN itself.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from seedsigner.helpers.bitcoin import message_sign, psbt_helpers, xpub as btc_xpub
from seedsigner.helpers.keycard import commands
from seedsigner.helpers.keycard.client import KeycardClient, recover_id_for
from seedsigner.helpers.keycard.responses import parse_tlv

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BtcXpubExport:
    pubkey_compressed: bytes        # 33 bytes
    chain_code: bytes               # 32 bytes
    depth: int                      # 0..255
    parent_fingerprint: bytes       # 4 bytes
    child_number: int               # last hardened/non-hardened index
    master_fingerprint: bytes       # 4-byte HASH160 of the master pubkey
    xpub_base58: str                # serialized via XPUB_VERSION_MAINNET
    descriptor: str                 # wpkh(...) with BIP-380 checksum


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


_HARDENED = 0x80000000


def path_str_to_components(path: str) -> list[int]:
    """``m/84'/0'/0'/0/5`` → [0x80000054, 0x80000000, 0x80000000, 0, 5].

    Accepts both ``'`` and ``h`` as the hardened marker. Empty path
    (``"m"``) yields ``[]`` — used for master-key export.
    """
    parts = path.split("/")
    if parts[0] not in ("m", "M"):
        raise ValueError(f"path must start with 'm': {path!r}")
    components: list[int] = []
    for part in parts[1:]:
        if not part:
            continue
        hardened = part.endswith("'") or part.endswith("h")
        index = int(part.rstrip("'h"))
        if index >= _HARDENED:
            raise ValueError(f"path component out of range: {part}")
        components.append(index | _HARDENED if hardened else index)
    return components


# ---------------------------------------------------------------------------
# Pubkey compression
# ---------------------------------------------------------------------------


def compress_pubkey(uncompressed: bytes) -> bytes:
    """Convert a 65-byte uncompressed pubkey (``0x04 || X || Y``) to its
    33-byte compressed form (``0x02/0x03 || X``)."""
    if len(uncompressed) != 65 or uncompressed[0] != 0x04:
        raise ValueError("expected 65-byte uncompressed pubkey (0x04 prefix)")
    x = uncompressed[1:33]
    y = uncompressed[33:65]
    prefix = 0x02 if (y[-1] & 1) == 0 else 0x03
    return bytes([prefix]) + x


# ---------------------------------------------------------------------------
# DER encoding of ECDSA (r, s)
# ---------------------------------------------------------------------------


def _int_to_der_int(n: int) -> bytes:
    raw = n.to_bytes(32, "big")
    # Strip leading zero bytes, but keep at least one. Then add a
    # leading zero if the high bit is set (avoids negative-number
    # interpretation in DER).
    stripped = raw.lstrip(b"\x00")
    if not stripped:
        stripped = b"\x00"
    if stripped[0] & 0x80:
        stripped = b"\x00" + stripped
    return b"\x02" + bytes([len(stripped)]) + stripped


def encode_der_signature(r: int, s: int) -> bytes:
    """Pack ``(r, s)`` as a DER-encoded ECDSA signature (no sighash
    byte). The Keycard applet enforces low-S already, so we trust the
    inputs without re-normalising."""
    body = _int_to_der_int(r) + _int_to_der_int(s)
    return b"\x30" + bytes([len(body)]) + body


# ---------------------------------------------------------------------------
# xpub export (DERIVE + EXPORT_KEY extended)
# ---------------------------------------------------------------------------


def _parse_extended_export(response: bytes) -> tuple[bytes, bytes]:
    """Pull (uncompressed_pubkey, chain_code) out of an EXPORT_KEY
    extended-public response.

    Format (Keycard applet): outer template ``0xA1`` containing
    ``0x80`` (public key, 65 bytes uncompressed) and ``0x82`` (chain
    code, 32 bytes). Some firmwares wrap the public key under tag
    ``0xA1`` directly without an outer constructed tag — handle both.
    """
    tag, body, _ = parse_tlv(response, 0)
    if tag == 0xA1:
        inner = body
    else:
        # Older Status applet revisions returned the inner TLVs at the
        # top level. Treat the whole response as the constructed body.
        inner = response

    cursor = 0
    pub_key: bytes | None = None
    chain: bytes | None = None
    while cursor < len(inner):
        t, v, cursor = parse_tlv(inner, cursor)
        if t == 0x80:
            pub_key = v
        elif t == 0x82:
            chain = v
    if pub_key is None or chain is None:
        raise ValueError("EXPORT KEY extended response missing pubkey or chain code")
    if len(pub_key) != 65 or pub_key[0] != 0x04:
        raise ValueError("EXPORT KEY pubkey must be 65-byte uncompressed")
    if len(chain) != 32:
        raise ValueError("EXPORT KEY chain code must be 32 bytes")
    return pub_key, chain


def export_xpub(client: KeycardClient, account_path: str) -> BtcXpubExport:
    """DERIVE to ``account_path`` then EXPORT KEY (extended) and pack
    the result into a ready-to-display ``BtcXpubExport``.

    Also exports the master pubkey at ``m`` to compute the master
    fingerprint, which is the value descriptor consumers expect in the
    ``[xx....../84h/0h/0h]`` key origin block.
    """
    components = path_str_to_components(account_path)

    # 1. Master fingerprint: DERIVE to root, EXPORT current (pubkey only).
    client.derive_key([], source=commands.DERIVE_P1_FROM_MASTER)
    master_response = client.export_pubkey(path_components=None, extended=False)
    master_pub_uncompressed = _parse_pubkey_only(master_response)
    master_fingerprint = btc_xpub.pubkey_fingerprint(
        compress_pubkey(master_pub_uncompressed),
    )

    # 2. Account-level xpub: DERIVE to account_path, EXPORT extended.
    client.derive_key(components, source=commands.DERIVE_P1_FROM_MASTER)
    extended_response = client.export_pubkey(path_components=None, extended=True)
    pub_uncompressed, chain_code = _parse_extended_export(extended_response)
    pubkey_compressed = compress_pubkey(pub_uncompressed)

    depth = len(components)
    # ``parent_fingerprint`` is the HASH160 of the parent pubkey. We
    # can compute it locally by DERIVE'ing to the parent and exporting
    # its pubkey, then truncating its HASH160. But cheaper: derive
    # parent in software is what wallets do once they have the chain
    # code; for the xpub layout we only need the parent fingerprint
    # field set to *something* valid. The Keycard doesn't surface the
    # parent fingerprint, so derive it by stepping back one hop.
    if components:
        client.derive_key(components[:-1], source=commands.DERIVE_P1_FROM_MASTER)
        parent_response = client.export_pubkey(path_components=None, extended=False)
        parent_pub = _parse_pubkey_only(parent_response)
        parent_fingerprint = btc_xpub.pubkey_fingerprint(compress_pubkey(parent_pub))
        child_number = components[-1]
    else:
        parent_fingerprint = b"\x00\x00\x00\x00"
        child_number = 0

    hdkey = btc_xpub.build_hdkey(
        pubkey_compressed=pubkey_compressed,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
    )
    xpub_str = btc_xpub.serialize_xpub(hdkey)
    account_path_no_leading_m = "/".join(account_path.split("/")[1:]).replace("'", "h")
    descriptor = btc_xpub.wpkh_descriptor(
        xpub=xpub_str,
        master_fingerprint=master_fingerprint,
        account_path=account_path_no_leading_m,
    )

    return BtcXpubExport(
        pubkey_compressed=pubkey_compressed,
        chain_code=chain_code,
        depth=depth,
        parent_fingerprint=parent_fingerprint,
        child_number=child_number,
        master_fingerprint=master_fingerprint,
        xpub_base58=xpub_str,
        descriptor=descriptor,
    )


def _parse_pubkey_only(response: bytes) -> bytes:
    """Parse an EXPORT KEY (P2=0x01) response into the uncompressed
    public key bytes."""
    tag, body, _ = parse_tlv(response, 0)
    if tag != 0xA1:
        # Some firmwares return just the inner public-key TLV.
        body = response
    cursor = 0
    while cursor < len(body):
        t, v, cursor = parse_tlv(body, cursor)
        if t == 0x80:
            if len(v) != 65 or v[0] != 0x04:
                raise ValueError("public key must be 65-byte uncompressed")
            return v
    raise ValueError("EXPORT KEY response missing public-key TLV (0x80)")


# ---------------------------------------------------------------------------
# PSBT signing
# ---------------------------------------------------------------------------


def sign_psbt(
    client: KeycardClient,
    parsed: psbt_helpers.ParsedPsbt,
    sighash_type: int = 0x01,
) -> psbt_helpers.ParsedPsbt:
    """Sign every input in ``parsed`` and write the partial signatures
    back into the PSBT in place.

    ``parsed`` must already have been produced by
    ``psbt_helpers.extract`` against the same master fingerprint as
    the Keycard. Returns the same object for chaining.
    """
    psbt = parsed.psbt
    for view in parsed.inputs:
        sighash = psbt_helpers.sighash_for_input(psbt, view.index, sighash_type)
        view.sighash_hex = sighash.hex()
        sig = client.sign(
            hash_to_sign=sighash,
            path_components=view.derivation,
            derive_and_make_current=False,
        )
        pubkey_compressed = compress_pubkey(sig.public_key)
        r_int = int.from_bytes(sig.r, "big")
        s_int = int.from_bytes(sig.s, "big")
        der_sig = encode_der_signature(r_int, s_int)
        psbt_helpers.add_partial_signature(
            psbt, view.index, pubkey_compressed, der_sig, sighash_type,
        )
    return parsed


# ---------------------------------------------------------------------------
# BIP-137 message signing
# ---------------------------------------------------------------------------


def sign_message(client: KeycardClient, message: bytes | str, path: str) -> str:
    """Drive the Keycard to produce a BIP-137 signature for ``message``.

    Returns the base64-encoded 65-byte ``[header || r || s]`` string
    that ``bitcoin-cli verifymessage`` (and Electrum / Sparrow / Specter)
    consume directly.
    """
    digest = message_sign.message_digest(message)
    components = path_str_to_components(path)
    sig = client.sign(
        hash_to_sign=digest,
        path_components=components,
        derive_and_make_current=False,
    )
    recid = recover_id_for(sig.public_key, digest, sig.r, sig.s)
    r_int = int.from_bytes(sig.r, "big")
    s_int = int.from_bytes(sig.s, "big")
    return message_sign.encode_signature(r_int, s_int, recid)
