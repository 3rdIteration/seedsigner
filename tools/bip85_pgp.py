#!/usr/bin/env python3
"""Console tool to generate BIP85-derived PGP keys.

This script mimics the SeedSigner graphical menu for generating GPG keys
without requiring a ``gpg`` installation.  It derives key material using
BIP85 and exports the result in ASCII-armoured format.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone, date
from pathlib import Path
from typing import List, Tuple

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
from Cryptodome.PublicKey import RSA


# Allow running without installing the project as a package.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from seedsigner.models.seed import Seed
from seedsigner.views.tools_views import (
    BIP85_GPG_CREATED_TS,
    bip85_rsa_from_root,
    bip85_ed25519_from_root,
    bip85_secp256k1_from_root,
    bip85_p256_from_root,
    bip85_brainpoolp256r1_from_root,
    _bip85_subkey_specs,
    _bip85_key_type_choices,
)


# CLI test tool should expose every supported key type regardless of UI settings.
CLI_KEY_TYPE_CHOICES = tuple(_bip85_key_type_choices(include_ecc=True))
CLI_KEY_TYPE_CODES = tuple(code for _, code in CLI_KEY_TYPE_CHOICES)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def _rsa_to_privpacket(rsa_key: RSA.RsaKey) -> fields.RSAPriv:
    priv = fields.RSAPriv()
    priv.n = MPI(rsa_key.n)
    priv.e = MPI(rsa_key.e)
    priv.d = MPI(rsa_key.d)
    priv.p = MPI(rsa_key.p)
    priv.q = MPI(rsa_key.q)
    priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
    priv._compute_chksum()
    return priv


def _add_subkey(
    pgp_key: PGPKey,
    root,
    alg: str,
    key_index: int,
    sub_index: int,
    pkalg: PubKeyAlgorithm,
    usage: set,
    created: datetime,
    expires,
    alg_name: str | None,
    key_bits: int | None,
):
    subpkt = PrivSubKeyV4()
    subpkt.pkalg = pkalg
    if alg == "secp256k1":
        subpkt.keymaterial = bip85_secp256k1_from_root(root, key_index, sub_index, alg_name)
    elif alg in ["p256", "nistp256"]:
        subpkt.keymaterial = bip85_p256_from_root(root, key_index, sub_index, alg_name)
    elif alg in ["brainpoolp256r1", "brainpoolP256r1"]:
        subpkt.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index, sub_index, alg_name)
    elif alg == "ed25519":
        subpkt.keymaterial = bip85_ed25519_from_root(root, key_index, sub_index, alg_name)
    else:
        rsa_sub = bip85_rsa_from_root(root, key_bits, key_index, sub_index)
        subpkt.keymaterial = _rsa_to_privpacket(rsa_sub)
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


def _add_subkey_set(
    pgp_key: PGPKey,
    root,
    alg: str,
    base_index: int,
    start_index: int,
    created: datetime,
    expires,
    key_bits: int | None,
):
    """Add a trio of subkeys starting at ``start_index``.

    ``start_index`` is the current count of existing subkeys.  Each group of
    three subkeys uses the next BIP85 key index while cycling the subkey index
    between 0-2.  This mirrors the behaviour of the graphical Add Subkeys
    workflow."""

    specs = _bip85_subkey_specs(alg)
    group_index = base_index + (start_index // 3)
    for offset, pkalg, usage, *name in specs:
        sub_index = (start_index % 3) + offset
        alg_name = name[0] if name else None
        _add_subkey(
            pgp_key,
            root,
            alg,
            group_index,
            sub_index,
            pkalg,
            usage,
            created,
            expires,
            alg_name,
            key_bits,
        )


def _key_bits(key_type: str | None) -> int | None:
    """Return RSA bit length for ``key_type`` or ``None`` for EC types."""
    return {
        "rsa2048": 2048,
        "rsa3072": 3072,
        "rsa4096": 4096,
    }.get(key_type)


def create_bip85_pgp_key(
    mnemonic: str,
    key_index: int,
    primary_type: str,
    name: str,
    email: str,
    expiration: str | None = None,
    subkey_type: str | None = None,
    additional_sets: int = 0,
) -> PGPKey:
    """Generate a BIP85-derived PGP key and optional subkeys."""

    seed = Seed(mnemonic.split())
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    created = datetime.fromtimestamp(BIP85_GPG_CREATED_TS, tz=timezone.utc)

    default_exp = (
        date(2029, 12, 31) if primary_type == "rsa2048" else date(2035, 12, 31)
    )
    if expiration:
        expiration_dt = datetime.strptime(expiration, "%Y-%m-%d").date()
    else:
        expiration_dt = default_exp
    expires = (
        datetime.combine(expiration_dt, datetime.min.time(), tzinfo=timezone.utc)
        - created
    )

    key_bits = _key_bits(primary_type)

    pk = PrivKeyV4()
    if primary_type == "secp256k1":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_secp256k1_from_root(root, key_index)
    elif primary_type == "p256":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_p256_from_root(root, key_index)
    elif primary_type == "brainpoolp256r1":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index)
    elif primary_type == "ed25519":
        pk.pkalg = PubKeyAlgorithm.EdDSA
        pk.keymaterial = bip85_ed25519_from_root(root, key_index)
    else:
        rsa_main = bip85_rsa_from_root(root, key_bits, key_index)
        pk.pkalg = PubKeyAlgorithm.RSAEncryptOrSign
        pk.keymaterial = _rsa_to_privpacket(rsa_main)
    pk.created = created
    pk.update_hlen()

    pgp_key = PGPKey()
    pgp_key._key = pk

    uid = PGPUID.new(name, email=email)
    pgp_key.add_uid(
        uid,
        usage={KeyFlags.Certify, KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
        expires=expires,
        created=created,
    )

    if subkey_type:
        sub_bits = _key_bits(subkey_type)

        if subkey_type == "ed25519":
            base_specs: List[Tuple] = [
                (
                    0,
                    PubKeyAlgorithm.ECDH,
                    {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    "ECDH",
                ),
                (1, PubKeyAlgorithm.EdDSA, {KeyFlags.Authentication}, "EdDSA"),
                (2, PubKeyAlgorithm.EdDSA, {KeyFlags.Sign}, "EdDSA"),
            ]
        elif subkey_type in ["secp256k1", "p256", "brainpoolp256r1"]:
            base_specs = [
                (
                    0,
                    PubKeyAlgorithm.ECDH,
                    {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    "ECDH",
                ),
                (1, PubKeyAlgorithm.ECDSA, {KeyFlags.Authentication}, "ECDSA"),
                (2, PubKeyAlgorithm.ECDSA, {KeyFlags.Sign}, "ECDSA"),
            ]
        else:
            base_specs = [
                (
                    0,
                    PubKeyAlgorithm.RSAEncryptOrSign,
                    {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                ),
                (1, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Authentication}),
                (2, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Sign}),
            ]

        for sub_index, pkalg, usage, *name in base_specs:
            alg_name = name[0] if name else None
            _add_subkey(
                pgp_key,
                root,
                subkey_type,
                key_index,
                sub_index,
                pkalg,
                usage,
                created,
                expires,
                alg_name,
                sub_bits,
            )

        alg_for_specs = {
            "p256": "nistp256",
            "brainpoolp256r1": "brainpoolP256r1",
            "secp256k1": "secp256k1",
            "ed25519": "ed25519",
            "rsa2048": "rsa2048",
            "rsa3072": "rsa3072",
            "rsa4096": "rsa4096",
        }[subkey_type]
        start = 3
        for _ in range(additional_sets):
            _add_subkey_set(
                pgp_key,
                root,
                alg_for_specs,
                key_index,
                start,
                created,
                expires,
                sub_bits,
            )
            start += 3

    return pgp_key


def export_public_key(pgp_key: PGPKey) -> str:
    return str(pgp_key.pubkey)


def export_private_key(pgp_key: PGPKey) -> str:
    return str(pgp_key)


# ---------------------------------------------------------------------------
# CLI interface
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Generate BIP85-derived PGP keys")
    parser.add_argument("mnemonic", help="BIP39 mnemonic words", nargs="?")
    parser.add_argument("--index", type=int, default=None, help="BIP85 key index")
    parser.add_argument(
        "--type",
        choices=CLI_KEY_TYPE_CODES,
        help="Key type",
    )
    parser.add_argument("--name", help="User name")
    parser.add_argument("--email", help="User email")
    parser.add_argument("--expiration", help="Expiration date YYYY-MM-DD")
    parser.add_argument(
        "--subkey-type",
        choices=CLI_KEY_TYPE_CODES,
        help="Generate three subkeys of this type",
    )
    parser.add_argument(
        "--additional",
        type=int,
        default=None,
        help="Number of additional subkey sets (each adds three subkeys)",
    )
    parser.add_argument(
        "--export",
        choices=["public", "private"],
        default="public",
        help="Which key material to output",
    )

    args = parser.parse_args()

    mnemonic = args.mnemonic or input("Enter mnemonic: ")
    index = args.index if args.index is not None else int(input("BIP85 index: "))
    if args.type:
        key_type = args.type
    else:
        options = CLI_KEY_TYPE_CHOICES
        for i, (label, _) in enumerate(options, 1):
            print(f"{i}: {label}")
        sel = int(input("Select key type: ")) - 1
        key_type = options[sel][1]
    name = args.name or input("Name: ")
    email = args.email or input("Email: ")
    expiration = args.expiration
    if expiration is None:
        expiration = input(
            "Expiration YYYY-MM-DD (leave blank for default): "
        ).strip() or None
    subkey_type = args.subkey_type
    additional = args.additional
    if subkey_type is None:
        gen = input("Generate trio of subkeys? [y/N]: ").strip().lower()
        if gen in {"y", "yes"}:
            options = CLI_KEY_TYPE_CHOICES
            for i, (label, _) in enumerate(options, 1):
                print(f"{i}: {label}")
            sel = int(input("Select subkey type: ")) - 1
            subkey_type = options[sel][1]
            if additional is None:
                additional = int(
                    input("Additional subkey sets (each adds three subkeys) [0]: ")
                    or 0
                )
        else:
            additional = 0
    else:
        if additional is None:
            additional = 0
    export_type = args.export

    key = create_bip85_pgp_key(
        mnemonic,
        index,
        key_type,
        name,
        email,
        expiration,
        subkey_type,
        additional,
    )

    if export_type == "private":
        print(export_private_key(key))
    else:
        print(export_public_key(key))


if __name__ == "__main__":
    main()
