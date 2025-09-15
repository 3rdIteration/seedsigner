#!/usr/bin/env python3
"""Console tool to generate BIP85-derived PGP keys.

This script mimics the SeedSigner graphical menu for generating GPG keys
without requiring a ``gpg`` installation.  It derives key material using
BIP85 and exports the result in ASCII-armoured format.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone, date
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

from seedsigner.models.seed import Seed
from seedsigner.helpers.bip85_drng import BIP85DRNG


BIP85_GPG_CREATED_TS = 1231006505  # Genesis block timestamp


# ---------------------------------------------------------------------------
# BIP85 derivation helpers copied from tools_views
# ---------------------------------------------------------------------------


def bip85_rsa_from_root(root, bits: int, index: int, sub_index: int | None = None):
    from embit import bip85

    path = [bits, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, 828365, path)
    drng = BIP85DRNG.new(entropy)
    return RSA.generate(bits, randfunc=drng.read)


def bip85_ed25519_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "EdDSA"
):
    from embit import bip85
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives import serialization
    from pgpy.constants import EllipticCurveOID

    path = [259, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, 828365, path)
    d_bytes = entropy[:32]
    if alg == "EdDSA":
        priv = fields.EdDSAPriv()
        priv.oid = EllipticCurveOID.Ed25519
        pub_bytes = (
            ed25519.Ed25519PrivateKey.from_private_bytes(d_bytes)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        priv.p = fields.ECPoint.from_values(
            priv.oid.key_size,
            fields.ECPointFormat.Native,
            pub_bytes,
        )
        priv.s = fields.MPI(int.from_bytes(d_bytes, "big"))
    else:
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.Curve25519
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
        pub_bytes = (
            x25519.X25519PrivateKey.from_private_bytes(d_bytes)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
        priv.p = fields.ECPoint.from_values(
            priv.oid.key_size,
            fields.ECPointFormat.Native,
            pub_bytes,
        )
        priv.s = fields.MPI(int.from_bytes(d_bytes, "big"))
    priv._compute_chksum()
    return priv


def bip85_secp256k1_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA"
):
    from embit import bip85
    from cryptography.hazmat.primitives.asymmetric import ec
    from pgpy.constants import EllipticCurveOID

    path = [256, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, 828365, path)
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    d = int.from_bytes(entropy[:32], "big") % order
    if d == 0:
        d = 1
    pn = ec.derive_private_key(d, ec.SECP256K1()).public_key().public_numbers()
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.SECP256K1
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.SECP256K1
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pn.x),
        fields.MPI(pn.y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def bip85_p256_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA"
):
    from embit import bip85
    from cryptography.hazmat.primitives.asymmetric import ec
    from pgpy.constants import EllipticCurveOID

    path = [257, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, 828365, path)
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    d = int.from_bytes(entropy[:32], "big") % order
    if d == 0:
        d = 1
    pn = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.NIST_P256
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.NIST_P256
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pn.x),
        fields.MPI(pn.y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def bip85_brainpoolp256r1_from_root(
    root, index: int, sub_index: int | None = None, alg: str = "ECDSA"
):
    from embit import bip85
    from cryptography.hazmat.primitives.asymmetric import ec
    from pgpy.constants import EllipticCurveOID

    path = [258, index]
    if sub_index is not None:
        path.append(sub_index)
    entropy = bip85.derive_entropy(root, 828365, path)
    order = 0xA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7
    d = int.from_bytes(entropy[:32], "big") % order
    if d == 0:
        d = 1
    pn = ec.derive_private_key(d, ec.BrainpoolP256R1()).public_key().public_numbers()
    if alg == "ECDH":
        priv = fields.ECDHPriv()
        priv.oid = EllipticCurveOID.Brainpool_P256
        priv.kdf.halg = priv.oid.kdf_halg
        priv.kdf.encalg = priv.oid.kek_alg
    else:
        priv = fields.ECDSAPriv()
        priv.oid = EllipticCurveOID.Brainpool_P256
    priv.p = fields.ECPoint.from_values(
        priv.oid.key_size,
        fields.ECPointFormat.Standard,
        fields.MPI(pn.x),
        fields.MPI(pn.y),
    )
    priv.s = fields.MPI(d)
    priv._compute_chksum()
    return priv


def _bip85_subkey_specs(alg: str):
    """Return subkey specifications for the given algorithm."""
    from pgpy.constants import PubKeyAlgorithm, KeyFlags

    if alg == "ed25519":
        return [
            (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
            (1, PubKeyAlgorithm.EdDSA, {KeyFlags.Authentication, KeyFlags.Sign}, "EdDSA"),
            (2, PubKeyAlgorithm.EdDSA, {KeyFlags.Sign}, "EdDSA"),
        ]
    if alg in ["secp256k1", "nistp256", "brainpoolP256r1"]:
        return [
            (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
            (1, PubKeyAlgorithm.ECDSA, {KeyFlags.Authentication, KeyFlags.Sign}, "ECDSA"),
            (2, PubKeyAlgorithm.ECDSA, {KeyFlags.Sign}, "ECDSA"),
        ]
    return [
        (0, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}),
        (1, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Authentication, KeyFlags.Sign}),
        (2, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Sign}),
    ]


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


def create_bip85_pgp_key(
    mnemonic: str,
    key_index: int,
    key_type: str,
    name: str,
    email: str,
    expiration: str | None = None,
    additional_sets: int = 0,
) -> PGPKey:
    """Generate a BIP85-derived PGP key."""

    seed = Seed(mnemonic.split())
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    created = datetime.fromtimestamp(BIP85_GPG_CREATED_TS, tz=timezone.utc)

    default_exp = date(2029, 12, 31) if key_type == "rsa2048" else date(2035, 12, 31)
    if expiration:
        expiration_dt = datetime.strptime(expiration, "%Y-%m-%d").date()
    else:
        expiration_dt = default_exp
    expires = datetime.combine(expiration_dt, datetime.min.time(), tzinfo=timezone.utc) - created

    key_bits = (
        2048
        if key_type == "rsa2048"
        else 3072
        if key_type == "rsa3072"
        else 4096
        if key_type == "rsa4096"
        else None
    )

    pk = PrivKeyV4()
    if key_type == "secp256k1":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_secp256k1_from_root(root, key_index)
    elif key_type == "p256":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_p256_from_root(root, key_index)
    elif key_type == "brainpoolp256r1":
        pk.pkalg = PubKeyAlgorithm.ECDSA
        pk.keymaterial = bip85_brainpoolp256r1_from_root(root, key_index)
    elif key_type == "ed25519":
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

    # initial subkeys mirror graphical workflow
    if key_type == "ed25519":
        base_specs: List[Tuple] = [
            (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
            (1, PubKeyAlgorithm.EdDSA, {KeyFlags.Authentication}, "EdDSA"),
            (2, PubKeyAlgorithm.EdDSA, {KeyFlags.Sign}, "EdDSA"),
        ]
    elif key_type in ["secp256k1", "p256", "brainpoolp256r1"]:
        base_specs = [
            (0, PubKeyAlgorithm.ECDH, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}, "ECDH"),
            (1, PubKeyAlgorithm.ECDSA, {KeyFlags.Authentication}, "ECDSA"),
            (2, PubKeyAlgorithm.ECDSA, {KeyFlags.Sign}, "ECDSA"),
        ]
    else:
        base_specs = [
            (0, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage}),
            (1, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Authentication}),
            (2, PubKeyAlgorithm.RSAEncryptOrSign, {KeyFlags.Sign}),
        ]

    for sub_index, pkalg, usage, *name in base_specs:
        alg_name = name[0] if name else None
        _add_subkey(
            pgp_key,
            root,
            key_type,
            key_index,
            sub_index,
            pkalg,
            usage,
            created,
            expires,
            alg_name,
            key_bits,
        )

    # additional sets
    alg_for_specs = {
        "p256": "nistp256",
        "brainpoolp256r1": "brainpoolP256r1",
        "secp256k1": "secp256k1",
        "ed25519": "ed25519",
        "rsa2048": "rsa2048",
        "rsa3072": "rsa3072",
        "rsa4096": "rsa4096",
    }[key_type]
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
            key_bits,
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
        choices=[
            "p256",
            "brainpoolp256r1",
            "rsa2048",
            "rsa3072",
            "rsa4096",
            "secp256k1",
            "ed25519",
        ],
        help="Key type",
    )
    parser.add_argument("--name", help="User name")
    parser.add_argument("--email", help="User email")
    parser.add_argument("--expiration", help="Expiration date YYYY-MM-DD")
    parser.add_argument(
        "--additional",
        type=int,
        default=0,
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
        options = [
            ("p256", "NIST P-256"),
            ("brainpoolp256r1", "Brainpool P-256"),
            ("rsa2048", "RSA 2048"),
            ("rsa3072", "RSA 3072"),
            ("rsa4096", "RSA 4096"),
            ("secp256k1", "secp256k1"),
            ("ed25519", "Ed25519"),
        ]
        for i, (_, label) in enumerate(options, 1):
            print(f"{i}: {label}")
        sel = int(input("Select key type: ")) - 1
        key_type = options[sel][0]
    name = args.name or input("Name: ")
    email = args.email or input("Email: ")
    expiration = args.expiration
    if expiration is None:
        expiration = input(
            "Expiration YYYY-MM-DD (leave blank for default): "
        ).strip() or None
    additional = args.additional
    if args.additional == 0 and args.additional is None:
        additional = int(
            input("Additional subkey sets (each adds three subkeys) [0]: ") or 0
        )
    export_type = args.export

    key = create_bip85_pgp_key(
        mnemonic,
        index,
        key_type,
        name,
        email,
        expiration,
        additional,
    )

    if export_type == "private":
        print(export_private_key(key))
    else:
        print(export_public_key(key))


if __name__ == "__main__":
    main()
