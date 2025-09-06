"""Helper functions for PGP message encryption and decryption.

These utilities wrap the :mod:`pgpy` package so that SeedSigner can encrypt
and decrypt arbitrary text payloads using PGP public and private keys.  The
functions are intentionally lightweight and do not rely on the external GPG
binary, making them suitable for environments where only a minimal Python
runtime is available.
"""
from __future__ import annotations

from typing import Optional

from pgpy import PGPKey, PGPMessage


def encrypt_message(pubkey_blob: str, message: str) -> str:
    """Encrypt ``message`` with the provided ASCII-armored public key.

    Parameters
    ----------
    pubkey_blob: str
        ASCII-armored public key data.
    message: str
        Plaintext message to encrypt.

    Returns
    -------
    str
        ASCII-armored encrypted message suitable for transport or QR
        encoding.
    """

    pubkey, _ = PGPKey.from_blob(pubkey_blob)
    pgp_message = PGPMessage.new(message)
    encrypted_message = pubkey.encrypt(pgp_message)
    return str(encrypted_message)


def decrypt_message(privkey_blob: str, ciphertext: str, passphrase: Optional[str] = None) -> str:
    """Decrypt ``ciphertext`` with ``privkey_blob``.

    Parameters
    ----------
    privkey_blob: str
        ASCII-armored private key data.
    ciphertext: str
        ASCII-armored encrypted message produced by
        :func:`encrypt_message`.
    passphrase: Optional[str]
        Optional passphrase to unlock the private key.  ``None`` can be
        provided for unprotected keys.

    Returns
    -------
    str
        The decrypted plaintext message.
    """

    privkey, _ = PGPKey.from_blob(privkey_blob)
    message = PGPMessage.from_blob(ciphertext)

    if privkey.is_protected:
        if passphrase is None:
            raise ValueError("Passphrase required for encrypted private key")
        with privkey.unlock(passphrase):
            decrypted = privkey.decrypt(message)
    else:
        decrypted = privkey.decrypt(message)

    return decrypted.message
