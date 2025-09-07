"""Helper functions for PGP message encryption and decryption.

These utilities wrap the :mod:`pgpy` package so that SeedSigner can encrypt
and decrypt arbitrary text payloads using PGP public and private keys.  The
functions are intentionally lightweight and do not rely on the external GPG
binary, making them suitable for environments where only a minimal Python
runtime is available.
"""
from __future__ import annotations

from typing import Iterable, Optional, Tuple

from pgpy import PGPKey, PGPMessage


def encrypt_message(
    pubkey_blob: Optional[str],
    message: str,
    signkey_blob: Optional[str] = None,
    signkey_passphrase: Optional[str] = None,
) -> str:
    """Sign and optionally encrypt ``message``.

    Parameters
    ----------
    pubkey_blob: Optional[str]
        ASCII-armored public key data. If ``None`` the message will not be
        encrypted.
    message: str
        Plaintext message to encrypt.
    signkey_blob: Optional[str]
        Optional ASCII-armored private key used to sign the message before
        encryption.
    signkey_passphrase: Optional[str]
        Optional passphrase for the signing key when ``signkey_blob`` is
        provided.

    Returns
    -------
    str
        The resulting ASCII-armored message which may be signed and/or
        encrypted.
    """

    pgp_message = PGPMessage.new(message)

    if signkey_blob:
        signkey, _ = PGPKey.from_blob(signkey_blob)
        if signkey.is_protected:
            if signkey_passphrase is None:
                raise ValueError("Passphrase required for encrypted signing key")
            with signkey.unlock(signkey_passphrase):
                pgp_message |= signkey.sign(pgp_message)
        else:
            pgp_message |= signkey.sign(pgp_message)

    if pubkey_blob:
        pubkey, _ = PGPKey.from_blob(pubkey_blob)
        pgp_message = pubkey.encrypt(pgp_message)

    return str(pgp_message)


def decrypt_message(
    privkey_blob: Optional[str],
    ciphertext: str,
    passphrase: Optional[str] = None,
    pubkey_blobs: Optional[Iterable[str]] = None,
) -> Tuple[str, Optional[str], bool]:
    """Decrypt ``ciphertext`` and optionally verify a signature.

    Parameters
    ----------
    privkey_blob: Optional[str]
        ASCII-armored private key data. Required if ``ciphertext`` is
        encrypted; otherwise ``None`` can be supplied.
    ciphertext: str
        ASCII-armored message produced by :func:`encrypt_message`.
    passphrase: Optional[str]
        Optional passphrase to unlock the private key. ``None`` can be
        provided for unprotected keys.

    Returns
    -------
    Tuple[str, Optional[str], bool]
        A tuple containing the decrypted plaintext message (or the original
        message if it was not encrypted), the fingerprint of the signing
        key if the message included a signature, and a boolean indicating
        whether the signature was verified with the provided public keys.
    """

    message = PGPMessage.from_blob(ciphertext)

    if not message.is_encrypted:
        decrypted = message
    else:
        if privkey_blob is None:
            raise ValueError("Encrypted message requires a private key")

        privkey, _ = PGPKey.from_blob(privkey_blob)

        if privkey.is_protected:
            if passphrase is None:
                raise ValueError("Passphrase required for encrypted private key")
            with privkey.unlock(passphrase):
                decrypted = privkey.decrypt(message)
        else:
            decrypted = privkey.decrypt(message)

    result = decrypted.message
    if isinstance(result, (bytes, bytearray)):
        plaintext = result.decode("utf-8")
    else:
        plaintext = result

    signer_fpr: Optional[str] = None
    verified = False
    if decrypted.is_signed:
        signer_fpr = decrypted.signatures[0].signer_fingerprint
        if pubkey_blobs:
            for blob in pubkey_blobs:
                try:
                    pub, _ = PGPKey.from_blob(blob)
                    if pub.verify(decrypted):
                        verified = True
                        break
                except Exception:
                    continue

    return plaintext, signer_fpr, verified
