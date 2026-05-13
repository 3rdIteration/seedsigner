"""SeedSigner package initialisation.

This module ensures that the Python ``hashlib`` library has support for the
``ripemd160`` hash algorithm.  Some minimal Python environments – such as the
one used in the SeedSigner OS image – are built against an OpenSSL library that
omits RIPEMD160.  Downstream libraries (e.g. ``pysatochip`` and ``embit``)
expect ``hashlib.new('ripemd160')`` to be available and will raise a
``ValueError`` otherwise which manifests in the UI as
"Unsupported hash type ripemd160".

To make the behaviour consistent across platforms we try to create the hash and
if it fails we patch ``hashlib.new`` to delegate RIPEMD160 to PyCryptodome's
implementation.  This keeps the rest of the codebase unchanged on the
stripped-down system image.
"""

from __future__ import annotations

import hashlib

try:
    # Attempt to create a RIPEMD160 hash to see if the algorithm is available.
    hashlib.new("ripemd160")
except ValueError:  # pragma: no cover - depends on host OpenSSL build
    # ``ripemd160`` is missing; fall back to PyCryptodome's implementation and
    # patch ``hashlib.new`` so that libraries expecting it continue to work.
    from Cryptodome.Hash import RIPEMD160

    _orig_hashlib_new = hashlib.new

    def _hashlib_new(name: str, data: bytes = b"", *args, **kwargs):
        if name.lower() == "ripemd160":
            # PyCryptodome's ``new`` accepts an optional ``data`` parameter.
            return RIPEMD160.new(data)
        return _orig_hashlib_new(name, data, *args, **kwargs)

    hashlib.new = _hashlib_new
