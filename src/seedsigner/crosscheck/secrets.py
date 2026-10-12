"""
Hygiene for secret material that passes through libwally during a cross-check.

Two facts about the wallycore Python bindings shape this module:

* Extended keys come back as PyCapsules whose destructor is `bip32_key_free`,
  which zeroes the C struct (private key and chain code included) before
  freeing it. Dropping the last reference is therefore enough. Calling
  `bip32_key_free` explicitly is NOT safe: the capsule destructor frees the
  key again later (double free, which kills the process).
* Secret byte strings (BIP-39 seeds, private keys) come back as `bytearray`,
  which can be wiped in place. `wallycore.bzero` cannot be used for this from
  Python -- it crashes the interpreter -- so the repo's own `wipe_bytes` does it.

Embit's own key objects hold secrets as Python ints and immutable bytes; those
remain covered only by `Seed.wipe()` and `helpers.secure_delete`, best effort.
"""
from seedsigner.helpers.secure_delete import wipe_bytes



class SecretScratch:
    """
    Collects secret bytearrays produced during a check and wipes them on exit.

        with SecretScratch() as scratch:
            seed = scratch.keep(wally.bip39_mnemonic_to_seed512(...))
            ...
    """
    def __init__(self):
        self._buffers: list[bytearray] = []

    def keep(self, buf):
        if isinstance(buf, bytearray):
            self._buffers.append(buf)
        return buf

    def wipe(self):
        for buf in self._buffers:
            wipe_bytes(buf)
        self._buffers.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.wipe()
        return False
