"""
Address cross-check: an address SeedSigner is about to tell the user belongs to
their wallet (address verification, sign-message) is re-derived by libwally from
the seed -- or the smartcard's xpub, or the descriptor -- and must match.
"""
from seedsigner.crosscheck import CrossCheckCode, CrossCheckError, get_wally
from seedsigner.crosscheck import keys as K
from seedsigner.crosscheck.descriptor import descriptor_address


def _fail(detail: str):
    raise CrossCheckError(CrossCheckCode.ADDRESS, detail)


def check_singlesig_address(address: str, network: str, kind: str, path: list[int],
                            seed_bytes: bytes | None = None, xprv: str | None = None,
                            xpub: str | None = None) -> None:
    """
    `address` must be the `kind` (keys.SINGLESIG_*) address of the key at `path`
    below the given key source (the full path from the master key for a seed or
    xprv; the path below the account key for a smartcard xpub).
    """
    w = get_wally()
    if w is None:
        return
    root = K.key_from_secret(network, seed_bytes, xprv, xpub, CrossCheckCode.ADDRESS)
    if root is None:
        _fail("no key to derive the address from")
    try:
        spk = K.singlesig_script(kind, K.derive_pubkey(root, path))
    finally:
        del root
    if K.address(spk, network) != address:
        _fail("address differs")


def check_descriptor_address(address: str, network: str, descriptor: str, branch: int, index: int) -> None:
    """`address` must be `descriptor`'s address at (branch, index)."""
    w = get_wally()
    if w is None:
        return
    if descriptor_address(descriptor, network, branch, index) != address:
        _fail(f"descriptor address {branch}/{index} differs")
