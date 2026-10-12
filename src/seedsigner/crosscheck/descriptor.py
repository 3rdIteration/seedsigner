"""
Descriptor cross-check: libwally's descriptor/miniscript engine re-parses a
wallet descriptor embit accepted and must agree on its keys and the addresses it
generates.

A known-good multisig descriptor is the user's ground truth for which outputs
are change and which addresses are theirs, so a parser disagreement there would
silently move funds out of the wallet's view.
"""
from dataclasses import dataclass, field

from seedsigner.crosscheck import CrossCheckCode, CrossCheckError, get_wally
from seedsigner.crosscheck.keys import address, parse_extended_key, path_from_str


# How many receive and change addresses are compared at import.
ADDRESSES_COMPARED = 5



@dataclass
class DescriptorKeyClaim:
    fingerprint: str           # hex
    origin_path: list[int]     # account path, hardened indexes with the high bit set
    xpub: str                  # base58 as embit holds it



@dataclass
class DescriptorClaims:
    descriptor: str
    network: str
    keys: list[DescriptorKeyClaim] = field(default_factory=list)
    num_branches: int = 1
    # (branch, index) -> address embit generates
    addresses: dict[tuple[int, int], str] = field(default_factory=dict)



def _fail(detail: str):
    raise CrossCheckError(CrossCheckCode.DESCRIPTOR, detail)


def parse(descriptor: str):
    """
    Parse with libwally. Network-agnostic on purpose: embit accepts a descriptor's
    keys whatever network they name (that mismatch is the flow's to report), and
    the cross-check is about whether the two libraries agree on what it means.
    Addresses are then encoded for the configured network by keys.address.
    """
    w = get_wally()
    if w is None:
        return None
    try:
        return w.descriptor_parse(descriptor, None, w.WALLY_NETWORK_NONE, 0)
    except ValueError:
        _fail("libwally cannot parse the descriptor")


def descriptor_script(descriptor: str, branch: int, index: int, parsed=None) -> bytes | None:
    """The descriptor's scriptPubKey at (branch, index) per libwally; None if skipped."""
    w = get_wally()
    if w is None:
        return None
    d = parsed if parsed is not None else parse(descriptor)
    num_paths = w.descriptor_get_num_paths(d)
    multi_index = branch if num_paths > 1 else 0
    if multi_index >= num_paths:
        _fail(f"descriptor has no branch {branch}")
    try:
        return bytes(w.descriptor_to_script(d, 0, 0, 0, multi_index, index, 0))
    except ValueError:
        _fail(f"libwally cannot derive the descriptor at {branch}/{index}")


def descriptor_address(descriptor: str, network: str, branch: int, index: int, parsed=None) -> str | None:
    """The descriptor's address at (branch, index) per libwally; None if skipped."""
    spk = descriptor_script(descriptor, branch, index, parsed)
    return None if spk is None else address(spk, network)


def check_descriptor(claims: DescriptorClaims) -> None:
    w = get_wally()
    if w is None:
        return

    d = parse(claims.descriptor)

    num_keys = w.descriptor_get_num_keys(d)
    if num_keys != len(claims.keys):
        _fail(f"key count differs (libwally {num_keys}, embit {len(claims.keys)})")

    for i, key in enumerate(claims.keys):
        try:
            fingerprint = bytes(w.descriptor_get_key_origin_fingerprint(d, i)).hex()
            origin_path = path_from_str(w.descriptor_get_key_origin_path_str(d, i))
        except ValueError:
            # No [fingerprint/path] origin on this key.
            fingerprint, origin_path = "", []
        if fingerprint != key.fingerprint:
            _fail(f"key {i} fingerprint differs")
        if origin_path != list(key.origin_path):
            _fail(f"key {i} origin path differs")

        theirs = parse_extended_key(key.xpub, CrossCheckCode.DESCRIPTOR)
        mine = parse_extended_key(w.descriptor_get_key(d, i), CrossCheckCode.DESCRIPTOR)
        if (bytes(w.bip32_key_get_pub_key(mine)) != bytes(w.bip32_key_get_pub_key(theirs))
                or bytes(w.bip32_key_get_chain_code(mine)) != bytes(w.bip32_key_get_chain_code(theirs))):
            _fail(f"key {i} xpub differs")

    num_paths = w.descriptor_get_num_paths(d)
    if num_paths != claims.num_branches:
        _fail(f"branch count differs (libwally {num_paths}, embit {claims.num_branches})")

    for (branch, index), expected in claims.addresses.items():
        if descriptor_address(claims.descriptor, claims.network, branch, index, parsed=d) != expected:
            _fail(f"address {branch}/{index} differs")
