"""
libwally helpers shared by the cross-checks: extended key parsing, derivation,
script rebuilding and address encoding. Nothing here imports embit.
"""
from seedsigner.helpers.secure_delete import wipe_bytes
from seedsigner.crosscheck import CrossCheckCode, CrossCheckError, NETWORK_MAINNET, _wally as w, bech32_hrp, wally_network


HARDENED = 0x80000000



def parse_extended_key(b58: str, code: str = CrossCheckCode.MISMATCH):
    """
    Parse an xpub/xprv (or a SLIP-132 variant such as zpub/Vprv) with libwally's own
    base58check decoder.

    wally only accepts the plain BIP32 versions; a SLIP-132 key differs from one
    only in its four version bytes, so those are swapped before parsing. The
    key material is what's being checked, and that is untouched.
    """
    raw = w.base58_to_bytes(b58, w.BASE58_FLAG_CHECKSUM)  # a bytearray; wiped below
    try:
        if len(raw) != 78:
            raise CrossCheckError(code, "extended key has the wrong length")
        is_private = raw[45] == 0
        version = int.from_bytes(raw[0:4], "big")
        plain = (
            (w.BIP32_VER_MAIN_PRIVATE, w.BIP32_VER_TEST_PRIVATE) if is_private
            else (w.BIP32_VER_MAIN_PUBLIC, w.BIP32_VER_TEST_PUBLIC)
        )
        if version not in plain:
            raw[0:4] = plain[0].to_bytes(4, "big")
        try:
            return w.bip32_key_unserialize(raw)
        except ValueError:
            raise CrossCheckError(code, "libwally could not parse an extended key")
    finally:
        for i in range(len(raw)):
            raw[i] = 0


def derive_pubkey(key, path: list[int]) -> bytes:
    """Compressed pubkey at `path` below `key` (path relative to `key`)."""
    if not path:
        return bytes(w.bip32_key_get_pub_key(key))
    # A private parent is needed for hardened levels; derive privately when the
    # key has one, then keep only the public half.
    priv = w.bip32_key_get_priv_key(key)
    is_private = any(priv)
    wipe_bytes(priv)
    flags = w.BIP32_FLAG_KEY_PRIVATE if is_private else w.BIP32_FLAG_KEY_PUBLIC
    child = w.bip32_key_from_parent_path(key, list(path), flags)
    try:
        return bytes(w.bip32_key_get_pub_key(child))
    finally:
        del child


def relative_path(full_path: list[int], root_path: list[int]) -> list[int] | None:
    """`full_path` below `root_path`, or None if it isn't below it."""
    if list(full_path[:len(root_path)]) != list(root_path):
        return None
    return list(full_path[len(root_path):])


def decode_keypath(value: bytes) -> tuple[bytes, list[int]]:
    """A PSBT keypath value: 4-byte fingerprint then little-endian uint32 indexes."""
    value = bytes(value)
    if len(value) < 4 or (len(value) - 4) % 4:
        raise CrossCheckError(CrossCheckCode.MISMATCH, "malformed keypath")
    return value[:4], [int.from_bytes(value[i:i + 4], "little") for i in range(4, len(value), 4)]



def script_type(spk: bytes) -> int:
    try:
        return w.scriptpubkey_get_type(bytes(spk))
    except ValueError:
        return w.WALLY_SCRIPT_TYPE_UNKNOWN


def address(spk: bytes, network: str) -> str | None:
    """
    The address for a scriptPubKey, encoded by libwally. None for scripts with no
    address form (OP_RETURN, bare multisig, unknown).
    """
    spk = bytes(spk)
    t = script_type(spk)
    if t in (w.WALLY_SCRIPT_TYPE_P2PKH, w.WALLY_SCRIPT_TYPE_P2SH):
        return w.scriptpubkey_to_address(spk, wally_network(network))
    if t in (w.WALLY_SCRIPT_TYPE_P2WPKH, w.WALLY_SCRIPT_TYPE_P2WSH, w.WALLY_SCRIPT_TYPE_P2TR):
        return w.addr_segwit_from_bytes(spk, bech32_hrp(network), 0)
    # Other witness versions (2-16) are standard addresses too, even if unspendable
    # by design; let the segwit encoder decide.
    if len(spk) >= 4 and (spk[0] == 0 or 0x51 <= spk[0] <= 0x60) and spk[1] == len(spk) - 2:
        try:
            return w.addr_segwit_from_bytes(spk, bech32_hrp(network), 0)
        except ValueError:
            return None
    return None



SINGLESIG_P2PKH = "p2pkh"
SINGLESIG_P2WPKH = "p2wpkh"
SINGLESIG_P2SH_P2WPKH = "p2sh-p2wpkh"
SINGLESIG_P2TR = "p2tr"


def singlesig_script(kind: str, pubkey: bytes) -> bytes:
    pubkey = bytes(pubkey)
    if kind == SINGLESIG_P2PKH:
        return bytes(w.scriptpubkey_p2pkh_from_bytes(pubkey, w.WALLY_SCRIPT_HASH160))
    if kind == SINGLESIG_P2WPKH:
        return bytes(w.witness_program_from_bytes(pubkey, w.WALLY_SCRIPT_HASH160))
    if kind == SINGLESIG_P2SH_P2WPKH:
        redeem = bytes(w.witness_program_from_bytes(pubkey, w.WALLY_SCRIPT_HASH160))
        return bytes(w.scriptpubkey_p2sh_from_bytes(redeem, w.WALLY_SCRIPT_HASH160))
    if kind == SINGLESIG_P2TR:
        # BIP-86 key-path-only output: wally applies the BIP-341 tweak with an
        # empty script tree.
        return bytes(w.scriptpubkey_p2tr_from_bytes(pubkey, 0))
    raise CrossCheckError(CrossCheckCode.MISMATCH, f"unsupported single-sig type {kind}")


def p2wsh(script: bytes) -> bytes:
    return bytes(w.witness_program_from_bytes(bytes(script), w.WALLY_SCRIPT_SHA256))


def p2sh(script: bytes) -> bytes:
    return bytes(w.scriptpubkey_p2sh_from_bytes(bytes(script), w.WALLY_SCRIPT_HASH160))



def parse_multisig(script: bytes) -> tuple[int, list[bytes]] | None:
    """
    (m, pubkeys) for an `OP_m <key>... OP_n OP_CHECKMULTISIG` script, else None.

    The split is done here, but the result only counts once libwally rebuilds the
    exact same script from it: any encoding the simple reader got wrong would
    fail that comparison.
    """
    script = bytes(script)
    if len(script) < 3 or script[-1] != 0xAE:
        return None
    m_op, n_op = script[0], script[-2]
    if not (0x51 <= m_op <= 0x60 and 0x51 <= n_op <= 0x60):
        return None
    m, n = m_op - 0x50, n_op - 0x50
    keys, pos = [], 1
    while pos < len(script) - 2:
        if script[pos] != 33:
            return None
        keys.append(script[pos + 1:pos + 34])
        pos += 34
    if pos != len(script) - 2 or len(keys) != n or not 1 <= m <= n:
        return None

    rebuilt = bytes(w.scriptpubkey_multisig_from_bytes(b"".join(keys), m, 0))
    if rebuilt != script:
        return None
    return m, keys



def path_from_str(path: str) -> list[int]:
    """'m/84h/0h/0h' (or with ') as BIP32 indexes."""
    out = []
    for part in [p for p in path.split("/") if p and p != "m"]:
        hardened = part[-1] in "h'H"
        index = int(part[:-1] if hardened else part)
        out.append(index | HARDENED if hardened else index)
    return out


def key_from_secret(network: str, seed_bytes: bytes | None = None, xprv: str | None = None,
                    xpub: str | None = None, code: str = CrossCheckCode.MISMATCH):
    """
    A libwally extended key from whichever source is at hand: the master key
    built by libwally from the seed bytes, a parsed xprv, or (smartcard flows) a
    parsed public key. None if none is given.
    """
    if seed_bytes is not None:
        version = w.BIP32_VER_MAIN_PRIVATE if network == NETWORK_MAINNET else w.BIP32_VER_TEST_PRIVATE
        return w.bip32_key_from_seed(seed_bytes, version, 0)
    if xprv is not None:
        return parse_extended_key(xprv, code)
    if xpub is not None:
        return parse_extended_key(xpub, code)
    return None
