"""
PSBT cross-check: libwally independently parses the psbt and must agree with
what embit (and PSBTParser on top of it) is about to show the user; after signing
it must agree that every signature commits to that same transaction under this
seed's keys.

Checks, in flow order:

  check_parsed      after PSBTParser.parse(), before any review screen
                    - wally parses the raw bytes as received
                    - field-by-field diff of the transaction summary: version,
                      locktime, txid, every input's outpoint/sequence/utxo/sighash,
                      every output's amount/script/address, totals, fee
                    - every change output re-verified from the seed's own keys:
                      single-sig by rebuilding the script, multisig by rebuilding
                      the script and re-tying every cosigner key (global xpubs or
                      the loaded descriptor)
                    - and the converse: a single-sig output wally proves pays this
                      seed must not be shown as a payment to someone else

  binding           psbt_binding() at the end of review, check_binding() right
                    before signing: the psbt about to be signed is byte-for-byte
                    the one that was reviewed

  check_signed      after signing, before export
                    - the signed psbt still describes the reviewed transaction
                    - every signature this seed added verifies, under the
                      wally-derived key, against a wally-computed sighash
                    - signatures were added to exactly the inputs this seed owns
                    - ECDSA: wally re-signs and must produce identical bytes
                    - complete psbts: wally finalizes and extracts a copy, and
                      that transaction must be the reviewed one
"""
import hashlib
from dataclasses import dataclass, field

from seedsigner.crosscheck import CrossCheckCode, CrossCheckError, NETWORK_MAINNET, get_wally
from seedsigner.crosscheck import keys as K
from seedsigner.crosscheck.descriptor import descriptor_script
from seedsigner.crosscheck.secrets import SecretScratch


SINGLESIG_TYPES = (K.SINGLESIG_P2PKH, K.SINGLESIG_P2WPKH, K.SINGLESIG_P2SH_P2WPKH, K.SINGLESIG_P2TR)

CHANGE_BASIS_COSIGNERS = "cosigners"
CHANGE_BASIS_DESCRIPTOR = "descriptor"

SIGHASH_DEFAULT = 0
SIGHASH_ALL = 1



@dataclass
class InputClaim:
    txid: bytes                 # internal (serialized) byte order
    vout: int
    sequence: int
    amount: int | None
    script_pubkey: bytes | None
    sighash: int | None



@dataclass
class OutputClaim:
    amount: int
    script_pubkey: bytes
    # The address the review screens show for this output; None where none is shown
    # (OP_RETURN).
    address: str | None



@dataclass
class ChangeClaim:
    output_index: int
    path: list[int]             # full path of this seed's key in the output



@dataclass
class PSBTClaims:
    raw: bytes
    network: str = NETWORK_MAINNET
    tx_version: int = 0
    locktime: int = 0
    txid: bytes = b""
    inputs: list[InputClaim] = field(default_factory=list)
    outputs: list[OutputClaim] = field(default_factory=list)
    input_total: int = 0
    fee: int = 0

    # Wallet policy as PSBTParser resolved it; "p2wpkh", "p2wsh", ... None when the
    # parser had no policy (nothing to verify change against).
    policy_type: str | None = None
    m: int | None = None
    n: int | None = None
    change: list[ChangeClaim] = field(default_factory=list)
    multisig_change_basis: str | None = None

    # The key change and signatures are verified against. With a seed, libwally
    # builds the master key itself from the seed bytes (or the seed's xprv); a
    # smartcard flow only has the public key at root_path (an account key), from
    # which the unhardened change/receive levels are still derivable. All None
    # when signing with a bare private key (WIF), where there is no tree.
    seed_bytes: bytes | None = None
    xprv: str | None = None
    root_xpub: str | None = None
    root_path: list[int] = field(default_factory=list)
    master_fingerprint: bytes = b""

    # Coordinator-supplied global xpubs, (base58, account path); claims, which wally
    # re-derives from rather than trusts.
    global_xpubs: list[tuple[str, list[int]]] = field(default_factory=list)
    descriptor: str | None = None



@dataclass
class SignerClaims:
    """What signing is expected to have done."""
    # input index -> full paths of this seed's keys in that input
    owned_inputs: dict[int, list[list[int]]] = field(default_factory=dict)
    # Whether the seed's own key signed (rather than a smartcard): only then can
    # libwally re-sign and compare signature bytes.
    resign: bool = False



def _fail(code: str, detail: str):
    raise CrossCheckError(code, detail)


def has_key_tree(claims: PSBTClaims) -> bool:
    return claims.seed_bytes is not None or claims.xprv is not None or claims.root_xpub is not None


def _verification_root(w, claims: PSBTClaims, code: str):
    """
    The key at claims.root_path, built by libwally: private when the seed is at
    hand (so hardened levels derive), else the smartcard's public account key.
    """
    return K.key_from_secret(claims.network, claims.seed_bytes, claims.xprv, claims.root_xpub, code)



def _compact_size(data: bytes, pos: int) -> tuple[int, int]:
    first = data[pos]
    if first < 0xFD:
        return first, pos + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    return int.from_bytes(data[pos + 1:pos + 1 + width], "little"), pos + 1 + width


def _strip_global_xpubs(raw: bytes) -> bytes | None:
    """
    `raw` with its PSBT_GLOBAL_XPUB entries removed, or None if the global map
    can't be walked. See _wally_parse for why.
    """
    if raw[:5] != b"psbt\xff":
        return None
    try:
        out = bytearray(raw[:5])
        pos = 5
        while True:
            start = pos
            key_len, pos = _compact_size(raw, pos)
            if key_len == 0:
                out += raw[start:pos]
                break
            key = raw[pos:pos + key_len]
            pos += key_len
            val_len, pos = _compact_size(raw, pos)
            pos += val_len
            if pos > len(raw):
                return None
            if key[0] != 0x01:
                out += raw[start:pos]
        out += raw[pos:]
        return bytes(out)
    except (IndexError, KeyError):
        return None


def _wally_parse(w, raw: bytes):
    """
    Parse with libwally, refusing what it refuses -- with one exception.

    wally validates every PSBT_GLOBAL_XPUB entry and rejects the whole psbt over
    one that doesn't decode. A malformed global xpub is coordinator metadata
    SeedSigner never trusts for ownership (change is proven by re-derivation), and
    embit tolerates it, so refusing on it alone would refuse psbts that are
    otherwise sound. If wally accepts the psbt once those entries are removed,
    the rest of it is cross-checked as normal.
    """
    try:
        return w.psbt_from_bytes(raw, 0)
    except ValueError:
        pass
    stripped = _strip_global_xpubs(raw)
    if stripped is not None and stripped != raw:
        try:
            return w.psbt_from_bytes(stripped, 0)
        except ValueError:
            pass
    _fail(CrossCheckCode.PARSE, "libwally rejects the psbt")


def _unsigned_tx(w, wp):
    try:
        return w.psbt_extract(wp, w.WALLY_PSBT_EXTRACT_NON_FINAL)
    except ValueError:
        _fail(CrossCheckCode.PARSE, "libwally cannot build the transaction")


def _input_utxo(w, wp, i):
    """(amount, scriptPubKey) of input i's spent output, per wally; (None, None) if absent."""
    try:
        utxo = w.psbt_get_input_best_utxo_alloc(wp, i)
    except ValueError:
        return None, None
    if utxo is None:
        return None, None
    return w.tx_output_get_satoshi(utxo), bytes(w.tx_output_get_script(utxo))



def _diff(w, wp, tx, claims: PSBTClaims):
    def mismatch(what):
        _fail(CrossCheckCode.MISMATCH, what)

    if w.tx_get_version(tx) != claims.tx_version:
        mismatch("tx version")
    if w.tx_get_locktime(tx) != claims.locktime:
        mismatch("locktime")
    if bytes(w.tx_get_txid(tx)) != bytes(claims.txid):
        mismatch("txid")

    num_inputs = w.tx_get_num_inputs(tx)
    if num_inputs != len(claims.inputs):
        mismatch("input count")

    input_total = 0
    for i, claim in enumerate(claims.inputs):
        if bytes(w.tx_get_input_txhash(tx, i)) != bytes(claim.txid):
            mismatch(f"input {i} previous txid")
        if w.tx_get_input_index(tx, i) != claim.vout:
            mismatch(f"input {i} previous output index")
        if w.tx_get_input_sequence(tx, i) != claim.sequence:
            mismatch(f"input {i} sequence")

        sighash = w.psbt_get_input_sighash(wp, i)
        if (sighash or None) != (claim.sighash or None):
            mismatch(f"input {i} sighash type")

        amount, spk = _input_utxo(w, wp, i)
        if amount != claim.amount or spk != (bytes(claim.script_pubkey) if claim.script_pubkey is not None else None):
            mismatch(f"input {i} spent output")
        input_total += amount or 0

        # The full previous transaction, where given, must be the one the outpoint
        # names, and must pay what the witness utxo (if any) says.
        try:
            prev_tx = w.psbt_get_input_utxo(wp, i)
        except ValueError:
            prev_tx = None
        if prev_tx is not None:
            if bytes(w.tx_get_txid(prev_tx)) != bytes(claim.txid):
                mismatch(f"input {i} previous transaction is not the one spent")
            if claim.vout >= w.tx_get_num_outputs(prev_tx):
                mismatch(f"input {i} previous transaction has no output {claim.vout}")
            prev_amount = w.tx_get_output_satoshi(prev_tx, claim.vout)
            prev_spk = bytes(w.tx_get_output_script(prev_tx, claim.vout))
            if (prev_amount, prev_spk) != (amount, spk):
                mismatch(f"input {i} previous transaction disagrees with its witness utxo")

    if input_total != claims.input_total:
        mismatch("input total")

    num_outputs = w.tx_get_num_outputs(tx)
    if num_outputs != len(claims.outputs):
        mismatch("output count")

    output_total = 0
    for i, claim in enumerate(claims.outputs):
        amount = w.tx_get_output_satoshi(tx, i)
        spk = bytes(w.tx_get_output_script(tx, i))
        if amount != claim.amount:
            mismatch(f"output {i} amount")
        if spk != bytes(claim.script_pubkey):
            mismatch(f"output {i} script")
        if claim.address is not None and K.address(spk, claims.network) != claim.address:
            mismatch(f"output {i} address")
        output_total += amount

    if input_total - output_total != claims.fee:
        mismatch("fee")



def _keypath(w, wp, scope: str, index: int, pubkey: bytes) -> tuple[bytes, list[int]] | None:
    find = w.psbt_find_input_keypath if scope == "in" else w.psbt_find_output_keypath
    get = w.psbt_get_input_keypath if scope == "in" else w.psbt_get_output_keypath
    found = find(wp, index, pubkey)
    if not found:
        return None
    return K.decode_keypath(get(wp, index, found - 1))


def _scope_multisig_script(w, wp, scope: str, index: int, policy_type: str) -> bytes | None:
    if policy_type in ("p2wsh", "p2sh-p2wsh"):
        getter, size = (
            (w.psbt_get_input_witness_script, w.psbt_get_input_witness_script_len) if scope == "in"
            else (w.psbt_get_output_witness_script, w.psbt_get_output_witness_script_len)
        )
    else:
        getter, size = (
            (w.psbt_get_input_redeem_script, w.psbt_get_input_redeem_script_len) if scope == "in"
            else (w.psbt_get_output_redeem_script, w.psbt_get_output_redeem_script_len)
        )
    if not size(wp, index):
        return None
    return bytes(getter(wp, index))


def _multisig_script_pubkey(policy_type: str, script: bytes) -> bytes:
    if policy_type == "p2wsh":
        return K.p2wsh(script)
    if policy_type == "p2sh-p2wsh":
        return K.p2sh(K.p2wsh(script))
    return K.p2sh(script)


def _cosigners(w, wp, scope: str, index: int, pubkeys: list[bytes], global_xpubs, cache: dict) -> list[str] | None:
    """
    The global xpubs that provably derive every key in a multisig script (wally
    derivation), as a sorted list of their key material; None if any key can't
    be tied to one. Mirrors what PSBTParser._get_cosigners proves with embit.
    """
    found = []
    for pubkey in pubkeys:
        keypath = _keypath(w, wp, scope, index, pubkey)
        if keypath is None:
            return None
        _, path = keypath
        match = None
        for b58, account_path in global_xpubs:
            if list(account_path) != list(path[:-2]):
                continue
            if b58 not in cache:
                cache[b58] = K.parse_extended_key(b58)
            if K.derive_pubkey(cache[b58], path[-2:]) == bytes(pubkey):
                match = bytes(w.bip32_key_get_pub_key(cache[b58])).hex()
                break
        if match is None:
            return None
        found.append(match)
    return sorted(found)


def _check_change(w, wp, tx, claims: PSBTClaims):
    def fail(what):
        _fail(CrossCheckCode.CHANGE, what)

    if not claims.change:
        return
    if not has_key_tree(claims) and claims.multisig_change_basis != CHANGE_BASIS_DESCRIPTOR:
        fail("change claimed without a key to verify it against")

    root = _verification_root(w, claims, CrossCheckCode.CHANGE)
    is_multisig = claims.m is not None
    xpub_cache = {}
    input_cosigners = None

    for change in claims.change:
        i = change.output_index
        if i >= w.tx_get_num_outputs(tx):
            fail(f"change output {i} does not exist")
        spk = bytes(w.tx_get_output_script(tx, i))

        our_pubkey = None
        if root is not None:
            rel = K.relative_path(change.path, claims.root_path)
            if rel is None:
                fail(f"output {i} change path is outside the signing key")
            our_pubkey = K.derive_pubkey(root, rel)

        if not is_multisig:
            if claims.policy_type not in SINGLESIG_TYPES:
                fail(f"output {i}: unsupported change type {claims.policy_type}")
            if K.singlesig_script(claims.policy_type, our_pubkey) != spk:
                fail(f"output {i} does not pay this seed's key")
            if claims.policy_type != K.SINGLESIG_P2TR:
                keypath = _keypath(w, wp, "out", i, our_pubkey)
                if keypath is None or keypath[1] != list(change.path):
                    fail(f"output {i} does not claim this seed's key at its change path")
            continue

        script = _scope_multisig_script(w, wp, "out", i, claims.policy_type)
        parsed = K.parse_multisig(script) if script is not None else None
        if parsed is None:
            fail(f"output {i} change script is not multisig")
        m, pubkeys = parsed
        if (m, len(pubkeys)) != (claims.m, claims.n):
            fail(f"output {i} change is {m}-of-{len(pubkeys)}, wallet is {claims.m}-of-{claims.n}")
        if _multisig_script_pubkey(claims.policy_type, script) != spk:
            fail(f"output {i} does not commit to its change script")
        if our_pubkey is not None and our_pubkey not in pubkeys:
            fail(f"output {i} change script lacks this seed's key")

        if claims.multisig_change_basis == CHANGE_BASIS_DESCRIPTOR:
            branch, index = change.path[-2], change.path[-1]
            if descriptor_script(claims.descriptor, branch, index) != spk:
                fail(f"output {i} is not the descriptor's address at {branch}/{index}")

        elif claims.multisig_change_basis == CHANGE_BASIS_COSIGNERS:
            if input_cosigners is None:
                in_script = _scope_multisig_script(w, wp, "in", 0, claims.policy_type)
                in_parsed = K.parse_multisig(in_script) if in_script is not None else None
                if in_parsed is None:
                    fail("input 0 script is not multisig")
                input_cosigners = _cosigners(w, wp, "in", 0, in_parsed[1], claims.global_xpubs, xpub_cache)
                if input_cosigners is None:
                    fail("libwally cannot tie the inputs' keys to the global xpubs")
            if _cosigners(w, wp, "out", i, pubkeys, claims.global_xpubs, xpub_cache) != input_cosigners:
                fail(f"output {i} change keys are not the inputs' cosigners")

        else:
            fail(f"output {i} multisig change has no verification basis")


def _check_unclaimed_singlesig_change(w, wp, tx, claims: PSBTClaims):
    """
    The converse of _check_change for single-sig: an output libwally proves pays
    this seed, at a path it claims, must be among the outputs shown as the seed's
    own -- not displayed as a payment to someone else.
    """
    if claims.m is not None or not has_key_tree(claims) or claims.policy_type not in SINGLESIG_TYPES:
        return
    if claims.policy_type == K.SINGLESIG_P2TR:
        # wally 1.5 exposes no accessor for an output's taproot keypaths.
        return

    root = _verification_root(w, claims, CrossCheckCode.CHANGE)
    shown_as_ours = {c.output_index for c in claims.change}
    fingerprints = {bytes(claims.master_fingerprint), b"\x00\x00\x00\x00"}

    for i in range(w.tx_get_num_outputs(tx)):
        if i in shown_as_ours or w.psbt_get_output_keypaths_size(wp, i) != 1:
            continue
        fingerprint, path = K.decode_keypath(w.psbt_get_output_keypath(wp, i, 0))
        rel = K.relative_path(path, claims.root_path)
        if fingerprint not in fingerprints or rel is None:
            continue
        spk = bytes(w.tx_get_output_script(tx, i))
        if K.singlesig_script(claims.policy_type, K.derive_pubkey(root, rel)) == spk:
            _fail(CrossCheckCode.CHANGE, f"output {i} pays this seed but is shown as a payment")



def check_parsed(claims: PSBTClaims) -> None:
    """Raise CrossCheckError unless libwally agrees with PSBTParser's reading."""
    w = get_wally()
    if w is None:
        return
    wp = _wally_parse(w, bytes(claims.raw))
    tx = _unsigned_tx(w, wp)
    _diff(w, wp, tx, claims)
    _check_change(w, wp, tx, claims)
    _check_unclaimed_singlesig_change(w, wp, tx, claims)



def psbt_binding(serialized: bytes) -> tuple[bytes, bytes] | None:
    """
    (wally's BIP-370 unique id, sha256 of the bytes) for the psbt as reviewed.
    The id covers the unsigned transaction; the hash covers everything else too.
    """
    w = get_wally()
    if w is None:
        return None
    wp = _wally_parse(w, bytes(serialized))
    return bytes(w.psbt_get_id(wp, 0)), hashlib.sha256(bytes(serialized)).digest()


def check_binding(reviewed: tuple[bytes, bytes] | None, serialized: bytes) -> None:
    """Raise CrossCheckError unless `serialized` is the psbt that was reviewed."""
    w = get_wally()
    if w is None:
        return
    if reviewed is None:
        _fail(CrossCheckCode.SWAPPED, "no record of the reviewed psbt")
    if psbt_binding(serialized) != tuple(reviewed):
        _fail(CrossCheckCode.SWAPPED, "the psbt changed after it was reviewed")



def _witness_items(w, stack) -> list[bytes]:
    data = bytes(w.tx_witness_stack_to_bytes(stack))
    count, pos = _compact_size(data, 0)
    items = []
    for _ in range(count):
        size, pos = _compact_size(data, pos)
        items.append(data[pos:pos + size])
        pos += size
    return items


def _ecdsa_digest(w, wp, tx, i, spk, amount, pubkey, sighash_type) -> bytes:
    """
    The digest an ECDSA signature by `pubkey` on input i commits to, by libwally.

    Uses the transaction-level digest function with the spend type decided here
    from the prevout script, rather than psbt_get_input_signature_hash: that one
    computes a legacy digest for a segwit input whose psbt carries only the full
    previous transaction.
    """
    def script_of(getter, size):
        return bytes(getter(wp, i)) if size(wp, i) else None

    witness_script = script_of(w.psbt_get_input_witness_script, w.psbt_get_input_witness_script_len)
    redeem_script = script_of(w.psbt_get_input_redeem_script, w.psbt_get_input_redeem_script_len)
    p2pkh_code = K.singlesig_script(K.SINGLESIG_P2PKH, pubkey)
    witness = w.WALLY_TX_FLAG_USE_WITNESS

    t = K.script_type(spk)
    if t == w.WALLY_SCRIPT_TYPE_P2WPKH:
        code, flags = p2pkh_code, witness
    elif t == w.WALLY_SCRIPT_TYPE_P2WSH:
        code, flags = witness_script, witness
    elif t == w.WALLY_SCRIPT_TYPE_P2SH and witness_script is not None:
        code, flags = witness_script, witness
    elif (t == w.WALLY_SCRIPT_TYPE_P2SH and redeem_script is not None
            and K.script_type(redeem_script) == w.WALLY_SCRIPT_TYPE_P2WPKH):
        code, flags = p2pkh_code, witness
    elif t == w.WALLY_SCRIPT_TYPE_P2SH:
        code, flags = redeem_script, 0
    elif t == w.WALLY_SCRIPT_TYPE_P2PKH:
        code, flags = spk, 0
    else:
        raise ValueError("unsupported input type")
    if code is None:
        raise ValueError("missing script")
    return bytes(w.tx_get_btc_signature_hash(tx, i, code, amount, sighash_type, flags))


def check_signed(signed: bytes, claims: PSBTClaims, signer: SignerClaims) -> None:
    """Raise CrossCheckError unless every new signature is sound by libwally's reckoning."""
    w = get_wally()
    if w is None:
        return

    def fail(what):
        _fail(CrossCheckCode.SIGNATURE, what)

    wp = _wally_parse(w, bytes(signed))
    tx = _unsigned_tx(w, wp)

    # (a) still the reviewed transaction
    try:
        _diff(w, wp, tx, claims)
    except CrossCheckError as e:
        fail(f"signed psbt differs from the reviewed one: {e.detail}")

    if not has_key_tree(claims):
        # Bare private key (WIF): no tree to derive the signing key from.
        return

    root = _verification_root(w, claims, CrossCheckCode.SIGNATURE)
    num_inputs = w.tx_get_num_inputs(tx)
    prevout_scripts = w.map_init_alloc(num_inputs, None)
    prevout_values = []
    for i in range(num_inputs):
        amount, spk = _input_utxo(w, wp, i)
        if spk is None:
            fail(f"input {i} has no spent output")
        w.map_add_integer(prevout_scripts, i, spk)
        prevout_values.append(amount)

    with SecretScratch() as scratch:
        signing_root = root if signer.resign and (claims.seed_bytes is not None or claims.xprv is not None) else None

        signed_inputs = set()
        for i in range(num_inputs):
            amount, spk = _input_utxo(w, wp, i)
            is_taproot = K.script_type(spk) == w.WALLY_SCRIPT_TYPE_P2TR
            paths = signer.owned_inputs.get(i, [])

            if is_taproot:
                sig = None
                if w.psbt_get_input_taproot_signature_len(wp, i):
                    sig = bytes(w.psbt_get_input_taproot_signature(wp, i))
                else:
                    try:
                        stack = w.psbt_get_input_final_witness_alloc(wp, i)
                    except ValueError:
                        stack = None
                    if stack is not None:
                        items = _witness_items(w, stack)
                        if len(items) == 1 and len(items[0]) in (64, 65):
                            sig = items[0]
                if sig is None:
                    continue
                if not paths:
                    fail(f"input {i} was signed but this seed owns no key in it")
                signed_inputs.add(i)

                sighash_type = sig[64] if len(sig) == 65 else SIGHASH_DEFAULT
                if sighash_type != (claims.inputs[i].sighash or SIGHASH_DEFAULT):
                    fail(f"input {i} signature uses an unexpected sighash type")
                digest = w.tx_get_btc_taproot_signature_hash(
                    tx, i, prevout_scripts, prevout_values, None, 0, 0xFFFFFFFF, None, sighash_type, 0)
                for path in paths:
                    rel = K.relative_path(path, claims.root_path)
                    if rel is None:
                        continue
                    expected_spk = K.singlesig_script(K.SINGLESIG_P2TR, K.derive_pubkey(root, rel))
                    if expected_spk == spk:
                        break
                else:
                    fail(f"input {i} is not a key-path spend of this seed's key")
                try:
                    w.ec_sig_verify(spk[2:], bytes(digest), w.EC_FLAG_SCHNORR, sig[:64])
                except ValueError:
                    fail(f"input {i} schnorr signature does not verify")
                continue

            for path in paths:
                rel = K.relative_path(path, claims.root_path)
                if rel is None:
                    fail(f"input {i} key path is outside the signing key")
                pubkey = K.derive_pubkey(root, rel)
                found = w.psbt_find_input_signature(wp, i, pubkey)
                if not found:
                    continue
                signed_inputs.add(i)
                sig = bytes(w.psbt_get_input_signature(wp, i, found - 1))
                sighash_type = sig[-1]
                if sighash_type != (claims.inputs[i].sighash or SIGHASH_ALL):
                    fail(f"input {i} signature uses an unexpected sighash type")

                try:
                    digest = _ecdsa_digest(w, wp, tx, i, spk, amount, pubkey, sighash_type)
                except ValueError as e:
                    fail(f"input {i}: {e}")

                try:
                    compact = w.ec_sig_from_der(sig[:-1])
                    w.ec_sig_verify(pubkey, digest, w.EC_FLAG_ECDSA, compact)
                except ValueError:
                    fail(f"input {i} signature does not verify")

                if signing_root is not None:
                    child = w.bip32_key_from_parent_path(signing_root, rel, w.BIP32_FLAG_KEY_PRIVATE)
                    priv = scratch.keep(w.bip32_key_get_priv_key(child))
                    del child
                    # embit grinds for a low R value, as Bitcoin Core does.
                    ours = bytes(w.ec_sig_to_der(w.ec_sig_from_bytes(priv, digest, w.EC_FLAG_ECDSA | w.EC_FLAG_GRIND_R)))
                    if ours != sig[:-1]:
                        fail(f"input {i} signature differs from libwally's")

        del signing_root, root

    expected = {i for i, paths in signer.owned_inputs.items() if paths}
    if signed_inputs != expected:
        missing = sorted(expected - signed_inputs)
        extra = sorted(signed_inputs - expected)
        fail(f"signed inputs differ (unsigned: {missing}, unexpected: {extra})")

    # (d) a complete psbt must finalize, in libwally, to the reviewed transaction
    clone = w.psbt_clone_alloc(wp, 0)
    try:
        w.psbt_finalize(clone, 0)
    except ValueError:
        return
    if not w.psbt_is_finalized(clone):
        return
    try:
        final_tx = w.psbt_extract(clone, w.WALLY_PSBT_EXTRACT_FINAL)
    except ValueError:
        fail("libwally cannot extract the finalized transaction")
    if w.tx_get_num_inputs(final_tx) != num_inputs:
        fail("finalized transaction has a different input count")
    for i in range(num_inputs):
        if (bytes(w.tx_get_input_txhash(final_tx, i)), w.tx_get_input_index(final_tx, i), w.tx_get_input_sequence(final_tx, i)) != \
                (bytes(claims.inputs[i].txid), claims.inputs[i].vout, claims.inputs[i].sequence):
            fail(f"finalized transaction input {i} differs")
    if w.tx_get_num_outputs(final_tx) != len(claims.outputs):
        fail("finalized transaction has a different output count")
    for i, claim in enumerate(claims.outputs):
        if (w.tx_get_output_satoshi(final_tx, i), bytes(w.tx_get_output_script(final_tx, i))) != (claim.amount, bytes(claim.script_pubkey)):
            fail(f"finalized transaction output {i} differs")
    if (w.tx_get_version(final_tx), w.tx_get_locktime(final_tx)) != (claims.tx_version, claims.locktime):
        fail("finalized transaction version or locktime differs")



def _input_signatures(w, wp, i) -> tuple[set[bytes], bytes | None]:
    sigs = {bytes(w.psbt_get_input_signature(wp, i, j)) for j in range(w.psbt_get_input_signatures_size(wp, i))}
    try:
        stack = w.psbt_get_input_final_witness_alloc(wp, i)
    except ValueError:
        stack = None
    witness = bytes(w.tx_witness_stack_to_bytes(stack)) if stack is not None else None
    return sigs, witness


def check_trimmed(trimmed: bytes, signed: bytes, claims: PSBTClaims) -> None:
    """
    The psbt actually exported (PSBTParser.trim drops everything but the
    signatures) must be the reviewed transaction carrying exactly the signatures
    check_signed verified on the full signed psbt.
    """
    w = get_wally()
    if w is None:
        return
    wp_trim = _wally_parse(w, bytes(trimmed))
    wp_full = _wally_parse(w, bytes(signed))
    if bytes(w.tx_get_txid(_unsigned_tx(w, wp_trim))) != bytes(claims.txid):
        _fail(CrossCheckCode.SIGNATURE, "exported psbt is not the reviewed transaction")
    for i in range(w.psbt_get_num_inputs(wp_full)):
        if _input_signatures(w, wp_trim, i) != _input_signatures(w, wp_full, i):
            _fail(CrossCheckCode.SIGNATURE, f"exported psbt input {i} signatures differ from the verified ones")
