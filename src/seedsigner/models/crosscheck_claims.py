"""
The embit side of the libwally cross-check: pulls plain values out of embit
objects for `seedsigner.crosscheck`, which never imports embit itself.
"""
from seedsigner.crosscheck.seed import (
    KIND_BIP39, KIND_ELECTRUM, KIND_SEED_BYTES, KIND_XPRV, SeedClaims, check_seed,
)
from seedsigner.helpers.embit_utils import get_standard_derivation_path
from seedsigner.models.seed import AezeedSeed, ElectrumSeed, Seed, Slip39Seed, XprvSeed
from seedsigner.models.settings_definition import SettingsConstants



def _account_paths(seed: Seed, network: str) -> list[str]:
    paths = []
    for script_type in (SettingsConstants.NATIVE_SEGWIT, SettingsConstants.NESTED_SEGWIT,
                        SettingsConstants.LEGACY_P2PKH, SettingsConstants.TAPROOT):
        paths.append(get_standard_derivation_path(network, SettingsConstants.SINGLE_SIG, script_type))
    for script_type in (SettingsConstants.NATIVE_SEGWIT, SettingsConstants.NESTED_SEGWIT):
        paths.append(get_standard_derivation_path(network, SettingsConstants.MULTISIG, script_type))

    override = seed.derivation_override(SettingsConstants.SINGLE_SIG)
    if override and override not in paths:
        paths.append(override)
    return paths


def seed_claims(seed: Seed, network: str) -> SeedClaims:
    if isinstance(seed, XprvSeed):
        claims = SeedClaims(kind=KIND_XPRV, xprv=seed._xprv)
    elif isinstance(seed, (AezeedSeed, Slip39Seed)):
        claims = SeedClaims(kind=KIND_SEED_BYTES, seed_bytes=seed.seed_bytes)
    elif isinstance(seed, ElectrumSeed):
        claims = SeedClaims(kind=KIND_ELECTRUM, mnemonic=seed.mnemonic_str,
                            passphrase=seed.passphrase, seed_bytes=seed.seed_bytes)
    else:
        claims = SeedClaims(kind=KIND_BIP39, mnemonic=seed.mnemonic_str,
                            passphrase=seed.passphrase, seed_bytes=seed.seed_bytes)

    claims.network = network
    claims.fingerprint = seed.get_fingerprint(network)

    root = seed.get_root(network)
    for path in _account_paths(seed, network):
        child = root.derive(path)
        claims.account_keys[path] = (child.get_public_key().sec(), bytes(child.chain_code))
    return claims


def crosscheck_seed(seed: Seed, network: str = None) -> None:
    """Raise CrossCheckError unless libwally re-derives this seed identically."""
    if network is None:
        from seedsigner.models.settings import Settings
        network = Settings.get_instance().get_value(SettingsConstants.SETTING__NETWORK)
    check_seed(seed_claims(seed, network))



# ---------------------------------------------------------------------- psbt

def psbt_claims(parser):
    """What PSBTParser is about to show for its psbt, as plain values."""
    from seedsigner.crosscheck.psbt import (
        CHANGE_BASIS_COSIGNERS, CHANGE_BASIS_DESCRIPTOR, ChangeClaim, InputClaim, OutputClaim, PSBTClaims,
    )

    psbt = parser.psbt
    raw = getattr(psbt, "seedsigner_raw_bytes", None) or psbt.serialize()
    tx = psbt.tx

    claims = PSBTClaims(
        raw=raw,
        network=parser.network,
        tx_version=tx.version,
        locktime=tx.locktime,
        txid=tx.txid()[::-1],
        input_total=parser.input_amount,
        fee=parser.fee_amount,
    )

    for inp in psbt.inputs:
        utxo = inp.utxo
        claims.inputs.append(InputClaim(
            txid=bytes(inp.txid)[::-1],
            vout=inp.vout,
            sequence=inp.sequence,
            amount=utxo.value if utxo is not None else None,
            script_pubkey=utxo.script_pubkey.data if utxo is not None else None,
            sighash=inp.sighash_type,
        ))

    shown = {c["output_index"]: c["address"] for c in parser.change_data}
    shown.update(zip(parser.destination_output_indexes, parser.destination_addresses))
    for i, out in enumerate(tx.vout):
        claims.outputs.append(OutputClaim(
            amount=out.value,
            script_pubkey=out.script_pubkey.data,
            address=shown.get(i),
        ))

    if isinstance(parser.policy, dict):
        claims.policy_type = parser.policy.get("type")
        claims.m = parser.policy.get("m")
        claims.n = parser.policy.get("n")
        if parser.is_multisig:
            # Mirrors _parse_outputs: seedless (no key tree), change is decided by
            # the descriptor alone; otherwise by the global-xpub cosigners when
            # those resolved, else by the descriptor.
            claims.multisig_change_basis = (
                CHANGE_BASIS_COSIGNERS
                if parser.can_verify_derivations and "cosigners" in parser.policy
                else CHANGE_BASIS_DESCRIPTOR
            )

    claims.change = [
        ChangeClaim(output_index=c["output_index"], path=list(c["verified_derivation_path"]))
        for c in parser.change_data
    ]

    if parser.can_verify_derivations:
        seed = parser.seed
        if isinstance(seed, XprvSeed):
            claims.xprv = seed._xprv
        elif isinstance(seed, Seed) and seed.seed_bytes is not None:
            claims.seed_bytes = seed.seed_bytes
        else:
            # Smartcard flows hand over a public account key, not a seed.
            claims.root_xpub = parser.root.to_public().to_base58()
        claims.root_path = list(parser.root_path)
        claims.master_fingerprint = bytes(parser.master_fingerprint or parser.root.my_fingerprint)

    claims.global_xpubs = [(xpub.to_base58(), list(der.derivation)) for xpub, der in psbt.xpubs.items()]
    if parser.multisig_descriptor is not None:
        claims.descriptor = parser.multisig_descriptor.to_string()

    return claims


def signer_claims(parser, seed_signed: bool):
    """What signing should have done; `seed_signed` when the seed (not a card) signed."""
    from seedsigner.crosscheck.psbt import SignerClaims

    return SignerClaims(
        owned_inputs={
            i: [list(d.derivation) for d in paths]
            for i, paths in enumerate(parser.verified_input_derivation_paths)
        },
        resign=seed_signed,
    )



# ---------------------------------------------------------------- descriptor

def wally_descriptor_str(descriptor_str: str) -> str:
    """
    embit's `{0,1}` multipath syntax in the standard BIP-389 form `<0;1>` that
    libwally reads; everything else is passed through untouched.
    """
    import re
    return re.sub(r"\{(\d+(?:,\d+)+)\}", lambda m: "<" + m.group(1).replace(",", ";") + ">", descriptor_str)


def descriptor_claims(descriptor, descriptor_str: str, network: str):
    from embit.networks import NETWORKS
    from seedsigner.crosscheck.descriptor import ADDRESSES_COMPARED, DescriptorClaims, DescriptorKeyClaim

    claims = DescriptorClaims(descriptor=wally_descriptor_str(descriptor_str), network=network)
    for key in descriptor.keys:
        claims.keys.append(DescriptorKeyClaim(
            fingerprint=key.origin.fingerprint.hex() if key.origin else "",
            origin_path=list(key.origin.derivation) if key.origin else [],
            xpub=key.key.to_base58(),
        ))
    claims.num_branches = descriptor.num_branches

    embit_network = NETWORKS[SettingsConstants.map_network_to_embit(network)]
    for branch in range(descriptor.num_branches):
        for index in range(ADDRESSES_COMPARED):
            claims.addresses[(branch, index)] = descriptor.derive(index, branch_index=branch).address(embit_network)
    return claims


def crosscheck_descriptor(descriptor, descriptor_str: str, network: str = None) -> None:
    """Raise CrossCheckError unless libwally reads `descriptor_str` as embit did."""
    from seedsigner.crosscheck.descriptor import check_descriptor
    if network is None:
        from seedsigner.models.settings import Settings
        network = Settings.get_instance().get_value(SettingsConstants.SETTING__NETWORK)
    check_descriptor(descriptor_claims(descriptor, descriptor_str, network))



# ------------------------------------------------------------------- address

def _singlesig_kind(script_type: str) -> str:
    from seedsigner.crosscheck import keys as K
    return {
        SettingsConstants.NATIVE_SEGWIT: K.SINGLESIG_P2WPKH,
        SettingsConstants.NESTED_SEGWIT: K.SINGLESIG_P2SH_P2WPKH,
        SettingsConstants.LEGACY_P2PKH: K.SINGLESIG_P2PKH,
        SettingsConstants.TAPROOT: K.SINGLESIG_P2TR,
    }[script_type]


def crosscheck_seed_address(seed: Seed, address: str, network: str, script_type: str,
                            derivation_path: str, index: int, is_change: bool) -> None:
    """Raise CrossCheckError unless libwally derives `address` from the seed itself."""
    from seedsigner.crosscheck.address import check_singlesig_address
    from seedsigner.crosscheck.keys import path_from_str

    path = path_from_str(derivation_path) + [1 if is_change else 0, index]
    if isinstance(seed, XprvSeed):
        secrets = dict(xprv=seed._xprv)
    else:
        secrets = dict(seed_bytes=seed.seed_bytes)
    check_singlesig_address(address, network, _singlesig_kind(script_type), path, **secrets)


def crosscheck_xpub_address(xpub, address: str, network: str, script_type: str,
                            index: int, is_change: bool) -> None:
    """As crosscheck_seed_address, from an account xpub (embit HDKey) instead."""
    from seedsigner.crosscheck.address import check_singlesig_address
    check_singlesig_address(address, network, _singlesig_kind(script_type),
                            [1 if is_change else 0, index], xpub=xpub.to_base58())


def crosscheck_descriptor_address(descriptor, address: str, network: str, index: int, is_change: bool) -> None:
    from seedsigner.crosscheck.address import check_descriptor_address
    check_descriptor_address(address, network, wally_descriptor_str(descriptor.to_string()),
                             1 if is_change else 0, index)
