"""
embit vs libwally timings for the operations the cross-check duplicates.

Not collected by pytest. Run on the target (e.g. a Pi Zero) to see what the
libwally cross-check costs, and whether libwally is fast enough to take over
candidate generation in the address-verification brute force:

    PYTHONPATH=src python tests/benchmarks/bench_wally_vs_embit.py [--addresses N]
"""
import argparse
import os
import sys
import time
from binascii import a2b_base64

import wallycore as w
from embit import bip32, bip39, script
from embit.networks import NETWORKS

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from psbt_testing_util import PSBTTestData  # noqa: E402


MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def timed(label, fn, repeat=1):
    start = time.perf_counter()
    for _ in range(repeat):
        fn()
    elapsed = (time.perf_counter() - start) / repeat
    print(f"  {label:<40} {elapsed * 1000:9.2f} ms")
    return elapsed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--addresses", type=int, default=1000)
    args = parser.parse_args()

    seed = bip39.mnemonic_to_seed(MNEMONIC)
    root = bip32.HDKey.from_seed(seed)
    account = root.derive("m/84h/0h/0h").to_public()
    wroot = w.bip32_key_from_seed(seed, w.BIP32_VER_MAIN_PRIVATE, 0)
    waccount = w.bip32_key_from_parent_path_str(wroot, "m/84h/0h/0h", 0, w.BIP32_FLAG_KEY_PUBLIC)

    print("Seed -> master key")
    timed("embit", lambda: bip32.HDKey.from_seed(bip39.mnemonic_to_seed(MNEMONIC)))
    timed("libwally", lambda: w.bip32_key_from_seed(w.bip39_mnemonic_to_seed512(MNEMONIC, ""), w.BIP32_VER_MAIN_PRIVATE, 0))

    n = args.addresses
    print(f"\n{n} p2wpkh receive addresses from the account xpub")

    def embit_addrs():
        for i in range(n):
            script.p2wpkh(account.derive([0, i]).key).address(NETWORKS["main"])

    def wally_addrs():
        for i in range(n):
            child = w.bip32_key_from_parent_path(waccount, [0, i], w.BIP32_FLAG_KEY_PUBLIC)
            w.addr_segwit_from_bytes(w.witness_program_from_bytes(w.bip32_key_get_pub_key(child), w.WALLY_SCRIPT_HASH160), "bc", 0)

    e = timed("embit", embit_addrs)
    l = timed("libwally", wally_addrs)
    print(f"  libwally is {e / l:.1f}x embit")

    raw = a2b_base64(PSBTTestData.SINGLE_SIG_NATIVE_SEGWIT_2_INPUTS)
    from embit.psbt import PSBT
    print("\nPSBT parse (2 inputs, 4 outputs)")
    timed("embit", lambda: PSBT.parse(raw), repeat=20)
    timed("libwally", lambda: w.psbt_from_bytes(raw, 0), repeat=20)

    print("\nFull cross-check of a parsed + signed psbt")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
    from seedsigner.crosscheck import psbt as xpsbt
    from seedsigner.models.crosscheck_claims import signer_claims
    from seedsigner.models.psbt_framing import parse_psbt
    from seedsigner.models.psbt_parser import PSBTParser
    from seedsigner.models.settings import SettingsConstants

    def make_parser():
        return PSBTParser(parse_psbt(raw), seed=PSBTTestData.two_input_seed, network=SettingsConstants.REGTEST)

    p = make_parser()
    timed("PSBTParser (incl. check_parsed)", make_parser, repeat=5)
    timed("check_parsed alone", lambda: xpsbt.check_parsed(p.crosscheck_claims), repeat=5)
    timed("embit sign_with", lambda: make_parser().psbt.sign_with(p.root), repeat=5)
    p.psbt.sign_with(p.root)
    signed = p.psbt.serialize()
    timed("check_signed (verify + re-sign)", lambda: xpsbt.check_signed(signed, p.crosscheck_claims, signer_claims(p, True)), repeat=5)


if __name__ == "__main__":
    main()
