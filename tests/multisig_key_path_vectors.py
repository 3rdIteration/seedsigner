"""
Builds 2-of-3 P2WSH multisig psbts whose cosigners each sit at their own account
path, for issue #477.

Some managed-multisig providers put their own key at a non-standard account (e.g.
m/48h/1h/778h/2h) while the user's keys stay at m/48h/1h/0h/2h. Every psbt such a
wallet produces is honest, but the cosigners' hardened paths don't line up -- which
used to be read as change "outside this wallet".

Everything is built from scratch so a vector can move exactly one path and nothing
else: the inputs and the change both sit at /0/<index> under each cosigner's own
account, as a sortedmulti descriptor would derive them.
"""
from dataclasses import dataclass, field

from embit import bip32, script
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from psbt_testing_util import PSBTTestData
from seedsigner.models.seed import Seed


NETWORK = NETWORKS["test"]

# Ours (the signing seed) plus two cosigners. The third plays the provider.
OUR_SEED = PSBTTestData.seed
COSIGNER_SEED = PSBTTestData.multisig_key_2
PROVIDER_SEED = PSBTTestData.multisig_key_3

STANDARD_ACCOUNT = "m/48h/1h/0h/2h"
# The account from the issue's screenshots.
PROVIDER_ACCOUNT = "m/48h/1h/778h/2h"

INPUT_AMOUNT = 1_000_000
SPEND_AMOUNT = 300_000
FEE = 1_000


def _root(seed: Seed) -> bip32.HDKey:
    return bip32.HDKey.from_seed(seed.seed_bytes, version=NETWORK["xprv"])


def _fingerprint(seed: Seed) -> bytes:
    return _root(seed).child(0).fingerprint


@dataclass
class Cosigner:
    seed: Seed
    account: str
    # Where this cosigner's key on the change output sits, if somewhere other
    # than its account (used to move one cosigner's change off its account).
    change_account: str = None

    @property
    def account_xpub(self) -> bip32.HDKey:
        return _root(self.seed).derive(self.account).to_public()

    def key(self, account: str, branch: int, index: int):
        return _root(self.seed).derive(f"{account}/{branch}/{index}").to_public().key

    def derivation(self, account: str, branch: int, index: int) -> DerivationPath:
        return DerivationPath(
            _fingerprint(self.seed),
            bip32.parse_path(f"{account}/{branch}/{index}"),
        )


@dataclass
class MultisigVector:
    cosigners: list = field(default_factory=list)
    input_index: int = 3
    change_branch: int = 1
    change_index: int = 4
    include_global_xpubs: bool = True

    def descriptor(self) -> Descriptor:
        """The wallet's known-good descriptor, as the user would load it."""
        keys = []
        for c in self.cosigners:
            origin = c.account.replace("m/", "").replace("h", "'")
            keys.append(f"[{_fingerprint(c.seed).hex()}/{origin}]{c.account_xpub.to_base58(NETWORK['xpub'])}/<0;1>/*")
        return Descriptor.from_string(f"wsh(sortedmulti(2,{','.join(keys)}))")

    def _witness_script(self, keys) -> script.Script:
        return script.multisig(2, sorted(keys, key=lambda k: k.sec()))

    def build(self) -> PSBT:
        in_keys = [c.key(c.account, 0, self.input_index) for c in self.cosigners]
        in_ws = self._witness_script(in_keys)

        change_keys = [
            c.key(c.change_account or c.account, self.change_branch, self.change_index)
            for c in self.cosigners
        ]
        change_ws = self._witness_script(change_keys)

        prev_tx = Transaction(
            vin=[TransactionInput(b"\x11" * 32, 0)],
            vout=[TransactionOutput(INPUT_AMOUNT, script.p2wsh(in_ws))],
        )

        external = _root(PSBTTestData.recipient_seed).derive("m/84h/1h/0h/0/0").to_public().key
        tx = Transaction(
            vin=[TransactionInput(prev_tx.txid(), 0, sequence=0xFFFFFFFD)],
            vout=[
                TransactionOutput(SPEND_AMOUNT, script.p2wpkh(external)),
                TransactionOutput(INPUT_AMOUNT - SPEND_AMOUNT - FEE, script.p2wsh(change_ws)),
            ],
        )

        psbt = PSBT(tx)
        inp = psbt.inputs[0]
        inp.non_witness_utxo = prev_tx
        inp.witness_utxo = prev_tx.vout[0]
        inp.witness_script = in_ws
        for c, key in zip(self.cosigners, in_keys):
            inp.bip32_derivations[key] = c.derivation(c.account, 0, self.input_index)

        out = psbt.outputs[1]
        out.witness_script = change_ws
        for c, key in zip(self.cosigners, change_keys):
            out.bip32_derivations[key] = c.derivation(
                c.change_account or c.account, self.change_branch, self.change_index
            )

        if self.include_global_xpubs:
            for c in self.cosigners:
                psbt.xpubs[c.account_xpub] = DerivationPath(
                    _fingerprint(c.seed), bip32.parse_path(c.account)
                )

        return psbt


def standard_wallet(**kwargs) -> MultisigVector:
    """Every cosigner at m/48h/1h/0h/2h."""
    return MultisigVector(cosigners=[
        Cosigner(OUR_SEED, STANDARD_ACCOUNT),
        Cosigner(COSIGNER_SEED, STANDARD_ACCOUNT),
        Cosigner(PROVIDER_SEED, STANDARD_ACCOUNT),
    ], **kwargs)


def provider_wallet(**kwargs) -> MultisigVector:
    """The issue's wallet: the provider's key at account 778h, ours at 0h."""
    return MultisigVector(cosigners=[
        Cosigner(OUR_SEED, STANDARD_ACCOUNT),
        Cosigner(COSIGNER_SEED, STANDARD_ACCOUNT),
        Cosigner(PROVIDER_SEED, PROVIDER_ACCOUNT),
    ], **kwargs)


# A purpose no coordinator derives a multisig at by default.
NONSTANDARD_ACCOUNT = "m/99h/1h/0h/2h"


def nonstandard_wallet(**kwargs) -> MultisigVector:
    """One cosigner at a path with a non-standard shape, not merely another account."""
    return MultisigVector(cosigners=[
        Cosigner(OUR_SEED, STANDARD_ACCOUNT),
        Cosigner(COSIGNER_SEED, STANDARD_ACCOUNT),
        Cosigner(PROVIDER_SEED, NONSTANDARD_ACCOUNT),
    ], **kwargs)
