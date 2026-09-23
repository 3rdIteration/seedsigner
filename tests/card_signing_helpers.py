"""
    Shared helpers for the jcardsim card-signing suites.

    Keycard and Satochip are asked to sign the same PSBT shapes and messages, so the
    builders and the off-card verification live here once. A pass means the applet really
    produced a signature over the right sighash with the key at the claimed derivation --
    not that a stub returned canned bytes.
"""

from binascii import a2b_base64
from hashlib import sha256

from ecdsa import SECP256k1, VerifyingKey
from ecdsa.util import sigdecode_der, sigdecode_string

from embit import script
from embit.ec import PrivateKey
from embit.psbt import DerivationPath, InputScope, OutputScope, PSBT
from embit.transaction import TransactionOutput

from seedsigner.helpers.satochip_signer import _compact_size
from seedsigner.models.settings import Settings
from seedsigner.models.settings_definition import SettingsConstants


SIGN_TIMEOUT = 30


class NoDummySettings:
    """
    Settings stub for signing tests: dummy signatures off, generous per-sign timeout.

    The dummy-signature obfuscation is deliberately random and dominates signing time, so
    switching it off keeps these tests deterministic and quick while still exercising the
    real sign call on the card.
    """

    def get_value(self, setting):
        if setting in (
            SettingsConstants.SETTING__KEYCARD_SIGN_TIMEOUT,
            SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT,
            SettingsConstants.SETTING__SATOCHIP_MSG_SIGN_TIMEOUT,
        ):
            return SIGN_TIMEOUT
        return 0


def patch_signing_settings(monkeypatch) -> None:
    """Route Settings.get_instance() at NoDummySettings for the duration of a test."""
    monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: NoDummySettings()))


def derivation_indices(path: str) -> list[int]:
    """``"m/84'/0'/0'/0/0"`` -> ``[0x80000054, 0x80000000, 0x80000000, 0, 0]``."""
    indices = []
    for element in path.split("/"):
        if element in ("m", ""):
            continue
        hardened = element.endswith("'") or element.endswith("h")
        index = int(element.rstrip("'h"))
        indices.append(index | 0x80000000 if hardened else index)
    return indices


def _script_pubkey(pub, script_type):
    if script_type == SettingsConstants.NATIVE_SEGWIT:
        return script.p2wpkh(pub)
    if script_type == SettingsConstants.NESTED_SEGWIT:
        return script.p2sh(script.p2wpkh(pub))
    raise ValueError(f"unsupported card-signing script type: {script_type}")


def single_sig_input(pub, fingerprint, path, script_type, *, txid, vout=0, value=1_000_000) -> InputScope:
    """A witness input whose only claimed derivation is ``pub`` at ``path``."""
    inp = InputScope()
    inp.txid = txid
    inp.vout = vout
    inp.bip32_derivations[pub] = DerivationPath(fingerprint, derivation_indices(path))
    inp.witness_utxo = TransactionOutput(value, _script_pubkey(pub, script_type))
    return inp


def multisig_input(cosigners, threshold, script_type, *, txid, vout=0, value=1_000_000) -> InputScope:
    """
    A bare-multisig witness input carrying a derivation per cosigner.

    ``cosigners`` is a list of ``(pubkey, fingerprint, path)``; thresholds are sorted by
    SEC bytes to match how the witness script is built.
    """
    pubs = sorted((pub for pub, _fingerprint, _path in cosigners), key=lambda p: p.sec())
    witness_script = script.multisig(threshold, pubs)
    if script_type == SettingsConstants.NATIVE_SEGWIT:
        spk = script.p2wsh(witness_script)
    elif script_type == SettingsConstants.NESTED_SEGWIT:
        spk = script.p2sh(script.p2wsh(witness_script))
    else:
        raise ValueError(f"unsupported card-signing script type: {script_type}")

    inp = InputScope()
    inp.txid = txid
    inp.vout = vout
    inp.witness_script = witness_script
    inp.witness_utxo = TransactionOutput(value, spk)
    for pub, fingerprint, path in cosigners:
        inp.bip32_derivations[pub] = DerivationPath(fingerprint, derivation_indices(path))
    return inp


def make_psbt(inputs, output_value=900_000) -> PSBT:
    """Wrap inputs in a PSBT with a single unrelated p2wpkh output."""
    psbt = PSBT()
    psbt.inputs = list(inputs)
    out = OutputScope()
    out.value = output_value
    out.script_pubkey = script.p2wpkh(PrivateKey(b"\x01" * 32).get_public_key())
    psbt.outputs.append(out)
    return psbt


def assert_signed_and_verifies(psbt: PSBT, index: int, pub) -> None:
    """The input carries a SIGHASH_ALL ECDSA signature by ``pub`` over its own sighash."""
    inp = psbt.inputs[index]
    assert pub in inp.partial_sigs, f"input {index} was not signed by the expected key"
    raw = bytes(inp.partial_sigs[pub])
    assert raw[-1] == 0x01, "the smartcard signers tag every signature SIGHASH_ALL"
    vk = VerifyingKey.from_string(pub.sec(), curve=SECP256k1)
    vk.verify_digest(raw[:-1], psbt.sighash(index), sigdecode=sigdecode_der)


def message_digest(message: str) -> bytes:
    """The Bitcoin signed-message digest both card paths ultimately sign."""
    payload = message.encode("utf-8")
    serialized = b"\x18Bitcoin Signed Message:\n" + _compact_size(len(payload)) + payload
    return sha256(sha256(serialized).digest()).digest()


def assert_message_signature(signature_b64: str, message: str, pub) -> None:
    """
    Verify a base64 compact signature (as the sign-message flow returns) against ``pub``.

    The 65th byte is a recovery id; the sign-message flow emits compressed keys, so it
    must be in the 31..34 range.
    """
    raw = a2b_base64(signature_b64)
    assert len(raw) == 65, f"expected a 65-byte compact signature, got {len(raw)}"
    assert 31 <= raw[0] <= 34, f"expected a compressed-key recovery flag, got {raw[0]}"
    vk = VerifyingKey.from_string(pub.sec(), curve=SECP256k1)
    vk.verify_digest(raw[1:], message_digest(message), sigdecode=sigdecode_string)
