"""
Seed-load cross-check: libwally independently re-derives what embit derived for a
seed (BIP-39/Electrum seed bytes, master fingerprint, account xpubs) before the
seed is admitted into SeedStorage.

A wrong fingerprint or xpub here would follow the seed everywhere -- exported to
a coordinator, used to decide which psbt outputs are change -- so the check runs
once, at the single point every seed passes through.
"""
import hmac
from dataclasses import dataclass, field

from seedsigner.crosscheck import CrossCheckCode, CrossCheckError, NETWORK_MAINNET, get_wally
from seedsigner.crosscheck.keys import parse_extended_key
from seedsigner.crosscheck.secrets import SecretScratch


KIND_BIP39 = "bip39"
KIND_ELECTRUM = "electrum"
# Seed types whose first step (aezeed deciphering, SLIP-39 share recovery) has
# no libwally implementation: the check starts from their seed bytes.
KIND_SEED_BYTES = "seed_bytes"
KIND_XPRV = "xprv"

# Electrum's seed stretching parameters (electrum/mnemonic.py), from the spec
# rather than from SettingsConstants so the two sides don't share a constant.
ELECTRUM_PBKDF2_ROUNDS = 2048
ELECTRUM_SALT_PREFIX = b"electrum"



@dataclass
class SeedClaims:
    """What embit derived, as plain values. Everything here gets re-derived."""
    kind: str
    network: str = NETWORK_MAINNET
    mnemonic: str = ""
    passphrase: str = ""
    seed_bytes: bytes | None = None
    xprv: str = ""
    fingerprint: str = ""
    # derivation path -> (compressed pubkey, chain code) at that path
    account_keys: dict[str, tuple[bytes, bytes]] = field(default_factory=dict)



def _fail(detail: str):
    raise CrossCheckError(CrossCheckCode.SEED, detail)


def check_seed(claims: SeedClaims) -> None:
    """Raise CrossCheckError unless libwally agrees with every claim."""
    w = get_wally()
    if w is None:
        return

    priv_ver = w.BIP32_VER_MAIN_PRIVATE if claims.network == NETWORK_MAINNET else w.BIP32_VER_TEST_PRIVATE

    with SecretScratch() as scratch:
        if claims.kind == KIND_XPRV:
            root = parse_extended_key(claims.xprv, CrossCheckCode.SEED)

        else:
            if claims.kind == KIND_BIP39:
                try:
                    w.bip39_mnemonic_validate(None, claims.mnemonic)
                except ValueError:
                    _fail("libwally rejects the BIP-39 mnemonic")
                seed = scratch.keep(w.bip39_mnemonic_to_seed512(claims.mnemonic, claims.passphrase))

            elif claims.kind == KIND_ELECTRUM:
                # Wipeable buffers: these hold the mnemonic and passphrase.
                password = scratch.keep(bytearray(claims.mnemonic, "utf-8"))
                salt = scratch.keep(bytearray(ELECTRUM_SALT_PREFIX) + bytearray(claims.passphrase, "utf-8"))
                seed = scratch.keep(w.pbkdf2_hmac_sha512(password, salt, 0, ELECTRUM_PBKDF2_ROUNDS))

            elif claims.kind == KIND_SEED_BYTES:
                seed = claims.seed_bytes or b""

            else:
                raise ValueError(f"Unknown seed kind {claims.kind}")

            if claims.kind != KIND_SEED_BYTES and not hmac.compare_digest(seed, claims.seed_bytes or b""):
                _fail("seed bytes differ")

            root = w.bip32_key_from_seed(seed, priv_ver, 0)

        fingerprint = w.bip32_key_get_fingerprint(root).hex()
        if fingerprint != claims.fingerprint:
            _fail(f"fingerprint differs (libwally {fingerprint}, embit {claims.fingerprint})")

        for path, (pubkey, chain_code) in claims.account_keys.items():
            child = w.bip32_key_from_parent_path_str(root, path, 0, w.BIP32_FLAG_KEY_PRIVATE)
            if bytes(w.bip32_key_get_pub_key(child)) != bytes(pubkey):
                _fail(f"public key at {path} differs")
            if bytes(w.bip32_key_get_chain_code(child)) != bytes(chain_code):
                _fail(f"chain code at {path} differs")
            del child

        del root
