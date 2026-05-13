"""UR (Uniform Resources) encoders for the Keycard BTC flow.

Outputs:
  - ``crypto-psbt``  — signed PSBT, animated multi-frame fountain
    encoding handled by ``BaseFountainQrEncoder`` upstream.
  - ``crypto-account`` — wallet export bundle (master fingerprint +
    wpkh descriptor + xpub) for watch-only wallets to ingest.

We reuse the firmware's existing UR2.0 fountain encoder
(``seedsigner.helpers.ur2.ur_encoder.UREncoder``) and the
``urtypes.crypto`` definitions. The only thing this module adds is a
serializer that gathers the fields into the right CBOR shape.

Network-aware: ``crypto-account`` requires a coin-type code (slip-44
``0`` for Bitcoin mainnet). We pin mainnet at MVP.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BtcAccountExport:
    master_fingerprint: bytes        # 4 bytes
    descriptor: str                  # ``wpkh([fp/84h/0h/0h]xpub.../<0;1>/*)``
    xpub: str                        # ``xpub...``
    coin_type: int = 0               # slip-44 mainnet


def encode_psbt_to_ur(psbt_bytes: bytes):
    """Return a ``UREncoder`` instance configured for ``crypto-psbt``.

    Caller can iterate ``encoder.next_part()`` to get the animated
    frames. We import lazily so the heavy ``urtypes`` chain only loads
    when a Bitcoin flow is actually exercised.
    """
    from urtypes.crypto.psbt import PSBT as URPsbt
    from seedsigner.helpers.ur2.ur_encoder import UREncoder
    from seedsigner.helpers.ur2.ur import UR

    cbor = URPsbt(psbt_bytes).to_cbor()
    ur = UR("crypto-psbt", cbor)
    # 80 chars/frame matches the existing ``UrPsbtQrEncoder`` upstream
    # default; small enough for typical printer modules, large enough
    # to keep animated PSBTs short.
    return UREncoder(ur=ur, max_fragment_len=80)


def encode_account_to_ur(export: BtcAccountExport):
    """Return a ``UREncoder`` for a ``crypto-account`` payload.

    The CBOR shape matches the BCR-2020-009 spec used by Sparrow /
    Specter; we build it via ``urtypes.crypto`` to avoid hand-rolling
    the tag soup.
    """
    from urtypes.crypto import Account, Output, HDKey, Keypath, PathComponent, CoinInfo
    from seedsigner.helpers.ur2.ur_encoder import UREncoder
    from seedsigner.helpers.ur2.ur import UR
    from embit import bip32

    hdkey_obj = bip32.HDKey.from_string(export.xpub)
    components = [
        PathComponent(84, True),
        PathComponent(export.coin_type, True),
        PathComponent(0, True),
    ]
    origin = Keypath(
        components=components,
        source_fingerprint=int.from_bytes(export.master_fingerprint, "big"),
        depth=3,
    )
    children = Keypath(
        components=[PathComponent(None, False), PathComponent(None, False)],
        source_fingerprint=None,
        depth=None,
    )
    hd = HDKey({
        "key": hdkey_obj.key.serialize(),
        "chain_code": hdkey_obj.chain_code,
        "origin": origin,
        "children": children,
        "parent_fingerprint": int.from_bytes(hdkey_obj.fingerprint, "big"),
        "use_info": CoinInfo(type=0, network=0),
    })
    output = Output(script_types=["wpkh"], crypto_key=hd)
    account = Account(
        master_fingerprint=int.from_bytes(export.master_fingerprint, "big"),
        output_descriptors=[output],
    )
    ur = UR("crypto-account", account.to_cbor())
    return UREncoder(ur=ur, max_fragment_len=80)
