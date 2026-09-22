"""
Silent Payments scan-key export.

The vectors come from four independent implementations, so a mistake shared with
any one of them still shows up:

* BIP-352's own receiving vectors (the unlabeled address of each distinct key pair
  across its 29 receiving cases);
* earthdiver's seed vectors in SeedSigner issue #769 (address and spscan key);
* Sparrow's drongo seed tests (testnet address);
* kiss-signer's (keys, addresses and the sp(...) scan export for abandon...about).
"""
from unittest.mock import MagicMock

import pytest
from embit import ec

from seedsigner.helpers import silent_payments
from seedsigner.models.seed import AezeedSeed, ElectrumSeed, Seed, Slip39Seed, XprvSeed
from seedsigner.models.settings_definition import SettingsConstants


MAINNET = SettingsConstants.MAINNET
TESTNET = SettingsConstants.TESTNET
REGTEST = SettingsConstants.REGTEST

ABANDON = ["abandon"] * 11 + ["about"]

# abandon...about, account 0, cross-checked against kiss-signer and Sparrow.
ABANDON_MAINNET_ADDRESS = "sp1qqfqnnv8czppwysafq3uwgwvsc638hc8rx3hscuddh0xa2yd746s7xqh6yy9ncjnqhqxazct0fzh98w7lpkm5fvlepqec2yy0sxlq4j6ccc3h6t0g"
ABANDON_MAINNET_EXPORT = "[73c5da0a/352h/0h/0h]spscan1q0rnl6lft0gkpg4nsn528qgdpytfdej40atdqgrxpqqsg8c5r8vys973ppv7y5c9cphgkzm6g4efmhhcdkazt87ggxwz3pruphc9vkkxxhtvyag"


# BIP-352 send_and_receive_test_vectors.json: (scan priv, spend priv, unlabeled address)
BIP352_RECEIVING = [
    ("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c", "9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3",
     "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv"),
    ("060b751d7892149006ed7b98606955a29fe284a1e900070c0971f5fb93dbf422", "9902c3c56e84002a7cd410113a9ab21d142be7f53cf5200720bb01314c5eb920",
     "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn"),
    ("11b7a82e06ca2648d5fded2366478078ec4fc9dc1d8ff487518226f229d768fd", "b8f87388cbb41934c50daca018901b00070a5ff6cc25a7e9e716a9d5b9e4d664",
     "sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqauj52ymtc4xdkmx3tgyhrsemg2g3303xk2gtzfy8h8ejet8fz8jcw23zua"),
    ("0000000000000000000000000000000000000000000000000000000000000002", "0000000000000000000000000000000000000000000000000000000000000001",
     "sp1qqtrqglu5g8kh6mfsg4qxa9wq0nv9cauwfwxw70984wkqnw2uwz0w2qnehen8a7wuhwk9tgrzjh8gwzc8q2dlekedec5djk0js9d3d7qhnq6lqj3s"),
    ("000000000000000000000000000000000000000000000000000000000000dead", "000000000000000000000000000000000000000000000000000000000000beef",
     "sp1qqtnvg7hxjck9ag24naytgd7pjwsmevwh95ydwht58w3uh7uw0ta7kq6xcdal4dazgg2txp472hdz4svms98328lqdflmpxppmc6ykamcrv9s7w9g"),
]

# SeedSigner issue #769 (earthdiver): (mnemonic, network, address, spscan key)
EARTHDIVER = [
    ("initial tilt corn easily leave weather strategy return topple gesture sad day", TESTNET,
     "tsp1qqfvn9pmvmz0ewpnp7w302lxqmnue2kgtpne2p38nuunun883sw36yq48ny7n2jl0nx9ljhmdnrgvpee6aufmg9wfvqfcr6c02at6r4u4xsegph7a",
     "tspscan1q09zrmaz09cdzs5jxm552qpv3f2gxd9vxhs0yady09jdd6aqt5e7s9fue8565hmue30u47mvc6rqwwwh0zw6ptjtqzwq7kr6h27sa09f5g6x977"),
    ("tongue vanish post gentle fever figure kangaroo select infant blur phrase relief", MAINNET,
     "sp1qq2c4jvrju33tmm9ll0560vm0rflfxkhd8zj74pka8s53dyaztzwlqqhrkuv0ut7wjv08kdq26t4twguxdcd9m35p6z4n784wyg3efwruevxty23x",
     "spscan1qnd95fpg2587jn73qg98pq8uk20y09v5c20u0e4kynsc4m2qmkrrs9cahrrlzln5nreangzkja2mj8pnwrfwudqws4vl3at3zyw2tslxtryq7pn"),
    ("index today witness obscure ugly curtain symbol pumpkin pelican child maple struggle arctic water tiny pizza harbor below violin eight tennis frost clown hood", TESTNET,
     "tsp1qqvdcq76j5kul4s6t52d07ssq8l96k49jur0kytua36k9qzj4m5xyxq5j2v4hc8njddv9xtnhly7hyv2agt28fypqn29q8mw3fjjlz00vvv824hd6",
     "tspscan1q0z4tkwaar4ww77qgesalgzw0c40q89zh7p7hmp3qn73yrdw9jpvs9yjn9d7puunttpfjuale84erzh2z636fqgy63gp7m52v5hcnmmrrlrxnur"),
    ("fold cotton pipe robust eagle rabbit coach average orient utility minor absurd fine claim artist rabbit kingdom original lobster cruise march city vibrant resemble", MAINNET,
     "sp1qq25f3laffnhpl69ytaxzz5gjnkrm2a2jr3mfz0ff6wuesg4j9e5lcqjj5qq7fy0t0wy9qvty7l7wk8vnmyxpxeq5ae0lmmzlgwnutg8945k2w7lh",
     "spscan1q79q4zljllyehszny72w5zfptzpxnp96esg0n2fwecgzd2v7fr6fsy54qq8jfr6mm3pgrze8hln43my7epsfkg98wtl77ch6r5lz6pedd2jcnxk"),
]

# Sparrow's drongo seed tests, testnet account 0: (mnemonic, address)
DRONGO = [
    ("life life life life life life life life life life life life",
     "tsp1qq0grgkzt7uwfst33pyge7k9mrkag0r9vrklc695n0pw7kwwc7qddqqley3n2a6z8q7vhkhzedtzj5kr86hv6fhh0zvu2j9tjrrxa4ye3acuv6f3q"),
    ("resist cube wrap sleep catalog shadow door scale stage rail script observe",
     "tsp1qqgksl44sjwjkedsmrfmf2xqsnyt2njtjp5plk2kzjlnd9el2n76awqe5j974lvkf2utv7nrg0eaug55z86n6n3v4e9alnftdzgqk6pqmm5dphvxn"),
]

# kiss-signer main/sp_spend_vectors.h and sim/test_sp.c, abandon...about
KISS_SPSCAN = {
    MAINNET: "sp([73c5da0a/352h/0h/0h]spscan1q0rnl6lft0gkpg4nsn528qgdpytfdej40atdqgrxpqqsg8c5r8vys973ppv7y5c9cphgkzm6g4efmhhcdkazt87ggxwz3pruphc9vkkxxhtvyag)",
    TESTNET: "sp([73c5da0a/352h/1h/0h]tspscan1q8pjcdy7qzlzxl44chw2tsanvzg7dtwhkqf3nsvzmdavls2ekl8qq9qesshy6w9knddr825kqp442302zuwddh6vtqk7zqvgszace9aczgnuqn3)",
}
KISS_KEYS = {
    # network: (scan pubkey, spend pubkey, address)
    MAINNET: ("024139b0f81042e243a90478e43990c6a27be0e3346f0c71adbbcdd511beaea1e3",
              "02fa210b3c4a60b80dd1616f48ae53bbdf0db744b3f9083385108f81be0acb58c6",
              ABANDON_MAINNET_ADDRESS),
    TESTNET: ("03439fc230182b46ff22032ca7ae2dff32958c9a0d177c7b7096df0d4b7141eb21",
              "02833085c9a716d36b467552c00d6aa8bd42e39adbe98b05bc203110177192f702",
              "tsp1qqdpels3srq45dlezqvk20t3dlueftry6p5thc7msjm0s6jm3g84jzq5rxzzunfck6d45va2jcqxk429agt3e4klf3vzmcgp3zqthryhhqgnz4k3n"),
}
KISS_MASTER_TPRV = "tprv8ZgxMBicQKsPe5YMU9gHen4Ez3ApihUfykaqUorj9t6FDqy3nP6eoXiAo2ssvpAjoLroQxHqr3R5nE3a5dU3DHTjTgJDd7zrbniJr6nrCzd"

# SLIP-39's first official vector (tests/data/shamir_vectors.json), passphrase "TREZOR"
SLIP39_SHARE = "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard"
SLIP39_XPRV = "xprv9s21ZrQH143K4QViKpwKCpS2zVbz8GrZgpEchMDg6KME9HZtjfL7iThE9w5muQA4YPHKN1u5VM1w8D4pvnjxa2BmpGMfXr7hnRrRHZ93awZ"

ELECTRUM_MNEMONIC = "regular reject rare profit once math fringe chase until ketchup century escape"
AEZEED_MNEMONIC = (
    "absorb original enlist once climb erode kid thrive kitchen giant define tube "
    "orange leader harbor comfort olive fatal success suggest drink penalty chimney ritual"
)


def abandon_seed(passphrase: str = "") -> Seed:
    return Seed(list(ABANDON), passphrase=passphrase)


def child_xprv_seed() -> XprvSeed:
    """An xprv one level below the abandon...about master."""
    return XprvSeed(abandon_seed().get_root(MAINNET).derive("m/0h").to_base58())


def key_part(export: str) -> str:
    """The spscan1.../tspscan1... key, without its [origin]."""
    return export.split("]", 1)[1]



@pytest.mark.parametrize("scan_priv, spend_priv, address", BIP352_RECEIVING)
def test_bip352_receiving_vectors(scan_priv, spend_priv, address):
    scan_pub = ec.PrivateKey(bytes.fromhex(scan_priv)).sec()
    spend_pub = ec.PrivateKey(bytes.fromhex(spend_priv)).sec()
    assert silent_payments._bech32m("sp", scan_pub + spend_pub) == address


@pytest.mark.parametrize("mnemonic, network, address, spscan", EARTHDIVER)
def test_earthdiver_vectors(mnemonic, network, address, spscan):
    seed = Seed(mnemonic.split())
    assert silent_payments.address(seed, network) == address
    assert key_part(silent_payments.scan_key_export(seed, network)) == spscan


@pytest.mark.parametrize("mnemonic, address", DRONGO)
def test_drongo_vectors(mnemonic, address):
    assert silent_payments.address(Seed(mnemonic.split()), TESTNET) == address


@pytest.mark.parametrize("network", [MAINNET, TESTNET])
def test_kiss_signer_vectors(network):
    seed = abandon_seed()
    scan_pub, spend_pub, address = KISS_KEYS[network]

    scan, spend = silent_payments._keys(seed, network)
    assert scan.sec().hex() == scan_pub
    assert spend.sec().hex() == spend_pub
    assert silent_payments.address(seed, network) == address

    # Sparrow's SeedSigner import adds the sp(...) around the key expression itself.
    assert "sp(%s)" % silent_payments.scan_key_export(seed, network) == KISS_SPSCAN[network]


def test_kiss_signer_encodes_given_pubkeys():
    scan_pub = "027a487fc19fb769877b8742d6ea18118f3c4e72b1ea8c6de602a7ad4a41dbe068"
    spend_pub = "0361e1b1e9de5e42cb2007f7ca54b9e0d57ed13938fad56d3f19e57513a8fce039"
    assert silent_payments._bech32m("tsp", bytes.fromhex(scan_pub + spend_pub)) == (
        "tsp1qqfaysl7pn7mknpmmsapdd6sczx8ncnnjk84gcm0xq2n66jjpm0sxsqmpuxc7nhj7gt9jqplhef2tncx40mgnjw8664kn7x09w5f63l8q8ymd0lna"
    )


def test_abandon_mainnet_export_and_address():
    seed = abandon_seed()
    assert silent_payments.scan_key_export(seed, MAINNET) == ABANDON_MAINNET_EXPORT
    assert silent_payments.address(seed, MAINNET) == ABANDON_MAINNET_ADDRESS
    assert len(ABANDON_MAINNET_EXPORT) == 139
    assert len(ABANDON_MAINNET_ADDRESS) == 116


@pytest.mark.parametrize("network, path, origin", [
    (MAINNET, "m/352'/0'/0'", "/352h/0h/0h]spscan1q"),
    (TESTNET, "m/352'/1'/0'", "/352h/1h/0h]tspscan1q"),
])
def test_export_origin_matches_the_seed_options_fingerprint(network, path, origin):
    seed = abandon_seed("TREZOR")
    assert silent_payments.derivation_path(network) == path
    assert silent_payments.scan_key_export(seed, network).startswith("[" + seed.get_fingerprint(network) + origin)


def test_bip39_passphrase_changes_fingerprint_and_keys():
    plain, protected = abandon_seed(), abandon_seed("TREZOR")
    assert protected.get_fingerprint(MAINNET) != plain.get_fingerprint(MAINNET)
    assert silent_payments.address(protected, MAINNET) != silent_payments.address(plain, MAINNET)

    # The same keys as the passphrase seed's own master xprv gives.
    xprv = XprvSeed(protected.get_root(MAINNET).to_base58())
    assert silent_payments.address(protected, MAINNET) == silent_payments.address(xprv, MAINNET)
    assert silent_payments.scan_key_export(protected, MAINNET) == silent_payments.scan_key_export(xprv, MAINNET)


@pytest.mark.parametrize("network", [MAINNET, TESTNET])
def test_slip39_matches_its_official_xprv(network, monkeypatch):
    # Slip39Seed shows a loading screen while it combines the shares.
    monkeypatch.setattr("seedsigner.gui.screens.screen.LoadingScreenThread", MagicMock())
    slip39 = Slip39Seed(mnemonics=[SLIP39_SHARE], slip39_passphrase="TREZOR")
    xprv = XprvSeed(SLIP39_XPRV)
    assert silent_payments.is_supported(slip39, network)
    assert silent_payments.address(slip39, network) == silent_payments.address(xprv, network)
    assert silent_payments.scan_key_export(slip39, network) == silent_payments.scan_key_export(xprv, network)


@pytest.mark.parametrize("network", [MAINNET, TESTNET])
def test_master_xprv_matches_its_bip39_seed(network):
    # A tprv, on mainnet too: the version bytes don't change the keys.
    xprv = XprvSeed(KISS_MASTER_TPRV)
    assert silent_payments.is_supported(xprv, network)
    assert silent_payments.address(xprv, network) == silent_payments.address(abandon_seed(), network)
    assert silent_payments.scan_key_export(xprv, network) == silent_payments.scan_key_export(abandon_seed(), network)


@pytest.mark.parametrize("seed_factory, network", [
    (abandon_seed, REGTEST),
    (lambda: ElectrumSeed(ELECTRUM_MNEMONIC.split()), MAINNET),
    (lambda: AezeedSeed(mnemonic=AEZEED_MNEMONIC.split()), MAINNET),
    (child_xprv_seed, MAINNET),
    (child_xprv_seed, TESTNET),
], ids=["regtest", "electrum", "aezeed", "child-xprv-mainnet", "child-xprv-testnet"])
def test_helper_refuses_unsupported_seeds_and_networks(seed_factory, network):
    seed = seed_factory()
    assert not silent_payments.is_supported(seed, network)
    with pytest.raises(ValueError):
        silent_payments.address(seed, network)
    with pytest.raises(ValueError):
        silent_payments.scan_key_export(seed, network)
