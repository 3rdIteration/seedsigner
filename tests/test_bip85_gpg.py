import pytest
import sys
import base  # ensure hardware mocks
import os
import shutil
from embit import bip32, bip85
from seedsigner.models.seed import Seed
from seedsigner.controller import Controller
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.views import tools_views
from seedsigner.views.tools_views import (
    bip85_brainpoolp256r1_from_root,
    bip85_ed25519_from_root,
    bip85_p256_from_root,
    bip85_rsa_from_root,
    bip85_secp256k1_from_root,
    bip85_add_subkeys,
    _bip85_subkey_specs,
    parse_secret_key_list,
    parse_subkey_list,
    parse_uid_list,
    filter_deletable_subkeys,
    BIP85_GPG_CREATED_TS,
    BIP85_DATA,
    bip85_save_data,
    bip85_load_data,
    _select_import_algo,
    bip85_verify_existing,
)
from seedsigner.helpers.bip85_drng import BIP85DRNG

pytestmark = pytest.mark.skipif(
    sys.platform in ("darwin", "win32") or shutil.which("gpg") is None,
    reason="requires working GnuPG2"
)

MNEMONIC = "resource timber firm banner horror pupil frozen main pear direct pioneer broken grid core insane begin sister pony end debate task silk empty curious".split()


def test_bip85_drng_vector():
    root = bip32.HDKey.from_string(
        "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
    )
    entropy = bip85.derive_entropy(root, 0, [0])
    assert entropy.hex() == (
        "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0"
        "0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
    )
    drng = BIP85DRNG.new(entropy)
    assert drng.read(80).hex() == (
        "b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd8"
        "83d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc"
        "8c7355b87a925a37ee405a7502991111"
    )


def test_bip85_rsa_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_rsa_from_root(root, 1024, 0)
    assert key.size_in_bits() == 1024
    assert key.n == int(
        "a3ec52b3ad61128b8253f0a34bfc9d19d01df9603acc8fac3eba3dda750421029d647122fbfc0384fdab97c44f6a7d0748819c46a33414217120daff2f0a471b234023897af78a7cb119df3c9f3b2b7690803587bff8016d14f5b91088201792569d745ff1d9c58235458faf706475242feb4fb699fccaf94b564398f57d921b",
        16,
    )


def test_bip85_rsa_large_key():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_rsa_from_root(root, 4096, 0)
    assert key.size_in_bits() == 4096


def test_bip85_rsa_3072_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_rsa_from_root(root, 3072, 0)
    assert key.size_in_bits() == 3072
    assert key.n == int(
        "c3cfd8332fde9f8ec605520f687c11f250b0eedfd695aa3170f3eb242c15e0be769a1120f9c81c30615e3a5f3a0c50aa399df15f2d3a8554a0d698c5c86cacfbbce160c8bf6e7f581f9ad16885cbe5aeffeddc8ff66c16a16b6f429da765b98adbdd4554e0ec322206fc8c9b780f3527f2b93aa3075bde1fb735829e41f5f42be6ee7dc0d28f570c394e7610f44b85ba452a933e2405a3a72cdf8d33577a85fb5bb35b2cd0c2d7c6f3309c4ca47aab8eb094d31db982c91e9ea9c8f369827d73c4a53f943c15dfff791b33aa2d60173f13dc437cee05222b288726cea9d02eefff111a74714655ed6c048c27ff1a3264732d2952a233c42b640ec93bc214a39eef342b285c828ae00d2082fae2bef26e88a6fc0650939beeeb518feea3b79576a54afe640146eb0d9fb0bcd12d14d7dea6aed79527243a182f6bf83d9b6128582b87eddecfb99d8969c779314e8334e7580204ac25ae734035b45510268d6fb8964a4f74ae7ca5ff2cabf0553c374d760d600da4472d09a42a81844844346525",
        16,
    )


def test_bip85_secp256k1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_secp256k1_from_root(root, 0)
    assert int(key.s) == int(
        "cefbb3197f44cbcd28ca548e7d6c22e2b67f497caeebb71fa91d1cc6ab78e502", 16
    )


def test_bip85_p256_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_p256_from_root(root, 0)
    assert int(key.s) == int(
        "ef959a78fb241496d3b56bf1307f142a1c4b141b7bdb6ec95afc11f66eafad2f", 16
    )


def test_bip85_brainpoolp256r1_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_brainpoolp256r1_from_root(root, 0)
    assert int(key.s) == int(
        "6f48a0f8172149dd27c6d18e43017e2083e3dcf9ac58144ca054e4e86a7d3a24", 16
    )


def test_bip85_ed25519_deterministic():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    key = bip85_ed25519_from_root(root, 0)
    assert int(key.s) == int(
        "7b947d4d726e678ce219948c837221b6712cdf74862b453921442d038f55040c", 16
    )


def test_bip85_ed25519_sub_index_progression():
    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    first = bip85_ed25519_from_root(root, 0, 0, "EdDSA")
    later = bip85_ed25519_from_root(root, 0, 3, "EdDSA")
    repeat = bip85_ed25519_from_root(root, 0, 3, "EdDSA")
    assert int(first.s) != int(later.s)
    assert int(later.s) == int(repeat.s)


def test_bip85_gpg_mixed_subkeys_deterministic():
    import datetime
    from pgpy import PGPKey, PGPUID
    from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
    from pgpy.constants import (
        PubKeyAlgorithm,
        KeyFlags,
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
    )
    from pgpy.packet import fields
    from pgpy.packet.types import MPI
    from Cryptodome.PublicKey import RSA

    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    created = datetime.datetime.fromtimestamp(
        BIP85_GPG_CREATED_TS, tz=datetime.timezone.utc
    )
    pk = PrivKeyV4()
    pk.pkalg = PubKeyAlgorithm.ECDSA
    pk.keymaterial = bip85_p256_from_root(root, 0)
    pk.created = created
    pk.update_hlen()
    pgp_key = PGPKey()
    pgp_key._key = pk
    uid = PGPUID.new("Test", email="test@example.com")
    pgp_key.add_uid(
        uid,
        usage={KeyFlags.Certify, KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
        created=created,
    )
    for sub_index, pkalg, usage, alg in _bip85_subkey_specs("nistp256"):
        subpkt = PrivSubKeyV4()
        subpkt.pkalg = pkalg
        subpkt.keymaterial = bip85_p256_from_root(root, 0, sub_index, alg)
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        pgp_key.add_subkey(
            subkey,
            usage=usage,
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
            created=created,
        )

    def rsa_to_privpacket(rsa_key: RSA.RsaKey):
        priv = fields.RSAPriv()
        priv.n = MPI(rsa_key.n)
        priv.e = MPI(rsa_key.e)
        priv.d = MPI(rsa_key.d)
        priv.p = MPI(rsa_key.p)
        priv.q = MPI(rsa_key.q)
        priv.u = MPI(pow(rsa_key.p, -1, rsa_key.q))
        priv._compute_chksum()
        return priv

    for sub_index, pkalg, usage in _bip85_subkey_specs("rsa2048"):
        subpkt = PrivSubKeyV4()
        subpkt.pkalg = pkalg
        rsa_sub = bip85_rsa_from_root(root, 2048, 1, sub_index)
        subpkt.keymaterial = rsa_to_privpacket(rsa_sub)
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        pgp_key.add_subkey(
            subkey,
            usage=usage,
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
            created=created,
        )

    assert pgp_key.fingerprint == "E22DC9A7FDC9F51B7E795EA4134E37F3677DD798"
    fingerprints = [sk.fingerprint for sk in pgp_key.subkeys.values()]
    assert fingerprints == [
        "CF79EEF39935329B69CFCD6FD73018577F0CBE35",
        "15BD8E20336AD1CFFA0B4363DEC612E5764867B6",
        "BFD31BC4A4579ADD568D6C3B5FB00DCBCB25E073",
        "0938B62C0B8FE641FE528A8411A26272C153E6CF",
        "9696B4AAFCA808BFFDE2A04AD2CA980F3652A5D4",
        "07A435FD12E96F72C09B31966577C9E71A248706",
    ]


def test_bip85_load_key_deterministic(monkeypatch):
    from pgpy import PGPKey

    seed = Seed(mnemonic=MNEMONIC)

    captured = {}

    def fake_run(cmd, input=None, capture_output=False, text=False, **kwargs):
        captured["armored"] = input
        class R:
            returncode = 0
            stdout = ""
            stderr = ""
        return R()

    monkeypatch.setattr("subprocess.run", fake_run)

    from seedsigner.gui.screens import seed_screens, tools_screens

    class DummyIndexScreen:
        def __init__(self, *args, **kwargs):
            pass
        def display(self):
            return "0"

    monkeypatch.setattr(
        seed_screens,
        "SeedBIP85SelectChildIndexScreen",
        DummyIndexScreen,
    )

    inputs = iter([
        {"textToEncode": "Test"},
        {"textToEncode": "t@example.com"},
        {"textToEncode": ""},
    ])

    class DummyTextEntry:
        def __init__(self, textToEncode="", title=""):
            pass
        def display(self):
            return next(inputs)

    monkeypatch.setattr(
        tools_screens,
        "ToolsTextQRTextEntryScreen",
        DummyTextEntry,
    )

    class DummyLoading:
        def __init__(self, text=""):
            pass
        def start(self):
            pass
        def stop(self):
            pass

    from seedsigner.gui.screens import screen as screen_mod
    monkeypatch.setattr(screen_mod, "LoadingScreenThread", DummyLoading)

    def fake_run_screen(self, screen, **kwargs):
        if kwargs.get("title") == "Key Type":
            return 0
        return 0

    monkeypatch.setattr(tools_views.ToolsGPGLoadBIP85KeyView, "run_screen", fake_run_screen)

    controller = type(
        "C",
        (),
        {
            "storage": type("S", (), {"seeds": [seed]})(),
            "get_seed": lambda self, idx: seed,
        },
    )()
    from seedsigner.models.settings_definition import SettingsConstants
    settings = type(
        "S",
        (),
        {"get_value": lambda self, x: SettingsConstants.MAINNET},
    )()

    view = object.__new__(tools_views.ToolsGPGLoadBIP85KeyView)
    view.controller = controller
    view.settings = settings

    tools_views.BIP85_DATA.clear()
    tools_views.ToolsGPGLoadBIP85KeyView.run(view)
    fpr1 = PGPKey.from_blob(captured["armored"])[0].fingerprint

    inputs = iter([
        {"textToEncode": "Test"},
        {"textToEncode": "t@example.com"},
        {"textToEncode": ""},
    ])
    class DummyTextEntry2:
        def __init__(self, textToEncode="", title=""):
            pass
        def display(self):
            return next(inputs)

    monkeypatch.setattr(
        tools_screens,
        "ToolsTextQRTextEntryScreen",
        DummyTextEntry2,
    )
    captured.clear()
    tools_views.ToolsGPGLoadBIP85KeyView.run(view)
    fpr2 = PGPKey.from_blob(captured["armored"])[0].fingerprint

    assert fpr1 == fpr2


def test_bip85_add_subkeys_index_sequential(monkeypatch):
    import datetime, subprocess
    from pgpy import PGPKey, PGPUID
    from pgpy.pgp import PrivKeyV4
    from pgpy.constants import (
        PubKeyAlgorithm,
        KeyFlags,
        HashAlgorithm,
        SymmetricKeyAlgorithm,
        CompressionAlgorithm,
    )

    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    created = datetime.datetime.fromtimestamp(
        BIP85_GPG_CREATED_TS, tz=datetime.timezone.utc
    )
    pk = PrivKeyV4()
    pk.pkalg = PubKeyAlgorithm.ECDSA
    pk.keymaterial = bip85_p256_from_root(root, 0)
    pk.created = created
    pk.update_hlen()
    pgp_key = PGPKey()
    pgp_key._key = pk
    uid = PGPUID.new("Test", email="t@example.com")
    pgp_key.add_uid(
        uid,
        usage={KeyFlags.Certify, KeyFlags.Sign},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB],
        created=created,
    )

    def fake_run(cmd, capture_output=False, text=False, input=None):
        class Result:
            def __init__(self, stdout=""):
                self.stdout = stdout
                self.returncode = 0

        if "--export-secret-keys" in cmd:
            return Result(str(pgp_key))
        return Result()

    monkeypatch.setattr(subprocess, "run", fake_run)

    added1 = bip85_add_subkeys(pgp_key.fingerprint, "ed25519", 0, 0, seed)
    added2 = bip85_add_subkeys(pgp_key.fingerprint, "secp256k1", 1, 3, seed)
    assert [a["index"] for a in added1] == [0, 1, 2]
    assert [a["index"] for a in added2] == [3, 4, 5]


def test_bip85_verify_existing_supports_cv25519():
    import datetime
    from pgpy import PGPKey
    from pgpy.pgp import PrivKeyV4, PrivSubKeyV4
    from pgpy.constants import PubKeyAlgorithm

    seed = Seed(mnemonic=MNEMONIC)
    root = bip32.HDKey.from_seed(seed.seed_bytes)
    created = datetime.datetime.fromtimestamp(
        BIP85_GPG_CREATED_TS, tz=datetime.timezone.utc
    )

    pk = PrivKeyV4()
    pk.pkalg = PubKeyAlgorithm.EdDSA
    pk.keymaterial = bip85_ed25519_from_root(root, 0)
    pk.created = created
    pk.update_hlen()
    primary = PGPKey()
    primary._key = pk

    subkeys = []
    for sub_index, pkalg, usage, alg_name in _bip85_subkey_specs("ed25519"):
        subpkt = PrivSubKeyV4()
        subpkt.pkalg = pkalg
        subpkt.keymaterial = bip85_ed25519_from_root(root, 0, sub_index, alg_name)
        subpkt.created = created
        subpkt.update_hlen()
        subkey = PGPKey()
        subkey._key = subpkt
        curve = "cv25519" if alg_name == "ECDH" else "ed25519"
        subkeys.append(
            {
                "idx": sub_index + 1,
                "fpr": subkey.fingerprint,
                "algo": str(pkalg.value),
                "curve": curve,
                "bits": "255",
            }
        )

    assert bip85_verify_existing(
        seed,
        primary.fingerprint,
        0,
        BIP85_GPG_CREATED_TS,
        "22",
        "255",
        "ed25519",
        subkeys,
    )


def test_parse_secret_key_list_primary_fingerprint_only():
    output = "\n".join(
        [
            "sec:-:0:0:::0::::::23::0:",
            "fpr:::::::::PRIMARYFPR:",
            "uid::::Test User:::::::",
            "ssb:-:0:0:::0::::::23::0:",
            "fpr:::::::::SUBKEYFPR:",
        ]
    )
    keys = parse_secret_key_list(output)
    assert keys[0]["fpr"] == "PRIMARYFPR"


def test_parse_secret_key_list_includes_created():
    output = "\n".join(
        [
            f"sec:-:0:0:KEYID:{BIP85_GPG_CREATED_TS}:0::::::23::0:",
            "fpr:::::::::PRIMARYFPR:",
            f"uid:u::::{BIP85_GPG_CREATED_TS}::HASH::Test User::::::::0:",
        ]
    )
    keys = parse_secret_key_list(output)
    assert keys[0]["created"] == BIP85_GPG_CREATED_TS


def test_parse_subkey_list_extracts_fingerprint():
    output = "\n".join(
        [
            "ssb:-:2048:1:::0::::::s::",
            "fpr:::::::::SUBFPR1:",
            "ssb:-:256:19:::0::::::e::::nistp256:",
            "fpr:::::::::SUBFPR2:",
        ]
    )
    subs = parse_subkey_list(output)
    assert subs[0]["fpr"] == "SUBFPR1"
    assert subs[1]["fpr"] == "SUBFPR2"
    assert subs[0]["idx"] == 1
    assert subs[1]["idx"] == 2
    assert subs[0]["algo"] == "1"
    assert subs[0]["bits"] == "2048"
    assert subs[0]["curve"] == ""
    assert subs[1]["algo"] == "19"
    assert subs[1]["bits"] == "256"
    assert subs[1]["curve"] == "nistp256"


def test_parse_uid_list_extracts_uids():
    output = "\n".join(
        [
            "sec:-:0:0:KEYID:::0::::::23::0:",
            "fpr:::::::::PRIMARYFPR:",
            "uid:::::::::User One::",
            "uid:::::::::User Two::",
        ]
    )
    uids = parse_uid_list(output)
    assert uids[0]["uid"] == "User One"
    assert uids[0]["idx"] == 1
    assert uids[1]["uid"] == "User Two"
    assert uids[1]["idx"] == 2


def test_add_uid_preserves_primary(tmp_path):
    from subprocess import run

    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir()
    os.chmod(gnupg_home, 0o700)
    env = {**os.environ, "GNUPGHOME": str(gnupg_home)}

    run(
        [
            "gpg",
            "--batch",
            "--passphrase",
            "",
            "--pinentry-mode",
            "loopback",
            "--quick-gen-key",
            "tester@example.com",
        ],
        env=env,
        check=True,
    )

    result = run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    keys = parse_secret_key_list(result.stdout)
    fpr = keys[0]["fpr"]
    primary = keys[0]["uid"]

    run(
        [
            "gpg",
            "--batch",
            "--quick-add-uid",
            fpr,
            "Another User <alt@example.com>",
        ],
        env=env,
        check=True,
    )
    run(
        ["gpg", "--batch", "--quick-set-primary-uid", fpr, primary],
        env=env,
        check=True,
    )

    result = run(
        ["gpg", "--list-secret-keys", "--with-colons", fpr],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    uids = parse_uid_list(result.stdout)
    assert uids[0]["uid"] == primary


def test_uid_menu_includes_set_primary_option(monkeypatch):
    from seedsigner.views import tools_views

    captured = {}

    def fake_run_screen(self, screen, *args, **kwargs):
        captured["labels"] = [b.button_label for b in kwargs.get("button_data", [])]
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsGPGUidMenuView, "run_screen", fake_run_screen)
    view = tools_views.ToolsGPGUidMenuView()
    view.run()
    assert "Set Primary User ID" in captured["labels"]


def test_set_primary_uid_sets_selected_uid(tmp_path, monkeypatch):
    import subprocess
    from seedsigner.views import tools_views

    gnupg_home = tmp_path / "gnupg"
    gnupg_home.mkdir()
    os.chmod(gnupg_home, 0o700)
    env = {**os.environ, "GNUPGHOME": str(gnupg_home)}

    subprocess.run(
        [
            "gpg",
            "--batch",
            "--passphrase",
            "",
            "--pinentry-mode",
            "loopback",
            "--quick-gen-key",
            "tester@example.com",
        ],
        env=env,
        check=True,
    )

    result = subprocess.run(
        ["gpg", "--list-secret-keys", "--with-colons"],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    keys = parse_secret_key_list(result.stdout)
    fpr = keys[0]["fpr"]

    subprocess.run(
        ["gpg", "--batch", "--quick-add-uid", fpr, "Another <alt@example.com>"],
        env=env,
        check=True,
    )

    subprocess.run(
        ["gpg", "--batch", "--quick-set-primary-uid", fpr, "tester@example.com"],
        env=env,
        check=True,
    )

    real_run = subprocess.run

    def fake_run(cmd, *args, **kwargs):
        kwargs.setdefault("env", env)
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", fake_run)

    def fake_run_screen(self, screen, *args, **kwargs):
        title = kwargs.get("title")
        if title == "Select Key":
            return 0
        if title == "Set Primary User ID":
            return 1
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsGPGSetPrimaryUidView, "run_screen", fake_run_screen)

    view = tools_views.ToolsGPGSetPrimaryUidView()
    view.run()

    result = real_run(
        ["gpg", "--list-secret-keys", "--with-colons", fpr],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    uids = parse_uid_list(result.stdout)
    assert uids[0]["uid"] == "Another <alt@example.com>"


def test_load_bip85_key_selects_seed(monkeypatch):
    from seedsigner.views import tools_views

    controller = Controller.get_instance()
    original = list(controller.storage.seeds)
    controller.storage.seeds = [Seed(mnemonic=MNEMONIC), Seed(mnemonic=MNEMONIC)]

    responses = iter([1, RET_CODE__BACK_BUTTON])
    screens = []

    def fake_run_screen(self, screen, *args, **kwargs):
        screens.append(screen)
        return next(responses)

    class DummyIndexScreen:
        def __init__(self, *args, **kwargs):
            pass

        def display(self):
            return "0"

    monkeypatch.setattr(tools_views.ToolsGPGLoadBIP85KeyView, "run_screen", fake_run_screen)
    monkeypatch.setattr(
        tools_views.seed_screens, "SeedBIP85SelectChildIndexScreen", DummyIndexScreen
    )

    captured = {}

    def fake_get_seed(idx):
        captured["idx"] = idx
        return controller.storage.seeds[idx]

    monkeypatch.setattr(controller, "get_seed", fake_get_seed)

    view = tools_views.ToolsGPGLoadBIP85KeyView()
    try:
        view.run()
    finally:
        controller.storage.seeds = original

    assert captured["idx"] == 1
    assert screens[0] == tools_views.seed_screens.SeedSelectSeedScreen


def test_filter_deletable_subkeys_bip85_only_latest():
    BIP85_DATA.clear()
    fpr = "P"
    BIP85_DATA[fpr] = {
        "primary_fpr": fpr,
        "seed_fpr": "S",
        "index": 0,
        "key_type": "NIST P-256",
        "uids": [],
        "subkeys": [
            {"index": 0, "type": "ECDH NIST P-256", "fingerprint": "A"},
            {"index": 1, "type": "ECDSA NIST P-256", "fingerprint": "B"},
        ],
        "revocations": [],
    }
    bip85_subs = [
        {"fpr": "A", "caps": "e", "idx": 1, "created": 0},
        {"fpr": "B", "caps": "s", "idx": 2, "created": 0},
    ]
    filtered = filter_deletable_subkeys(fpr, bip85_subs)
    assert len(filtered) == 1 and filtered[0]["idx"] == 2

    BIP85_DATA.clear()
    non_bip85 = [
        {"fpr": "A", "caps": "e", "idx": 1, "created": 0},
        {"fpr": "B", "caps": "s", "idx": 2, "created": 1},
    ]
    filtered2 = filter_deletable_subkeys("Z", non_bip85)
    assert len(filtered2) == 2


def test_bip85_save_and_load(tmp_path):
    BIP85_DATA.clear()
    fpr = "F"
    BIP85_DATA[fpr] = {
        "primary_fpr": fpr,
        "seed_fpr": "seedfpr",
        "index": 0,
        "key_type": "NIST P-256",
        "uids": ["User <user@example.com>"],
        "primary_uid": "User <user@example.com>",
        "subkeys": [{"index": 0, "type": "ECDH NIST P-256", "fingerprint": "A"}],
        "revocations": ["A"],
    }
    file_path = tmp_path / "bip85.json"
    bip85_save_data(file_path)
    BIP85_DATA.clear()
    bip85_load_data(file_path)
    assert BIP85_DATA[fpr]["seed_fpr"] == "seedfpr"
    assert BIP85_DATA[fpr]["key_type"] == "NIST P-256"
    assert BIP85_DATA[fpr]["uids"][0] == "User <user@example.com>"
    assert BIP85_DATA[fpr]["primary_uid"] == "User <user@example.com>"
    assert BIP85_DATA[fpr]["subkeys"][0]["type"] == "ECDH NIST P-256"


def test_load_bip85_data_from_microsd(monkeypatch, tmp_path):
    from pathlib import Path

    captured = {}

    def fake_bip85_load_data(path):
        captured["path"] = Path(path)

    monkeypatch.setattr(tools_views, "bip85_load_data", fake_bip85_load_data)
    monkeypatch.setattr(
        tools_views.MicroSD, "get_microsd_dir", lambda: tmp_path
    )

    def fake_run_screen(self, *args, **kwargs):
        return 0  # Select "From MicroSD"

    monkeypatch.setattr(
        tools_views.ToolsGPGLoadBip85DataView, "run_screen", fake_run_screen
    )

    view = tools_views.ToolsGPGLoadBip85DataView()
    view.run()

    expected = tmp_path / "microsd-images" / "bip85_data.json"
    assert captured["path"] == expected


def test_bip85_save_to_qr(monkeypatch):
    from seedsigner.gui.screens.screen import ButtonListScreen, QRDisplayScreen, WarningScreen
    from seedsigner.models.encode_qr import UrBytesQrEncoder
    import json

    BIP85_DATA.clear()
    fpr = "F"
    BIP85_DATA[fpr] = {
        "primary_fpr": fpr,
        "seed_fpr": "S",
        "index": 0,
        "key_type": "NIST P-256",
        "uids": [],
        "subkeys": [],
        "revocations": [],
    }

    captured = {}

    def fake_run_screen(self, screen, *args, **kwargs):
        if screen == ButtonListScreen:
            return 1  # select To QR
        if screen == WarningScreen:
            return 0  # start QR display
        if screen == QRDisplayScreen:
            captured["encoder"] = kwargs["qr_encoder"]
            return RET_CODE__BACK_BUTTON
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsGPGSaveBip85DataView, "run_screen", fake_run_screen)
    view = tools_views.ToolsGPGSaveBip85DataView()
    view.run()
    encoder = captured["encoder"]
    assert isinstance(encoder, UrBytesQrEncoder)
    data = json.loads(encoder.data.decode())[0]
    assert data["primary_fpr"] == fpr


def test_bip85_save_to_microsd_logs_path(monkeypatch, tmp_path):
    from seedsigner.gui.screens.screen import ButtonListScreen, WarningScreen
    from seedsigner.hardware import microsd

    BIP85_DATA.clear()
    BIP85_DATA["F"] = {
        "primary_fpr": "F",
        "seed_fpr": "S",
        "index": 0,
        "key_type": "NIST P-256",
        "uids": [],
        "subkeys": [],
        "revocations": [],
    }

    captured = {}

    def fake_run_screen(self, screen, *args, **kwargs):
        if screen == ButtonListScreen:
            return 0  # select To MicroSD
        if screen == WarningScreen:
            return 0
        return 0

    def fake_save(path):
        captured["path"] = path

    logs = []

    def fake_log(msg, *args):
        logs.append(msg % args)

    monkeypatch.setattr(tools_views.ToolsGPGSaveBip85DataView, "run_screen", fake_run_screen)
    monkeypatch.setattr(tools_views, "bip85_save_data", fake_save)
    monkeypatch.setattr(tools_views.logger, "info", fake_log)
    monkeypatch.setattr(microsd.MicroSD, "get_microsd_dir", lambda: tmp_path)

    view = tools_views.ToolsGPGSaveBip85DataView()
    view.controller.storage.seeds = []
    view.run()

    expected_path = tmp_path / "microsd-images" / "bip85_data.json"
    assert captured["path"] == expected_path
    assert any(str(expected_path) in entry for entry in logs)


def test_bip85_save_to_seedkeeper(monkeypatch):
    from seedsigner.gui.screens.screen import ButtonListScreen

    class DummyConnector:
        def __init__(self):
            self.saved = None

        def card_get_status(self):
            return (None, None, None, {"protocol_minor_version": 2})

        def make_header(self, t, rights, label):
            return {"label": label}

        def seedkeeper_import_secret(self, secret_dic):
            self.saved = secret_dic

    dummy = DummyConnector()
    monkeypatch.setattr(
        tools_views.seedkeeper_utils, "init_satochip", lambda *a, **k: dummy
    )

    BIP85_DATA.clear()
    BIP85_DATA["F"] = {
        "primary_fpr": "F",
        "seed_fpr": "S",
        "index": 0,
        "key_type": "NIST P-256",
        "uids": [],
        "subkeys": [],
        "revocations": [],
    }

    def fake_run_screen(self, screen, *args, **kwargs):
        if screen == ButtonListScreen:
            return 2  # select To Seedkeeper
        return 0

    monkeypatch.setattr(tools_views.ToolsGPGSaveBip85DataView, "run_screen", fake_run_screen)
    view = tools_views.ToolsGPGSaveBip85DataView()
    view.run()
    assert dummy.saved is not None
    assert dummy.saved["header"]["label"].startswith("BIP85-GPG-")


def test_bip85_seedkeeper_import_format():
    import json, binascii

    data_json = json.dumps(
        [
            {
                "primary_fpr": "F",
                "seed_fpr": "S",
                "index": 0,
                "key_type": "NIST P-256",
                "uids": [],
                "subkeys": [],
                "revocations": [],
            }
        ]
    )
    secret_hex = (
        len(data_json.encode()).to_bytes(2, "big") + data_json.encode()
    ).hex()
    BIP85_DATA.clear()
    decoded = binascii.unhexlify(secret_hex)[2:]
    tools_views.bip85_import_json(decoded.decode())
    assert BIP85_DATA["F"]["seed_fpr"] == "S"
    assert BIP85_DATA["F"]["key_type"] == "NIST P-256"


def test_advanced_menu_has_bip85_data_options(monkeypatch):
    buttons = {}

    def fake_run_screen(*args, **kwargs):
        buttons["labels"] = [b.button_label for b in kwargs["button_data"]]
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGAdvancedMenuView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGAdvancedMenuView()
    view.run()
    assert "BIP85 Metadata" in buttons["labels"]


def test_bip85_metadata_menu_has_options(monkeypatch):
    buttons = {}

    def fake_run_screen(*args, **kwargs):
        buttons["labels"] = [b.button_label for b in kwargs["button_data"]]
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGBip85MetadataMenuView, "run_screen", fake_run_screen
    )
    view = tools_views.ToolsGPGBip85MetadataMenuView()
    view.run()
    assert "Save BIP85 Data" in buttons["labels"]
    assert "Load BIP85 Data" in buttons["labels"]
    assert "Rebuild BIP85 Key" in buttons["labels"]


def test_rebuild_bip85_key(monkeypatch):
    controller = Controller.get_instance()
    seed = Seed(mnemonic=MNEMONIC)
    original = controller.storage.seeds
    controller.storage.seeds = [seed]
    fpr = seed.get_fingerprint()
    tools_views.BIP85_DATA.clear()
    tools_views.BIP85_DATA["X"] = {
        "primary_fpr": "X",
        "seed_fpr": fpr,
        "index": 1,
        "key_type": "NIST P-256",
        "uids": ["Other <o@b.com>", "Primary <a@b.com>"],
        "primary_uid": "Primary <a@b.com>",
        "subkeys": [
            {"index": 0, "type": "ECDH NIST P-256", "fingerprint": "F0"},
            {"index": 1, "type": "ECDSA NIST P-256", "fingerprint": "F1"},
            {"index": 2, "type": "ECDSA NIST P-256", "fingerprint": "F2"},
            {"index": 3, "type": "RSA 2048", "fingerprint": "F3"},
            {"index": 4, "type": "RSA 2048", "fingerprint": "F4"},
            {"index": 5, "type": "RSA 2048", "fingerprint": "F5"},
        ],
        "revocations": [],
    }
    # round-trip export/import
    data_json = tools_views.bip85_export_json()
    tools_views.BIP85_DATA.clear()
    tools_views.bip85_import_json(data_json)

    captured = {}

    def fake_run_screen(self, *args, **kwargs):
        if args[0].__name__ == "ButtonListScreen":
            captured["labels"] = [b.button_label for b in kwargs["button_data"]]
            return 0
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(
        tools_views.ToolsGPGRebuildBip85KeyView, "run_screen", fake_run_screen
    )

    def fake_run(cmd, input=None, capture_output=False):
        captured["cmd"] = cmd
        class Result:
            returncode = 0
        return Result()

    monkeypatch.setattr(tools_views.subprocess, "run", fake_run)

    added = []
    import pgpy

    real_add_uid = pgpy.PGPKey.add_uid

    def fake_add_uid(self, uid, selfsign=True, **prefs):
        label = uid.name
        if uid.email:
            label += f" <{uid.email}>"
        added.append((label, prefs.get("primary", False)))
        if len(self._uids) == 0:
            return real_add_uid(self, uid, selfsign=selfsign, **prefs)
        return None

    monkeypatch.setattr(pgpy.PGPKey, "add_uid", fake_add_uid)

    calls = []
    real = tools_views.bip85_p256_from_root

    def fake_p256(root, key_index, sub_index=None, alg=None):
        calls.append(("p256", key_index, sub_index, alg))
        return real(root, key_index, sub_index, alg)

    monkeypatch.setattr(tools_views, "bip85_p256_from_root", fake_p256)

    rsa_calls = []
    real_rsa = tools_views.bip85_rsa_from_root

    def fake_rsa(root, bits, key_index, sub_index=None):
        rsa_calls.append((bits, key_index, sub_index))
        return real_rsa(root, bits, key_index, sub_index)

    monkeypatch.setattr(tools_views, "bip85_rsa_from_root", fake_rsa)

    verify_called = {}

    def fake_verify(seed, fingerprint, key_index, created_ts, primary_algo, primary_bits, primary_curve, subkeys):
        verify_called["subkeys"] = subkeys
        return True

    monkeypatch.setattr(tools_views, "bip85_verify_existing", fake_verify)

    view = tools_views.ToolsGPGRebuildBip85KeyView()
    try:
        view.run()
    finally:
        controller.storage.seeds = original

    assert captured["cmd"] == ["gpg", "--batch", "--import"]
    expected = [
        ("p256", 1, None, None),
        ("p256", 0, 0, "ECDH"),
        ("p256", 0, 1, "ECDSA"),
        ("p256", 0, 2, "ECDSA"),
    ]
    assert calls == expected
    assert rsa_calls == [(2048, 1, 0), (2048, 1, 1), (2048, 1, 2)]
    assert verify_called["subkeys"] == [
        {"idx": 1, "algo": "18", "bits": "", "curve": "nistp256", "fpr": "F0"},
        {"idx": 2, "algo": "19", "bits": "", "curve": "nistp256", "fpr": "F1"},
        {"idx": 3, "algo": "19", "bits": "", "curve": "nistp256", "fpr": "F2"},
        {"idx": 4, "algo": "1", "bits": "2048", "curve": "", "fpr": "F3"},
        {"idx": 5, "algo": "1", "bits": "2048", "curve": "", "fpr": "F4"},
        {"idx": 6, "algo": "1", "bits": "2048", "curve": "", "fpr": "F5"},
    ]
    assert added == [
        ("Primary <a@b.com>", True),
        ("Other <o@b.com>", False),
    ]


def test_bip85_subkey_specs_include_sign_for_auth():
    from pgpy.constants import KeyFlags

    specs = _bip85_subkey_specs("ed25519")
    auth_flags = specs[1][2]
    assert KeyFlags.Authentication in auth_flags
    assert KeyFlags.Sign in auth_flags


def test_select_import_algo_uses_selected_subkeys():
    subkeys = [
        {"fpr": "A", "algo": "1", "curve": ""},
        {"fpr": "B", "algo": "19", "curve": "nistp256"},
    ]
    algo, curve = _select_import_algo("1", "", subkeys, ["B"])
    assert algo == "19" and curve == "nistp256"


def test_select_import_algo_mixed_types_error():
    subkeys = [
        {"fpr": "A", "algo": "1", "curve": ""},
        {"fpr": "B", "algo": "19", "curve": "nistp256"},
    ]
    with pytest.raises(ValueError):
        _select_import_algo("1", "", subkeys, ["A", "B"])


def test_gpg_quick_addkey_uses_loopback(monkeypatch):
    from seedsigner.views import tools_views

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd

        class Dummy:
            returncode = 0

        return Dummy()

    monkeypatch.setattr(tools_views.subprocess, "run", fake_run)
    tools_views.gpg_quick_addkey("FPR", "rsa2048", "encrypt")
    assert captured["cmd"][:6] == [
        "gpg",
        "--batch",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
    ]
    assert captured["cmd"][6:] == [
        "--quick-addkey",
        "FPR",
        "rsa2048",
        "encrypt",
    ]


def test_gpg_edit_subkey_invokes_edit(monkeypatch):
    from seedsigner.views import tools_views

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        captured["input"] = kwargs.get("input")
        class Dummy:
            returncode = 0
        return Dummy()

    monkeypatch.setattr(tools_views.subprocess, "run", fake_run)
    tools_views.gpg_edit_subkey("FPR", 2, "revkey")
    assert captured["cmd"] == [
        "gpg",
        "--batch",
        "--yes",
        "--pinentry-mode",
        "loopback",
        "--passphrase",
        "",
        "--command-fd",
        "0",
        "--status-fd",
        "2",
        "--edit-key",
        "FPR",
    ]
    assert (
        captured["input"]
        == "key 2\nrevkey\ny\n0\n\ny\nsave\n"
    )


def test_loose_add_subkeys_uses_pgpy(monkeypatch):
    from types import SimpleNamespace
    from seedsigner.views import tools_views

    new_calls = []
    state = {"add": 0, "unlock": 0}

    def fake_new(pkalg, curve):
        new_calls.append((pkalg, curve))
        return SimpleNamespace(_key=SimpleNamespace(created=None, update_hlen=lambda: None))

    from contextlib import contextmanager

    class MainKey:
        def __init__(self):
            self._key = SimpleNamespace(created=None)
            self.expires_at = None
            self.is_protected = True

        def unlock(self, passphrase):
            state["unlock"] += 1

            @contextmanager
            def cm():
                yield

            return cm()

        def add_subkey(self, subkey, **kwargs):
            state["add"] += 1

    def fake_from_blob(data):
        return MainKey(), None

    import pgpy

    monkeypatch.setattr(
        pgpy,
        "PGPKey",
        SimpleNamespace(new=fake_new, from_blob=fake_from_blob),
    )

    def fake_run(cmd, *args, **kwargs):
        class R:
            returncode = 0
            stdout = ""

        return R()

    monkeypatch.setattr("seedsigner.views.tools_views.subprocess.run", fake_run)

    assert tools_views.loose_add_subkeys("FPR", "secp256k1")
    assert len(new_calls) == 3
    assert state["add"] == 3
    assert state["unlock"] == 1


def test_gpg_export_selected_subkeys_filters(monkeypatch):
    from seedsigner.views import tools_views

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        class R:
            returncode = 0
            stdout = "data"

        return R()

    monkeypatch.setattr(tools_views.subprocess, "run", fake_run)
    tools_views.gpg_export_selected_subkeys("FPR", ["A" * 40, "B" * 40, "C" * 40])
    cmd = captured["cmd"]
    assert cmd == [
        "gpg",
        "--armor",
        "--export-options=export-minimal",
        "--export-secret-subkeys",
        "FPR",
        "AAAAAAAAAAAAAAAA!",
        "BBBBBBBBBBBBBBBB!",
        "CCCCCCCCCCCCCCCC!",
    ]


def test_add_subkeys_auto_bip85_index(monkeypatch):
    import seedsigner.views.tools_views as tools_views

    # Mock gpg list outputs: first call lists one BIP85 key, second shows three subkeys
    def fake_run(cmd, *args, **kwargs):
        class R:
            returncode = 0

            def __init__(self, stdout=""):
                self.stdout = stdout

        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    "sec:-:0:0:KEYID:0:0:::::::\n"
                    f"fpr:::::::::FPR:\n"
                    f"uid:u::::{tools_views.BIP85_GPG_CREATED_TS}::H::User::::::::\n"
                )
            else:
                return R(
                    "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
                )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    tools_views.BIP85_DATA["FPR"] = {
        "primary_fpr": "FPR",
        "seed_fpr": "seedfpr",
        "index": 0,
        "key_type": "NIST P-256",
        "uids": ["User"],
        "primary_uid": "User",
        "subkeys": [
            {"index": 0, "type": "ECDH NIST P-256", "fingerprint": "A"},
            {"index": 1, "type": "ECDSA NIST P-256", "fingerprint": "B"},
            {"index": 2, "type": "ECDSA NIST P-256", "fingerprint": "C"},
        ],
        "revocations": [],
    }

    captured = {}

    def fake_bip85_add_subkeys(fpr, alg, key_index, start_index, seed):
        captured["key_index"] = key_index
        captured["start_index"] = start_index
        captured["seed"] = seed
        return []

    monkeypatch.setattr(tools_views, "bip85_add_subkeys", fake_bip85_add_subkeys)

    def fake_verify(seed, fingerprint, key_index, created_ts, primary_algo, primary_bits, primary_curve, subkeys):
        captured["verified_seed"] = seed
        captured["verified_key_index"] = key_index
        return True

    monkeypatch.setattr(tools_views, "bip85_verify_existing", fake_verify)

    class DummyLoading:
        def __init__(self, text=""):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(
        "seedsigner.gui.screens.screen.LoadingScreenThread", DummyLoading
    )

    class SeedObj:
        def get_fingerprint(self, network=None):
            return "seedfpr"

    seed_obj = SeedObj()

    # Simulate selecting the only key and NIST P-256 type
    def fake_run_screen(self, screen, **kwargs):
        assert kwargs.get("text") != "Choose seed for BIP85 subkeys"
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("title") == "Key Type":
            return 0
        return 0

    monkeypatch.setattr(tools_views.ToolsGPGAddSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(tools_views.ToolsGPGAddSubkeysView)
    ControllerClass = type(
        "C",
        (),
        {
            "storage": type("S", (), {"seeds": [seed_obj]})(),
            "get_seed": lambda self, idx: seed_obj,
        },
    )
    view.controller = ControllerClass()
    view.settings = type("Set", (), {"get_value": lambda self, x: None})()
    tools_views.ToolsGPGAddSubkeysView.run(view)
    assert captured["key_index"] == 1
    assert captured["start_index"] == 3
    assert captured["seed"] is seed_obj
    assert captured["verified_seed"] is seed_obj
    assert captured["verified_key_index"] == 0


def test_add_subkeys_registry_index_correction(monkeypatch):
    import seedsigner.views.tools_views as tools_views

    class R:
        def __init__(self, stdout=""):
            self.stdout = stdout

    def fake_run(cmd, capture_output=True, text=True):
        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    "sec:-:0:0:KEYID:0:0:::::::\n"
                    f"fpr:::::::::FPR:\n"
                    f"uid:u::::{tools_views.BIP85_GPG_CREATED_TS}::H::User::::::::\n"
                )
            return R(
                "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
            )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    tools_views.BIP85_DATA["FPR"] = {
        "primary_fpr": "FPR",
        "seed_fpr": "seedfpr",
        "index": 1,
        "key_type": "NIST P-256",
        "uids": ["User"],
        "primary_uid": "User",
        "subkeys": [],
        "revocations": [],
    }

    calls = []

    def fake_bip85_add_subkeys(fpr, alg, key_index, start_index, seed):
        calls.append(("add", key_index, start_index))
        return []

    monkeypatch.setattr(tools_views, "bip85_add_subkeys", fake_bip85_add_subkeys)

    def fake_verify(seed, fingerprint, key_index, created_ts, primary_algo, primary_bits, primary_curve, subkeys):
        calls.append(("verify", key_index))
        return key_index == 0

    monkeypatch.setattr(tools_views, "bip85_verify_existing", fake_verify)

    class DummyLoading:
        def __init__(self, text=""):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(
        "seedsigner.gui.screens.screen.LoadingScreenThread", DummyLoading
    )

    class SeedObj:
        def get_fingerprint(self, network=None):
            return "seedfpr"

    seed_obj = SeedObj()

    def fake_run_screen(self, screen, **kwargs):
        assert kwargs.get("text") != "Choose seed for BIP85 subkeys"
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("title") == "Key Type":
            return 0
        return 0

    monkeypatch.setattr(tools_views.ToolsGPGAddSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(tools_views.ToolsGPGAddSubkeysView)
    ControllerClass = type(
        "C",
        (),
        {
            "storage": type("S", (), {"seeds": [seed_obj]})(),
            "get_seed": lambda self, idx: seed_obj,
        },
    )
    view.controller = ControllerClass()
    view.settings = type("Set", (), {"get_value": lambda self, x: None})()
    tools_views.ToolsGPGAddSubkeysView.run(view)

    assert calls[0] == ("verify", 1)
    assert calls[1] == ("verify", 0)
    assert calls[2] == ("add", 1, 3)
    assert tools_views.BIP85_DATA["FPR"]["index"] == 0


def test_add_subkeys_missing_seed(monkeypatch):
    class R:
        def __init__(self, stdout=""):
            self.stdout = stdout

    def fake_run(cmd, capture_output=True, text=True):
        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    "sec:-:0:0:KEYID:0:0:::::::\n"
                    + f"fpr:::::::::FPR:\n"
                    + f"uid:u::::{tools_views.BIP85_GPG_CREATED_TS}::H::User::::::::\n"
                )
            return R(
                    "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
            )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    tools_views.BIP85_DATA["FPR"] = {
        "primary_fpr": "FPR",
        "seed_fpr": "seedfpr",
        "index": 0,
        "key_type": "NIST P-256",
        "uids": ["User"],
        "primary_uid": "User",
        "subkeys": [
            {"index": 0, "type": "ECDH NIST P-256", "fingerprint": "A"},
            {"index": 1, "type": "ECDSA NIST P-256", "fingerprint": "B"},
            {"index": 2, "type": "ECDSA NIST P-256", "fingerprint": "C"},
        ],
        "revocations": [],
    }

    called = {"add": False, "warning": None}

    def fake_bip85_add_subkeys(*args, **kwargs):
        called["add"] = True
        return []

    monkeypatch.setattr(tools_views, "bip85_add_subkeys", fake_bip85_add_subkeys)

    class SeedObj:
        def get_fingerprint(self, network=None):
            return "other"

    seed_obj = SeedObj()

    def fake_run_screen(self, screen, **kwargs):
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("title") == "Key Type":
            return 0
        if kwargs.get("text") == "Required seed not loaded":
            called["warning"] = kwargs.get("text")
            return 0
        assert kwargs.get("text") != "Choose seed for BIP85 subkeys"
        return 0

    monkeypatch.setattr(tools_views.ToolsGPGAddSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(tools_views.ToolsGPGAddSubkeysView)
    ControllerClass = type(
        "C",
        (),
        {
            "storage": type("S", (), {"seeds": [seed_obj]})(),
        },
    )
    view.controller = ControllerClass()
    view.settings = type("Set", (), {"get_value": lambda self, x: None})()
    tools_views.ToolsGPGAddSubkeysView.run(view)
    assert not called["add"]
    assert called["warning"] == "Required seed not loaded"


def test_delete_subkeys_bip85_only_latest(monkeypatch):
    import subprocess
    from seedsigner.views import tools_views

    ts = tools_views.BIP85_GPG_CREATED_TS

    def fake_run(cmd, *args, **kwargs):
        class R:
            returncode = 0

            def __init__(self, stdout=""):
                self.stdout = stdout

        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    f"sec:-:0:0:KEYID:0:0:::::::\n"
                    f"fpr:::::::::FPR:\n"
                    f"uid:u::::{ts}::H::User::::::::\n"
                )
            return R(
                "sec:-:0:0:KEYID:0:::::::\n"
                f"ssb:-:0:0::{ts}::::::e:::::\n"
                "fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n"
                f"ssb:-:0:0::{ts}::::::s:::::\n"
                "fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:\n"
                f"ssb:-:0:0::{ts}::::::e:::::\n"
                "fpr:::::::::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:\n"
            )
        return R()

    tools_views.BIP85_DATA["FPR"] = {
        "primary_fpr": "FPR",
        "seed_fpr": "seedfpr",
        "index": 0,
        "key_type": "NIST P-256",
        "uids": ["User"],
        "primary_uid": "User",
        "subkeys": [
            {
                "index": 0,
                "type": "ECDH NIST P-256",
                "fingerprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            },
            {
                "index": 1,
                "type": "ECDSA NIST P-256",
                "fingerprint": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            },
            {
                "index": 2,
                "type": "ECDSA NIST P-256",
                "fingerprint": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            },
        ],
        "revocations": [],
    }

    monkeypatch.setattr(subprocess, "run", fake_run)

    captured = {}

    def fake_run_screen(self, screen, **kwargs):
        if kwargs.get("title") == "WARNING":
            return 0
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("title") == "Delete Subkeys":
            captured["labels"] = [b.button_label for b in kwargs["button_data"]]
            return RET_CODE__BACK_BUTTON
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsGPGDeleteSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(tools_views.ToolsGPGDeleteSubkeysView)
    tools_views.ToolsGPGDeleteSubkeysView.run(view)

    assert captured["labels"] == ["CCCCCCCC [e]", "Done"]


def test_delete_subkeys_non_bip85_lists_all(monkeypatch):
    import subprocess
    from seedsigner.views import tools_views

    tools_views.BIP85_DATA.clear()

    def fake_run(cmd, *args, **kwargs):
        class R:
            returncode = 0

            def __init__(self, stdout=""):
                self.stdout = stdout

        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    "sec:-:0:0:KEYID:0:0:::::::\n"
                    "fpr:::::::::FPR:\n"
                    "uid:u::::0::H::User::::::::\n"
                )
            return R(
                "sec:-:0:0:KEYID:0:::::::\n"
                "ssb:-:0:0::1::::::e:::::\n"
                "fpr:::::::::AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:\n"
                "ssb:-:0:0::2::::::s:::::\n"
                "fpr:::::::::BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:\n"
                "ssb:-:0:0::3::::::e:::::\n"
                "fpr:::::::::CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC:\n"
            )
        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    captured = {}

    def fake_run_screen(self, screen, **kwargs):
        if kwargs.get("title") == "WARNING":
            return 0
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("title") == "Delete Subkeys":
            captured["labels"] = [b.button_label for b in kwargs["button_data"]]
            return RET_CODE__BACK_BUTTON
        return RET_CODE__BACK_BUTTON

    monkeypatch.setattr(tools_views.ToolsGPGDeleteSubkeysView, "run_screen", fake_run_screen)

    view = object.__new__(tools_views.ToolsGPGDeleteSubkeysView)
    tools_views.ToolsGPGDeleteSubkeysView.run(view)

    assert captured["labels"] == [
        "AAAAAAAA [e]",
        "BBBBBBBB [s]",
        "CCCCCCCC [e]",
        "Done",
    ]


def test_smartpgp_import_filters_subkeys(monkeypatch):
    import types, sys, datetime as dt
    from pgpy.constants import KeyFlags, EllipticCurveOID

    # Stub out the smartcard modules to avoid dependency on actual hardware libs
    sc = types.ModuleType("smartcard")
    sc_exc = types.ModuleType("smartcard.Exceptions")
    class NoCardException(Exception):
        pass
    sc_exc.NoCardException = NoCardException
    sc_sys = types.ModuleType("smartcard.System")
    sc_sys.readers = lambda: []
    sc_util = types.ModuleType("smartcard.util")
    sc_util.toHexString = lambda data: ""
    sc.Exceptions = sc_exc
    sc.System = sc_sys
    sc.util = sc_util
    sys.modules.update({
        "smartcard": sc,
        "smartcard.Exceptions": sc_exc,
        "smartcard.System": sc_sys,
        "smartcard.util": sc_util,
    })

    from seedsigner.helpers import smartpgp_import

    captured = {}

    def fake_run(cmd, capture_output=True, check=True):
        captured["cmd"] = cmd
        class Res:
            stdout = b"dummy"
        return Res()

    monkeypatch.setattr(smartpgp_import, "run", fake_run)

    sk_fpr = "F" * 40

    class KM:
        oid = EllipticCurveOID.NIST_P256
        s = 1
        class P:
            x = 1
            y = 1
        p = P()

    class Sub:
        def __init__(self):
            self.key_flags = {KeyFlags.Sign}
            self.fingerprint = sk_fpr
            self.created = dt.datetime(2020, 1, 1)
            self._key = type("K", (), {"keymaterial": KM})()

    class Key:
        def __init__(self):
            self.subkeys = {"a": Sub()}

    monkeypatch.setattr(smartpgp_import.pgpy.PGPKey, "from_blob", lambda data: (Key(), None))

    class DummyCtx:
        def __init__(self):
            self.admin_pin = None
        def connect(self):
            pass
        def verify_admin_pin(self):
            pass
        def cmd_switch_crypto(self, curve, role):
            pass
        def cmd_put_key(self, role, pub, priv):
            pass
        def cmd_put_data(self, tag, value):
            pass

    ctx_calls = {}
    class Ctx(DummyCtx):
        def cmd_put_key(self, role, pub, priv):
            ctx_calls["role"] = role
    monkeypatch.setattr(smartpgp_import, "CardConnectionContext", lambda: Ctx())

    assert smartpgp_import.import_keys_with_smartpgp("PRIFPR", "1234", {"s": sk_fpr})
    cmd = captured["cmd"]
    assert "--export-secret-subkeys" in cmd
    assert "--export-secret-key" not in cmd
    assert cmd[-1] == "FFFFFFFFFFFFFFFF!"
    assert ctx_calls["role"] == "sig"
