import pytest
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
    _bip85_subkey_specs,
    parse_secret_key_list,
    parse_subkey_list,
    parse_uid_list,
    filter_deletable_subkeys,
    BIP85_GPG_CREATED_TS,
    _select_import_algo,
)
from seedsigner.helpers.bip85_drng import BIP85DRNG

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
            "sec:-:0:0:KEYID:1231006505:0::::::23::0:",
            "fpr:::::::::PRIMARYFPR:",
        ]
    )
    keys = parse_secret_key_list(output)
    assert keys[0]["created"] == 1231006505


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
    env = {"GNUPGHOME": str(gnupg_home)}

    run(
        ["gpg", "--batch", "--passphrase", "", "--quick-gen-key", "tester@example.com"],
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
    env = {"GNUPGHOME": str(gnupg_home)}

    subprocess.run(
        ["gpg", "--batch", "--passphrase", "", "--quick-gen-key", "tester@example.com"],
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
    subs = [
        {"fpr": "A", "caps": "e", "idx": 1},
        {"fpr": "B", "caps": "s", "idx": 2},
    ]
    filtered = filter_deletable_subkeys(BIP85_GPG_CREATED_TS, subs)
    assert len(filtered) == 1 and filtered[0]["idx"] == 2
    filtered2 = filter_deletable_subkeys(0, subs)
    assert len(filtered2) == 2


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
                    f"sec:-:0:0:KEYID:{tools_views.BIP85_GPG_CREATED_TS}:0:::::::\n"
                    "fpr:::::::::FPR:\n"
                )
            else:
                return R(
                    "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
                )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    captured = {}

    def fake_bip85_add_subkeys(fpr, alg, key_index, start_index, seed):
        captured["key_index"] = key_index
        captured["start_index"] = start_index
        captured["seed"] = seed
        return True

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

    seed_obj = object()

    # Simulate selecting the only key, seed, and NIST P-256 type
    def fake_run_screen(self, screen, **kwargs):
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("text") == "Choose seed for BIP85 subkeys":
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
    assert captured["verified_key_index"] == 1


def test_add_subkeys_mismatched_seed(monkeypatch):
    class R:
        def __init__(self, stdout=""):
            self.stdout = stdout

    def fake_run(cmd, capture_output=True, text=True):
        if cmd[:3] == ["gpg", "--list-secret-keys", "--with-colons"]:
            if len(cmd) == 3:
                return R(
                    f"sec:-:0:0:KEYID:{tools_views.BIP85_GPG_CREATED_TS}:0:::::::\n"
                    "fpr:::::::::FPR:\n"
                )
            return R(
                "sec:-:0:0:KEYID:0:::::::\n" + "ssb:-:0:0:::0:::::::\n" * 3
            )
        return R()

    import subprocess

    monkeypatch.setattr(subprocess, "run", fake_run)

    called = {"add": False, "warning": None}

    def fake_bip85_add_subkeys(*args, **kwargs):
        called["add"] = True
        return True

    monkeypatch.setattr(tools_views, "bip85_add_subkeys", fake_bip85_add_subkeys)

    def fake_verify(*args, **kwargs):
        return False

    monkeypatch.setattr(tools_views, "bip85_verify_existing", fake_verify)

    seed_obj = object()

    def fake_run_screen(self, screen, **kwargs):
        if kwargs.get("title") == "Select Key":
            return 0
        if kwargs.get("text") == "Choose seed for BIP85 subkeys":
            return 0
        if kwargs.get("title") == "Key Type":
            return 0
        if kwargs.get("text") == "Selected seed/index mismatch":
            called["warning"] = kwargs.get("text")
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
    assert not called["add"]
    assert called["warning"] == "Selected seed/index mismatch"


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
