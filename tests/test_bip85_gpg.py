from embit import bip32, bip85
from seedsigner.models.seed import Seed
from seedsigner.views.tools_views import (
    bip85_brainpoolp256r1_from_root,
    bip85_ed25519_from_root,
    bip85_p256_from_root,
    bip85_rsa_from_root,
    bip85_secp256k1_from_root,
    _bip85_subkey_specs,
    parse_secret_key_list,
    parse_subkey_list,
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


def test_parse_subkey_list_extracts_fingerprint():
    output = "\n".join(
        [
            "ssb:-:0:0:::0::::::s::",
            "fpr:::::::::SUBFPR1:",
            "ssb:-:0:0:::0::::::e::",
            "fpr:::::::::SUBFPR2:",
        ]
    )
    subs = parse_subkey_list(output)
    assert subs[0]["fpr"] == "SUBFPR1"
    assert subs[1]["fpr"] == "SUBFPR2"
    assert subs[0]["idx"] == 1
    assert subs[1]["idx"] == 2


def test_bip85_subkey_specs_include_sign_for_auth():
    from pgpy.constants import KeyFlags

    specs = _bip85_subkey_specs("ed25519")
    auth_flags = specs[1][2]
    assert KeyFlags.Authentication in auth_flags
    assert KeyFlags.Sign in auth_flags


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
    state = {"add": 0}

    def fake_new(pkalg, curve):
        new_calls.append((pkalg, curve))
        return SimpleNamespace(_key=SimpleNamespace(created=None, update_hlen=lambda: None))

    class MainKey:
        def __init__(self):
            self._key = SimpleNamespace(created=None)
            self.expires_at = None

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
        "--export-filter",
        "keep-subkey=keyid=AAAAAAAAAAAAAAAA || keyid=BBBBBBBBBBBBBBBB || keyid=CCCCCCCCCCCCCCCC",
        "--export-secret-keys",
        "FPR",
    ]
    filt = cmd[cmd.index("--export-filter") + 1]
    assert all(f"keyid={x[-16:]}" in filt for x in ["A" * 40, "B" * 40, "C" * 40])
    assert filt.count("keyid=") == 3
