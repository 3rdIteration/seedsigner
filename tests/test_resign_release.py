"""Tests for the Luckfox release re-signing helper.

The signers themselves live in seedsigner-os and are installed onto the image by
its build; this app imports them at runtime and does not vendor a copy. So every
test here needs them resolvable, which `secure_boot_tools` does via
$SEEDSIGNER_SECURE_BOOT_DIR, /usr/lib/seedsigner/secure-boot, or a sibling
seedsigner-os checkout. Without any of those the whole module skips - the same
condition under which the app hides the menu entry.

  * Synthetic  - a release folder built from scratch (a Rockchip-shaped
    container, a FIT, a rootfs + .size), re-signed and verified.

  * Artifact   - if a real signed build is present in the sibling seedsigner-os
    checkout, re-sign a copy of it and verify. Skipped otherwise.
"""
import hashlib
import os
import shutil
import struct
import tempfile
import types

import pytest

from seedsigner.helpers import resign_release as rr
from seedsigner.helpers import secure_boot_tools


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OS_REPO = os.path.join(os.path.dirname(REPO), "seedsigner-os")

if not secure_boot_tools.is_available():
    pytest.skip("seedsigner-os signing tools not resolvable (set %s)"
                % secure_boot_tools.ENV_VAR, allow_module_level=True)

rk, fs, ms = secure_boot_tools.load()


def test_tools_resolve_to_a_real_directory():
    """The resolver is the only route to the signers, so prove it works."""
    directory = secure_boot_tools.find_dir()
    assert directory is not None
    for name in ("rkloader.py", "fitsign.py", "minisign.py"):
        assert os.path.isfile(os.path.join(directory, name))


def test_unavailable_tools_raise_a_useful_error(monkeypatch, tmp_path):
    """A missing install must explain itself, not surface as an ImportError."""
    monkeypatch.setenv(secure_boot_tools.ENV_VAR, str(tmp_path))
    monkeypatch.setattr(secure_boot_tools, "IMAGE_DIR", str(tmp_path))
    monkeypatch.setattr(secure_boot_tools, "_sibling_checkout_dir",
                        lambda: str(tmp_path))
    assert secure_boot_tools.is_available() is False
    with pytest.raises(secure_boot_tools.SecureBootToolsUnavailable) as e:
        secure_boot_tools.load()
    assert secure_boot_tools.ENV_VAR in str(e.value)


# --- a synthetic release ----------------------------------------------------

def _rk_container(n, hdr_off=0x0):
    buf = bytearray(b"\xa5" * (hdr_off + rk.HDR_LEN + rk.SIG_LEN + 0x40))
    buf[hdr_off:hdr_off + 4] = rk.MAGIC_UNSIGNED
    struct.pack_into("<I", buf, hdr_off + 0x0c, 0x01)
    buf[hdr_off + rk.MOD_OFF:hdr_off + rk.MOD_OFF + rk.SIG_LEN] = n.to_bytes(rk.SIG_LEN, "little")
    return buf


class _Fdt:
    def __init__(self):
        self.strings = bytearray()
        self.struct = bytearray()

    def _soff(self, name):
        b = name.encode() + b"\x00"
        at = bytes(self.strings).find(b)
        if at >= 0:
            return at
        at = len(self.strings)
        self.strings += b
        return at

    def begin(self, name):
        self.struct += struct.pack(">I", 1) + name.encode() + b"\x00"
        while len(self.struct) % 4:
            self.struct += b"\x00"

    def end(self):
        self.struct += struct.pack(">I", 2)

    def prop(self, name, value):
        self.struct += struct.pack(">III", 3, len(value), self._soff(name)) + value
        while len(self.struct) % 4:
            self.struct += b"\x00"

    def finish(self):
        self.struct += struct.pack(">I", 9)
        off_memrsv = 40
        off_struct = off_memrsv + 16
        off_strings = off_struct + len(self.struct)
        total = off_strings + len(self.strings)
        hdr = struct.pack(">10I", 0xd00dfeed, total, off_struct, off_strings,
                          off_memrsv, 17, 16, 0, len(self.strings), len(self.struct))
        return bytearray(hdr + b"\x00" * 16 + bytes(self.struct) + bytes(self.strings))


def _fit(payload, embed_modulus=None):
    """A FIT with one payload; optionally embedding an RSA modulus in it."""
    if embed_modulus is not None:
        payload = payload + embed_modulus.to_bytes(256, "big") + payload
    f = _Fdt()
    f.begin("")
    f.prop("timestamp", struct.pack(">I", 0))
    f.begin("images")
    f.begin("kernel")
    f.prop("type", b"kernel\x00")
    f.prop("data-size", struct.pack(">I", len(payload)))
    f.prop("data-position", struct.pack(">I", 0))
    f.begin("hash")
    f.prop("algo", b"sha256\x00")
    f.prop("value", hashlib.sha256(payload).digest())
    f.end()
    f.end()
    f.end()
    f.begin("configurations")
    f.begin("conf")
    f.prop("kernel", b"kernel\x00")
    prefix = len(f.strings)
    f.begin("signature")
    f.prop("algo", b"sha256,rsa2048\x00")
    f.prop("padding", b"pss\x00")
    f.prop("hashed-nodes", b"\x00".join([b"/", b"/configurations", b"/configurations/conf",
                                         b"/images/kernel", b"/images/kernel/hash"]) + b"\x00")
    f.prop("hashed-strings", struct.pack(">II", 0, prefix))
    f.prop("timestamp", struct.pack(">I", 1))
    f.prop("value", b"\x00" * 256)
    f.end()
    f.end()
    f.end()
    f.end()
    blob = f.finish()
    buf = blob + bytearray(payload)
    _, off = fs.fdt_props(buf)["/images/kernel"]["data-position"]
    struct.pack_into(">I", buf, off, len(blob))
    return buf


@pytest.fixture
def old_key():
    """A 2048-bit RSA key standing in for the published dev key."""
    from Cryptodome.PublicKey import RSA
    return RSA.generate(2048, e=65537)


@pytest.fixture
def new_key():
    from Cryptodome.PublicKey import RSA
    return RSA.generate(2048, e=65537)


@pytest.fixture
def release(tmp_path, old_key):
    folder = tmp_path / "release"
    folder.mkdir()
    n = int(old_key.n)
    (folder / "idblock.img").write_bytes(bytes(_rk_container(n, 0x0)))
    (folder / "download.bin").write_bytes(bytes(_rk_container(n, 0x1bc)))
    (folder / "uboot.img").write_bytes(bytes(_fit(b"UBOOT" * 64, embed_modulus=n)))
    (folder / "boot.img").write_bytes(bytes(_fit(b"KERNEL" * 64)))
    rootfs = b"ROOTFS-CONTENT" * 500
    (folder / "rootfs.img").write_bytes(rootfs + b"\xff" * 4096)   # padded, as on-device
    (folder / "rootfs.img.size").write_text(str(len(rootfs)))
    return str(folder)


ED_SEED = hashlib.sha256(b"test-ed25519-seed").digest()


def test_find_release_dirs(tmp_path, release):
    found = rr.find_release_dirs(str(tmp_path))
    assert release in found


def test_find_release_dirs_ignores_unrelated(tmp_path):
    (tmp_path / "photos").mkdir()
    (tmp_path / "photos" / "a.jpg").write_bytes(b"x")
    assert rr.find_release_dirs(str(tmp_path)) == []


def test_inspect_release(release, old_key):
    info = rr.inspect_release(release)
    assert set(info["files"]) == {"idblock.img", "download.bin", "uboot.img", "boot.img"}
    assert info["rootfs"].endswith("rootfs.img")
    assert info["current_rsa_modulus"] == int(old_key.n)


def test_resign_then_verify(release, new_key):
    report = rr.resign_release(release, new_key, ED_SEED)
    assert report.ok
    signed = dict(report.signed)
    assert set(signed) == {"idblock.img", "download.bin", "uboot.img", "boot.img", "rootfs.img"}

    checks = rr.verify_release(release, int(new_key.n), ED_SEED)
    assert checks
    for name, ok, detail in checks:
        assert ok, "%s (%s) failed to verify" % (name, detail)


def test_old_key_no_longer_verifies(release, old_key, new_key):
    rr.resign_release(release, new_key, ED_SEED)
    checks = rr.verify_release(release, int(old_key.n), ED_SEED)
    assert all(not ok for name, ok, _d in checks if name != "rootfs.img")


def test_uboot_embedded_key_is_swapped(release, old_key, new_key):
    """uboot.img holds the key U-Boot verifies boot.img with; it must change."""
    rr.resign_release(release, new_key, ED_SEED)
    data = open(os.path.join(release, "uboot.img"), "rb").read()
    assert int(old_key.n).to_bytes(256, "big") not in data
    assert int(new_key.n).to_bytes(256, "big") in data


def test_rootfs_signature_covers_only_the_declared_size(release, new_key):
    rr.resign_release(release, new_key, ED_SEED)
    path = os.path.join(release, "rootfs.img")
    with open(path, "r+b") as f:            # scribble in the padding
        f.seek(os.path.getsize(path) - 10)
        f.write(b"XXXX")
    checks = dict((n, ok) for n, ok, _d in rr.verify_release(release, int(new_key.n), ED_SEED))
    assert checks["rootfs.img"] is True


def test_rootfs_tamper_is_caught(release, new_key):
    rr.resign_release(release, new_key, ED_SEED)
    path = os.path.join(release, "rootfs.img")
    with open(path, "r+b") as f:
        f.seek(100)
        f.write(b"X")
    checks = dict((n, ok) for n, ok, _d in rr.verify_release(release, int(new_key.n), ED_SEED))
    assert checks["rootfs.img"] is False


def test_rejects_non_2048_bit_key(release):
    from Cryptodome.PublicKey import RSA
    with pytest.raises(rr.ResignError, match="RSA-2048 only"):
        rr.resign_release(release, RSA.generate(3072, e=65537), ED_SEED)


def test_rejects_empty_folder(tmp_path, new_key):
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(rr.ResignError, match="no signable images"):
        rr.resign_release(str(empty), new_key, ED_SEED)


def test_ed25519_key_id_matches_minisign_keygen(tmp_path):
    """The key id this writes must match what minisign.py keygen would write."""
    pub = tmp_path / "k.pub"
    ms.main(["keygen", "--entropy", ED_SEED.hex(), "-p", str(pub)])
    assert ms.load_pubkey(str(pub))["key_id"] == rr.ed25519_key_id(ED_SEED)


def test_bip85_ed25519_seed_matches_the_gpg_derivation():
    """The raw-seed helper must derive the same key as the OpenPGP path."""
    import base  # noqa: F401  - hardware mocks, and imports the views in a
                 #               working order (gpg_views alone is circular)
    from embit import bip32
    from seedsigner.views.tools_views import (bip85_ed25519_seed_from_root,
                                              bip85_ed25519_from_root)
    from seedsigner.helpers.ec_point import ed25519_pub_from_seed

    root = bip32.HDKey.from_seed(b"\x01" * 32)
    seed = bip85_ed25519_seed_from_root(root, 0)
    assert len(seed) == 32
    priv = bip85_ed25519_from_root(root, 0)
    assert ed25519_pub_from_seed(seed) == ed25519_pub_from_seed(
        int(priv.s).to_bytes(32, "big"))


# --- against a real build ---------------------------------------------------

def _real_release():
    out = os.path.join(OS_REPO, "opt", "luckfox", "build-output")
    if not os.path.isdir(out):
        return None
    for name in sorted(os.listdir(out)):
        folder = os.path.join(out, name)
        if os.path.isdir(folder) and rr.looks_like_release(folder):
            return folder
    return None


def test_resigns_a_real_build(tmp_path, new_key):
    src = _real_release()
    if not src:
        pytest.skip("no built release under seedsigner-os/opt/luckfox/build-output")
    folder = str(tmp_path / "real")
    shutil.copytree(src, folder)

    report = rr.resign_release(folder, new_key, ED_SEED)
    assert report.ok
    for name, ok, detail in rr.verify_release(folder, int(new_key.n), ED_SEED):
        assert ok, "%s (%s) failed to verify" % (name, detail)


def test_verify_release_catches_a_stale_component_hash(tmp_path, new_key):
    """A perfectly signed image with a stale component hash must not pass.

    The 0x600 header's signature covers the header, which contains the sha256 of
    the SPL and its DTB. Re-signing after mutating those without refreshing the
    hashes yields something that verifies cryptographically and is rejected at
    boot; verify_release has to catch it.
    """
    src = _real_release()
    if not src:
        pytest.skip("no built release under seedsigner-os/opt/luckfox/build-output")
    folder = str(tmp_path / "stale")
    shutil.copytree(src, folder)
    rr.resign_release(folder, new_key, ED_SEED)
    assert all(ok for _n, ok, _d in rr.verify_release(folder, int(new_key.n), ED_SEED))

    # corrupt a byte inside a hashed component, then re-sign the header ONLY
    path = os.path.join(folder, "idblock.img")
    buf = rk.read(path)
    lay = rk.layout(buf)
    start, _end, _h, _s, _a = rk.component_table(buf, lay)[1]
    buf[start + 32] ^= 0xff
    rk.prepare_for_signing(buf, lay)
    sig = rk.rsa_sign_digest(rk.msg_digest(buf, lay), int(new_key.n), int(new_key.d))
    off, _ = lay["sig"]
    buf[off:off + rk.SIG_LEN] = sig
    rk.write_out(buf, path, None)

    checks = dict((n, ok) for n, ok, _d in rr.verify_release(folder, int(new_key.n), ED_SEED))
    assert checks["idblock.img"] is False
