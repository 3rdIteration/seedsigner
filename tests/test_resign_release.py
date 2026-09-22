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

rk, fs, ms, lr = secure_boot_tools.load()


def test_tools_resolve_to_a_real_directory():
    """The resolver is the only route to the signers, so prove it works."""
    directory = secure_boot_tools.find_dir()
    assert directory is not None
    for name in ("rkloader.py", "fitsign.py", "minisign.py", "luckfox_release.py"):
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
    # The whole header key block (N, E and the PKA constant C), as the vendor
    # tools write it. check_release fails a header whose C does not match its
    # modulus, because a fused BootROM rejects exactly that image.
    rk.write_key_block(buf, hdr_off, n)
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


def test_resign_refreshes_the_rootfs_sidecar(tmp_path, new_key):
    """A MicroSD/eMMC release ships rootfs.img.minisig beside the rootfs: a copy of
    the signature inside boot.img. Resign Release must not leave the old one there."""
    folder = _full_release(tmp_path, kind="squashfs")
    sidecar = os.path.join(folder, lr.ROOTFS_SIDECAR)
    before = lr.initramfs_members(rk.read(os.path.join(folder, "boot.img")))["rootfs.sig"]
    with open(sidecar, "wb") as f:
        f.write(before)

    report = rr.resign_release(folder, new_key, ED_SEED)
    assert report.ok
    after = lr.initramfs_members(rk.read(os.path.join(folder, "boot.img")))["rootfs.sig"]
    assert after != before, "the rootfs signature should have changed"
    with open(sidecar, "rb") as f:
        assert f.read() == after, "sidecar still holds the old signature"
    assert lr.rootfs_sidecar_state(folder) == (True, True)


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


# --- the build tools on a release with a rootfs verifier in boot.img -----------
#
# The synthetic release builder lives with the OS library's own tests; reusing it
# keeps one definition of what a release looks like.

def _os_release_builder():
    tests_dir = os.path.normpath(os.path.join(secure_boot_tools.find_dir(), "..", "..", "..", "tests"))
    if not os.path.isfile(os.path.join(tests_dir, "test_luckfox_release.py")):
        pytest.skip("seedsigner-os tests/ not beside the tools (%s)" % tests_dir)
    import sys
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)
    import test_luckfox_release
    return test_luckfox_release


@pytest.fixture
def dev_key():
    """The published dev RSA key, as a PyCryptodome object."""
    from Cryptodome.PublicKey import RSA
    tlr = _os_release_builder()
    return RSA.construct((tlr.N, 65537, tlr.D))


def _full_release(root, **kw):
    """A whole NAND-style release signed with the dev keys, plus a stale update.img."""
    tlr = _os_release_builder()
    folder = os.path.join(str(root), "release")
    tlr.make_release(folder, **kw)
    for name, off in (("idblock.img", 0x0), ("download.bin", 0x1bc)):
        buf = _rk_container(tlr.N, off)
        rk.sign_buf(buf, rk.layout(buf), tlr.N, tlr.D)
        with open(os.path.join(folder, name), "wb") as f:
            f.write(bytes(buf))
    uboot = _fit(b"UBOOT" * 64, embed_modulus=tlr.N)
    fs.sign_buf(uboot, tlr.N, tlr.D)
    with open(os.path.join(folder, "uboot.img"), "wb") as f:
        f.write(bytes(uboot))
    with open(os.path.join(folder, "update.img"), "wb") as f:
        f.write(b"RKFW-stale")
    return folder


def _snapshot(folder):
    out = {}
    for n in sorted(os.listdir(folder)):
        with open(os.path.join(folder, n), "rb") as f:
            out[n] = hashlib.sha256(f.read()).hexdigest()
    return out


def test_synthetic_release_starts_valid(tmp_path):
    folder = _full_release(tmp_path)
    rep = lr.check_release(folder)
    assert rep.ok, lr.format_report(rep)
    assert rep.boot_key["dev"]


def test_resign_all_moves_the_rootfs_key_inside_boot_img(tmp_path, new_key):
    folder = _full_release(tmp_path)
    report = rr.resign_release(folder, new_key, ED_SEED)

    checks = {n: ok for n, ok, _d in rr.verify_release(folder, int(new_key.n), ED_SEED)}
    assert checks == {n: True for n in ("idblock.img", "download.bin", "uboot.img",
                                        "boot.img", "rootfs.img")}
    rep = lr.check_release(folder)
    assert rep.ok, lr.format_report(rep)
    assert rep.rootfs_key["key_id"] == rr.ed25519_key_id_text(ED_SEED)
    assert not rep.boot_key["dev"] and not rep.rootfs_key["dev"]
    members = lr.initramfs_members(rk.read(os.path.join(folder, "boot.img")))
    assert lr.key_classes(members) == {"FIT": "prod", "ROOTFS": "prod"}
    # the stale bundle is gone and the SD script now writes all of boot.img
    assert report.deleted_update_img and not os.path.exists(os.path.join(folder, "update.img"))
    assert not lr.sd_update_check(folder, "max")["fixable"]
    assert "rootfs.img" in dict(report.signed)


def test_resign_refusal_leaves_the_folder_untouched(tmp_path, new_key):
    folder = _full_release(tmp_path, kind="squashfs")
    with open(os.path.join(folder, "rootfs.img"), "r+b") as f:
        f.seek(0x40)
        f.write(b"EVIL")
    before = _snapshot(folder)
    with pytest.raises(rr.ResignError, match="refusing"):
        rr.resign_release(folder, new_key, ED_SEED)
    assert _snapshot(folder) == before


def test_export_pubkeys(tmp_path, new_key):
    from Cryptodome.PublicKey import RSA
    out = rr.export_pubkeys(str(tmp_path), new_key, ED_SEED, 3, 5)
    assert os.path.basename(out) == rr.KEYS_DIR
    with open(os.path.join(out, "release-rsa.pub"), "rb") as f:
        pem = f.read()
    assert b"PRIVATE" not in pem
    assert RSA.import_key(pem).n == new_key.n
    assert ms.load_pubkey(os.path.join(out, "release-rootfs.pub"))["key_id"] == \
        rr.ed25519_key_id(ED_SEED)
    with open(os.path.join(out, "README.txt")) as f:
        readme = f.read()
    assert rr.rsa_modulus_fingerprint(int(new_key.n)) in readme
    assert rr.ed25519_key_id_text(ED_SEED) in readme
    assert "index 3" in readme and "index 5" in readme
    # the keys folder is never offered as a release
    assert rr.find_release_dirs(str(tmp_path)) == []


def test_pubkeys_on_card(tmp_path, new_key, old_key):
    # an empty card holds nothing
    assert rr.pubkeys_on_card(str(tmp_path), new_key, ED_SEED) is False
    out = rr.export_pubkeys(str(tmp_path), new_key, ED_SEED, 3, 5)
    # the exported halves match exactly (the re-key ceremony skips a redundant export)
    assert rr.pubkeys_on_card(str(tmp_path), new_key, ED_SEED) is True
    # any other key pair does not match, even as valid public files
    assert rr.pubkeys_on_card(str(tmp_path), old_key, ED_SEED) is False
    assert rr.pubkeys_on_card(str(tmp_path), new_key,
                              hashlib.sha256(b"other-ed-seed").digest()) is False
    # a corrupt file counts as absent and never raises
    with open(os.path.join(out, "release-rsa.pub"), "wb") as f:
        f.write(b"garbage")
    assert rr.pubkeys_on_card(str(tmp_path), new_key, ED_SEED) is False


def test_provision_copies_and_fixes(tmp_path):
    card = tmp_path
    folder = _full_release(card)
    chk = rr.provision_check(folder, str(card))
    assert chk["problems"] == []
    assert chk["fixable"], "the synthetic script is deliberately short for boot.img"
    assert any("dev keys" in w for w in chk["warnings"])
    assert not chk["overwrite"]

    placed = rr.provision_microsd(folder, str(card))
    assert placed == ["sd_update.txt", "boot.img", "rootfs.img"]
    for name in placed:
        with open(os.path.join(card, name), "rb") as a, open(os.path.join(folder, name), "rb") as b:
            assert a.read() == b.read()
    assert not lr.sd_update_check(str(card), "max")["fixable"]
    assert rr.provision_check(folder, str(card))["overwrite"]


def test_provision_refuses_a_staging_overrun(tmp_path, monkeypatch):
    folder = _full_release(tmp_path)
    monkeypatch.setitem(lr.BOARDS["max"], "ceiling", 0x00200000)
    chk = rr.provision_check(folder, str(tmp_path))
    assert any("ceiling" in p for p in chk["problems"])


def test_provision_refuses_without_a_script(tmp_path):
    folder = _full_release(tmp_path)
    os.remove(os.path.join(folder, "sd_update.txt"))
    assert rr.provision_check(folder, str(tmp_path))["problems"]


def test_force_rootfs_check_on_and_off(tmp_path, dev_key):
    tlr = _os_release_builder()
    folder = _full_release(tmp_path)
    assert rr.force_rootfs_state(folder) is False
    rr.set_force_rootfs(folder, dev_key, True)
    assert rr.force_rootfs_state(folder) is True
    assert fs.verify_buf(rk.read(os.path.join(folder, "boot.img")), tlr.N)
    rr.set_force_rootfs(folder, dev_key, False)
    assert rr.force_rootfs_state(folder) is False


def test_force_rootfs_check_needs_the_release_key(tmp_path, new_key):
    folder = _full_release(tmp_path)
    before = _snapshot(folder)
    with pytest.raises(rr.ResignError, match="not the one"):
        rr.set_force_rootfs(folder, new_key, True)
    assert _snapshot(folder) == before


def test_force_rootfs_check_unsupported_on_an_old_verifier(tmp_path, dev_key):
    folder = _full_release(tmp_path, force_aware=False)
    assert rr.force_rootfs_state(folder) is None
    with pytest.raises(rr.ResignError, match="does not support"):
        rr.set_force_rootfs(folder, dev_key, True)


def test_arm_refuses_the_dev_key(tmp_path, dev_key):
    folder = _full_release(tmp_path)
    reasons = rr.arm_burn_check(folder)
    assert any("PUBLISHED dev key" in r for r in reasons)
    before = _snapshot(folder)
    with pytest.raises(rr.ResignError):
        rr.arm_burn(folder, dev_key)
    assert _snapshot(folder) == before


def test_arm_refuses_a_key_the_release_is_not_signed_with(tmp_path, new_key, old_key):
    folder = _full_release(tmp_path)
    rr.resign_release(folder, new_key, ED_SEED)
    assert rr.arm_burn_check(folder) == []
    before = _snapshot(folder)
    with pytest.raises(rr.ResignError, match="not the one"):
        rr.arm_burn(folder, old_key)
    assert _snapshot(folder) == before


def test_arms_a_real_build(tmp_path, new_key):
    src = _real_release()
    if not src or not os.path.isfile(os.path.join(src, "idblock.img")):
        pytest.skip("no built release under seedsigner-os/opt/luckfox/build-output")
    folder = str(tmp_path / "real")
    shutil.copytree(src, folder)
    rr.resign_release(folder, new_key, ED_SEED)
    rr.arm_burn(folder, new_key)
    buf = rk.read(os.path.join(folder, "idblock.img"))
    assert rk.is_burn_armed(buf)
    for name, ok, detail in rr.verify_release(folder, int(new_key.n), ED_SEED):
        assert ok, "%s (%s) failed to verify" % (name, detail)


# --- keys brought as files or SeedKeeper secrets ---------------------------------

def test_parse_rsa_key_formats(new_key):
    for data in (new_key.export_key(format="PEM"), new_key.export_key(format="DER"),
                 new_key.export_key(format="PEM", pkcs=8)):
        assert int(rr.parse_rsa_key(data).n) == int(new_key.n)


def test_parse_rsa_key_refusals(new_key):
    from Cryptodome.PublicKey import RSA
    with pytest.raises(rr.ResignError, match="PUBLIC"):
        rr.parse_rsa_key(new_key.publickey().export_key())
    with pytest.raises(rr.ResignError, match="passphrase"):
        rr.parse_rsa_key(new_key.export_key(passphrase="pw", pkcs=8,
                                            protection="PBKDF2WithHMAC-SHA1AndAES128-CBC"))
    with pytest.raises(rr.ResignError, match="RSA-2048 only"):
        rr.parse_rsa_key(RSA.generate(1024 + 1024 + 1024, e=65537).export_key())
    with pytest.raises(rr.ResignError, match="not an RSA"):
        rr.parse_rsa_key(b"hello")


def test_parse_ed25519_key_formats(tmp_path):
    from Cryptodome.PublicKey import ECC
    seed = bytes(range(32))
    pub, sec = tmp_path / "k.pub", tmp_path / "k.key"
    ms.main(["keygen", "--entropy", seed.hex(), "-p", str(pub), "-s", str(sec)])
    # A key this tooling generated: the stored id is the derived one.
    assert rr.parse_ed25519_key(sec.read_bytes()) == (seed, rr.ed25519_key_id(seed))
    # The other formats carry no id: None means "derive it from the seed".
    assert rr.parse_ed25519_key(seed) == (seed, None)
    assert rr.parse_ed25519_key(seed.hex().encode() + b"\n") == (seed, None)
    ecc = ECC.construct(curve="Ed25519", seed=seed)
    assert rr.parse_ed25519_key(ecc.export_key(format="PEM").encode()) == (seed, None)
    assert rr.parse_ed25519_key(ecc.export_key(format="DER")) == (seed, None)


def test_parse_ed25519_key_keeps_a_third_partys_stored_id(tmp_path):
    """minisign -G randomises the key id; it is not derivable from the seed and
    must travel with the key, or signatures fail host-side verification against
    the original public key file."""
    seed = bytes(range(32))
    pk = ms.ed25519_public(seed)
    foreign_id = b"\x01" * 8
    assert foreign_id != rr.ed25519_key_id(seed)
    sec, pub = tmp_path / "f.key", tmp_path / "f.pub"
    ms.write_seckey(str(sec), foreign_id, seed + pk)
    ms.write_pubkey(str(pub), foreign_id, pk)

    parsed_seed, parsed_id = rr.parse_ed25519_key(sec.read_bytes())
    assert (parsed_seed, parsed_id) == (seed, foreign_id)

    # A signature tagged with the stored id verifies against the original
    # public key; one tagged with the derived id would not.
    digest = hashlib.blake2b(b"rootfs-bytes", digest_size=64).digest()
    sig = ms.ed25519_sign(seed, digest)
    assert ms.ed25519_verify(pk, digest, sig)


def test_parse_ed25519_key_refusals():
    dev_key = os.path.join(secure_boot_tools.find_dir(), "dev-keys-rootfs", "dev.key")
    with open(dev_key, "rb") as f:
        with pytest.raises(rr.ResignError, match="1 GiB"):
            rr.parse_ed25519_key(f.read())       # passphrase-protected
    with pytest.raises(rr.ResignError, match="not an Ed25519"):
        rr.parse_ed25519_key(b"short")


def test_find_key_files_skips_images_and_big_files(tmp_path):
    (tmp_path / "rsa.pem").write_bytes(b"x" * 100)
    (tmp_path / "boot.img").write_bytes(b"x" * 100)
    (tmp_path / "sd_update.txt").write_bytes(b"x")
    (tmp_path / "huge.bin2").write_bytes(b"x" * (rr.KEY_FILE_MAX_BYTES + 1))
    (tmp_path / "empty.key").write_bytes(b"")
    (tmp_path / ".hidden").write_bytes(b"x")
    (tmp_path / "keys").mkdir()
    (tmp_path / "keys" / "ed.key").write_bytes(b"x")
    (tmp_path / "keys" / "deep").mkdir()
    (tmp_path / "keys" / "deep" / "too-deep.key").write_bytes(b"x")
    found = [os.path.relpath(p, str(tmp_path)) for p in rr.find_key_files(str(tmp_path))]
    assert found == ["rsa.pem", os.path.join("keys", "ed.key")]


def test_seedkeeper_secret_bytes():
    data = b"payload-bytes"
    assert rr.seedkeeper_secret_bytes(list(bytes([len(data)]) + data), 1) == data
    assert rr.seedkeeper_secret_bytes(list(len(data).to_bytes(2, "big") + data), 2) == data
    long = b"k" * 300                                 # too long for a 1-byte prefix
    assert rr.seedkeeper_secret_bytes(list(len(long).to_bytes(2, "big") + long), 2) == long


# --- Sign Digest (air-gap: no bundle on the device) ------------------------------

def _digest_dir(tmp_path):
    d = tmp_path / rr.DIGEST_DIR
    d.mkdir(parents=True)
    return d


def test_sign_digests_roundtrip_all_tiers(tmp_path, new_key):
    n, d = int(new_key.n), int(new_key.d)
    digests = _digest_dir(tmp_path)

    ldr = _rk_container(n)                            # tier A: a real loader digest
    (digests / "download.digest").write_bytes(rk.signing_digest(ldr, rk.layout(ldr)))
    fit = _fit(b"BOOT" * 64)                          # tier B: a real FIT digest
    (digests / "boot.digest").write_bytes(fs.signed_digest(fit))
    rootfs_bytes = b"ROOTFS" * 1000                   # tier C: a prehash of some bytes
    (digests / "rootfs.digest").write_bytes(hashlib.blake2b(rootfs_bytes, digest_size=64).digest())

    report = rr.sign_digests(str(tmp_path), new_key, ED_SEED)
    assert report.ok
    # the public halves come back on the card too (see below); nothing else is written
    assert set(dict(report.signed)) == {
        "download.sig", "boot.sig", "rootfs.minisig",
        "release-rsa.pub", "release-rootfs.pub"}

    # tier A verifies little-endian against the loader digest
    sig = (digests / "download.sig").read_bytes()
    assert len(sig) == 256
    assert rk.rsa_verify_digest(rk.signing_digest(ldr, rk.layout(ldr)),
                                int.from_bytes(sig, "little"), n)

    # tier B verifies big-endian: splice it into a copy the way the PC does
    sig = (digests / "boot.sig").read_bytes()
    assert len(sig) == 256
    fit2 = bytearray(fit)
    fs._write_value(fit2, fs.signature_node(fit2), sig)
    assert fs.verify_buf(fit2, n)

    # tier C: minisign text with the derived key id; both signatures check out
    msig = ms.load_sig(str(digests / "rootfs.minisig"))
    pk = ms.ed25519_public(ED_SEED)
    digest = (digests / "rootfs.digest").read_bytes()
    assert msig["key_id"] == rr.ed25519_key_id(ED_SEED)
    assert ms.ed25519_verify(pk, digest, msig["sig"])
    assert ms.ed25519_verify(pk, msig["sig"] + msig["trusted_comment"].encode(),
                             msig["global_sig"])

    # the public halves come back on the card too, so the PC can verify from the
    # folder alone: same names/formats as Export Pubkeys
    from Cryptodome.PublicKey import RSA
    rsa_pub = RSA.import_key((digests / "release-rsa.pub").read_bytes())
    assert int(rsa_pub.n) == n
    rootfs_pub = lr.parse_pubkey_bytes((digests / "release-rootfs.pub").read_bytes())
    assert rootfs_pub["pk"] == pk and rootfs_pub["key_id"] == msig["key_id"]


def test_sign_digests_writes_only_the_keys_it_used(tmp_path, new_key):
    """Each public key is written only when its tier actually produced a signature."""
    def card(name):
        root = tmp_path / name
        d = _digest_dir(root)
        return root, d

    # tier C only -> only the Ed25519 half goes back on the card
    root, digests = card("c-rootfs")
    (digests / "rootfs.digest").write_bytes(b"\x22" * 64)
    rr.sign_digests(str(root), new_key, ED_SEED)
    assert (digests / "release-rootfs.pub").exists()
    assert not (digests / "release-rsa.pub").exists()

    # tier A only -> only the RSA half
    root, digests = card("c-ldr")
    (digests / "download.digest").write_bytes(b"\x11" * 32)
    rr.sign_digests(str(root), new_key, ED_SEED)
    assert (digests / "release-rsa.pub").exists()
    assert not (digests / "release-rootfs.pub").exists()

    # a digest that is refused does not count as signed: no key for it either
    root, digests = card("c-bad")
    (digests / "download.digest").write_bytes(b"\x11" * 64)     # wrong size -> skipped
    rr.sign_digests(str(root), new_key, ED_SEED)
    assert not (digests / "release-rsa.pub").exists()


def test_sign_digests_is_deterministic(tmp_path, new_key):
    digests = _digest_dir(tmp_path)
    (digests / "download.digest").write_bytes(b"\x11" * 32)
    (digests / "rootfs.digest").write_bytes(b"\x22" * 64)
    rr.sign_digests(str(tmp_path), new_key, ED_SEED)
    first = {(f.name): f.read_bytes() for f in digests.iterdir()}
    rr.sign_digests(str(tmp_path), new_key, ED_SEED)
    assert {(f.name): f.read_bytes() for f in digests.iterdir()} == first


def test_sign_digests_third_party_key_id_travels_with_the_signature(tmp_path, new_key):
    """A minisign -G key's stored id is not derivable from the seed; the .minisig
    must carry it, or host-side verification against the original pubkey fails."""
    foreign = b"\x01" * 8
    assert foreign != rr.ed25519_key_id(ED_SEED)
    digests = _digest_dir(tmp_path)
    (digests / "rootfs.digest").write_bytes(b"\x33" * 64)
    report = rr.sign_digests(str(tmp_path), new_key, ED_SEED, stored_key_id=foreign)
    assert report.ok
    msig = ms.load_sig(str(digests / "rootfs.minisig"))
    assert msig["key_id"] == foreign


def test_sign_digests_refuses_wrong_sized_files(tmp_path, new_key):
    digests = _digest_dir(tmp_path)
    (digests / "download.digest").write_bytes(b"\x11" * 64)     # tier A wants 32
    (digests / "rootfs.digest").write_bytes(b"\x22" * 32)       # tier C wants 64
    report = rr.sign_digests(str(tmp_path), new_key, ED_SEED)
    assert not report.ok
    skipped = dict(report.skipped)
    assert "64 bytes" in skipped["download.digest"] and "must be 32" in skipped["download.digest"]
    assert "32 bytes" in skipped["rootfs.digest"] and "must be 64" in skipped["rootfs.digest"]
    assert not (digests / "download.sig").exists()
    assert not (digests / "rootfs.minisig").exists()


def test_sign_digests_missing_keys_are_refused_upfront(tmp_path):
    digests = _digest_dir(tmp_path)
    (digests / "download.digest").write_bytes(b"\x11" * 32)
    with pytest.raises(rr.ResignError, match="no RSA key"):
        rr.sign_digests(str(tmp_path))
    (digests / "download.digest").unlink()
    (digests / "rootfs.digest").write_bytes(b"\x22" * 64)
    with pytest.raises(rr.ResignError, match="no Ed25519 key"):
        rr.sign_digests(str(tmp_path))


def test_sign_digests_refuses_a_card_without_the_folder(tmp_path, new_key):
    (tmp_path / "other").mkdir()
    with pytest.raises(rr.ResignError, match="airgap-sign.py digests"):
        rr.sign_digests(str(tmp_path), new_key, ED_SEED)


def test_sign_digests_ignores_unrecognised_files(tmp_path, new_key):
    digests = _digest_dir(tmp_path)
    (digests / "manifest.txt").write_text("not a digest")
    (digests / "unknown.digest").write_bytes(b"\x11" * 32)
    with pytest.raises(rr.ResignError, match="no .digest files"):
        rr.sign_digests(str(tmp_path), new_key, ED_SEED)
