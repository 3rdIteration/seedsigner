"""Re-sign a Luckfox SeedSigner OS release folder with BIP85-derived keys.

The device-side half of the air-gapped signing ceremony described in
seedsigner-os `docs/luckfox/airgapped-signing.md`. A release built by CI is
signed with a *published* dev key, so it verifies but is not protected. This
re-signs it with keys derived from the user's own seed, so only they can produce
an image the device will accept.

Neither private key is ever written to storage: the RSA key arrives as a
PyCryptodome object and the Ed25519 key as 32 raw bytes, and both are passed
straight into the signers' in-memory entry points.

WHAT GETS RE-SIGNED, and in what order (the order matters):

  1. `idblock.img` / `download.bin`  - the RSA public key is re-embedded, then
     the 0x600 header is re-signed. The OLD modulus is read out of idblock.img
     first, because step 2 needs it to find the key inside an opaque payload.
  2. `uboot.img` - carries the pubkey U-Boot uses to verify boot.img, inside its
     uncompressed `fdt` payload. Swap the key, recompute that payload's hash,
     then re-sign the FIT.
  3. `boot.img` - embeds no key; re-sign only.
  4. `rootfs.img` / `rootfs.ubifs` - Ed25519/minisign over exactly the first
     `<image>.size` bytes.

KNOWN LIMIT, surfaced to the user rather than hidden. The rootfs public key is
baked into the initramfs inside `boot.img`, and this tool does not rewrite it.
So re-signing the rootfs with a *different* Ed25519 key produces an image the
device will reject at boot. `inspect_release()` detects this by looking for the
public key inside boot.img's gzipped ramdisk, and the caller is expected to warn.
Until the rootfs signature is detached from the initramfs upstream, a rootfs key
change needs a rebuild, not a re-sign.
"""
import gzip
import hashlib
import io
import os

from seedsigner.helpers.luckfox_secure_boot import rkloader as rk
from seedsigner.helpers.luckfox_secure_boot import fitsign as fs
from seedsigner.helpers.luckfox_secure_boot import minisign as ms


# Files this tool knows how to handle, in the order they must be processed.
LOADER_FILES = ("idblock.img", "download.bin")
FIT_KEYED = "uboot.img"
FIT_PLAIN = "boot.img"
ROOTFS_CANDIDATES = ("rootfs.img", "rootfs.ubifs")

# Anything a release folder must contain for this to be worth offering.
REQUIRED_ANY = LOADER_FILES + (FIT_KEYED, FIT_PLAIN)


class ResignError(Exception):
    pass


class ResignReport:
    """What happened, for the result screen."""

    def __init__(self):
        self.signed = []        # [(filename, detail)]
        self.skipped = []       # [(filename, reason)]
        self.warnings = []      # [str]

    def add(self, name, detail):
        self.signed.append((name, detail))

    def skip(self, name, reason):
        self.skipped.append((name, reason))

    def warn(self, text):
        self.warnings.append(text)

    @property
    def ok(self):
        return bool(self.signed)


# --- discovery --------------------------------------------------------------

def find_release_dirs(root):
    """Directories under `root` that look like a flashable release folder."""
    out = []
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return out
    for name in entries:
        if name.startswith(".") or name == "__MACOSX":
            continue
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        if looks_like_release(path):
            out.append(path)
    # allow the card root itself to be a release folder
    if looks_like_release(root):
        out.insert(0, root)
    return out


def looks_like_release(path):
    try:
        names = set(os.listdir(path))
    except OSError:
        return False
    return any(f in names for f in REQUIRED_ANY)


def _rootfs_in(folder):
    for name in ROOTFS_CANDIDATES:
        img = os.path.join(folder, name)
        if os.path.isfile(img) and os.path.isfile(img + ".size"):
            return img
    return None


def _ramdisk_pubkey(boot_img):
    """The rootfs minisign pubkey baked into boot.img's initramfs, or None.

    The ramdisk is a gzipped cpio inside the FIT. We do not need to parse the
    cpio: the public key is a short base64 line, so finding the minisign public
    key header in the decompressed archive is enough to read it back.
    """
    try:
        buf = rk.read(boot_img)
        payloads = fs._image_payloads(buf)
    except Exception:
        return None
    if "ramdisk" not in payloads:
        return None
    pos, size, _ = payloads["ramdisk"]
    try:
        raw = gzip.GzipFile(fileobj=io.BytesIO(bytes(buf[pos:pos + size]))).read()
    except Exception:
        return None
    # The marker also appears as a printf format string inside the minisign
    # binary that shares the archive, so every candidate is validated by
    # actually decoding the key that follows it.
    marker = b"untrusted comment: minisign public key"
    at = raw.find(marker)
    while at >= 0:
        nl = raw.find(b"\n", at)
        end = raw.find(b"\n", nl + 1) if nl >= 0 else -1
        if nl >= 0 and end >= 0:
            block = raw[at:end + 1]
            try:
                import base64
                body = base64.b64decode(raw[nl + 1:end], validate=True)
                if len(body) == 42 and body[:2] == ms.ALG_PURE:
                    return block
            except Exception:
                pass
        at = raw.find(marker, at + 1)
    return None


def inspect_release(folder):
    """Describe a release folder without modifying it."""
    info = {
        "folder": folder,
        "files": [],
        "rootfs": None,
        "current_rsa_modulus": None,
        "ramdisk_rootfs_pubkey": None,
    }
    for name in REQUIRED_ANY:
        if os.path.isfile(os.path.join(folder, name)):
            info["files"].append(name)
    info["rootfs"] = _rootfs_in(folder)

    idb = os.path.join(folder, "idblock.img")
    if os.path.isfile(idb):
        try:
            buf = rk.read(idb)
            info["current_rsa_modulus"] = rk.read_modulus(buf, rk.layout(buf))
        except Exception:
            pass

    boot = os.path.join(folder, FIT_PLAIN)
    if os.path.isfile(boot):
        info["ramdisk_rootfs_pubkey"] = _ramdisk_pubkey(boot)
    return info


# --- key material -----------------------------------------------------------

def rsa_numbers(rsa_key):
    """PyCryptodome RSA object -> (n, d), validated for this boot chain."""
    n, d = int(rsa_key.n), int(rsa_key.d)
    if n.bit_length() != 2048:
        raise ResignError(
            "the Rockchip chain is RSA-2048 only; this key is %d-bit. The SPL "
            "verifier rejects anything else before the BootROM is reached."
            % n.bit_length())
    if int(rsa_key.e) != 65537:
        raise ResignError("public exponent must be 65537 (F4), got %d" % int(rsa_key.e))
    return n, d


def rsa_modulus_fingerprint(n):
    return hashlib.sha256(n.to_bytes(256, "big")).hexdigest()


def ed25519_key_id(seed):
    """Same derivation minisign.py keygen uses, so the two always agree."""
    return hashlib.blake2b(ms.ed25519_public(seed), digest_size=8).digest()


# --- the ceremony -----------------------------------------------------------

def resign_release(folder, rsa_key, ed25519_seed, progress=None):
    """Re-sign every signable artifact in `folder`. Returns a ResignReport.

    `rsa_key` is a PyCryptodome RSA object (from bip85_rsa_from_root);
    `ed25519_seed` is 32 raw bytes (from the BIP85 Ed25519 path). Pass
    `progress` a callable to receive one short status line per step.
    """
    def step(msg):
        if progress:
            progress(msg)

    info = inspect_release(folder)
    if not info["files"] and not info["rootfs"]:
        raise ResignError("no signable images found in %s" % folder)

    report = ResignReport()
    n, d = rsa_numbers(rsa_key)

    # The old modulus has to be captured BEFORE anything is re-keyed: uboot.img
    # can only be re-keyed by searching for the key it currently embeds.
    old_n = info["current_rsa_modulus"]

    # 1. loader tier
    for name in LOADER_FILES:
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            report.skip(name, "not present")
            continue
        step("Signing %s" % name)
        buf = rk.read(path)
        lay = rk.layout(buf)
        if old_n is None:
            old_n = rk.read_modulus(buf, lay)
        rk.set_pubkey(buf, lay, n)
        rk.sign_buf(buf, lay, n, d)
        rk.write_out(buf, path, None)
        report.add(name, "key re-embedded, header re-signed")

    # 2. uboot.img - re-key the embedded pubkey, refresh the payload hash, sign
    path = os.path.join(folder, FIT_KEYED)
    if os.path.isfile(path):
        step("Signing %s" % FIT_KEYED)
        buf = rk.read(path)
        hits = 0
        if old_n is not None and old_n != n:
            hits = fs.set_pubkey(buf, n, old_n)
            if not hits:
                report.warn(
                    "%s did not contain the old public key, so the key U-Boot uses "
                    "to verify boot.img was NOT updated. boot.img will be rejected "
                    "at runtime." % FIT_KEYED)
            fs.rehash_buf(buf)
        fs.sign_buf(buf, n, d)
        fs.write_out(buf, path, None)
        report.add(FIT_KEYED,
                   "key re-embedded (%d), re-signed" % hits if hits else "re-signed")
    else:
        report.skip(FIT_KEYED, "not present")

    # 3. boot.img - no embedded key
    path = os.path.join(folder, FIT_PLAIN)
    if os.path.isfile(path):
        step("Signing %s" % FIT_PLAIN)
        buf = rk.read(path)
        fs.sign_buf(buf, n, d)
        fs.write_out(buf, path, None)
        report.add(FIT_PLAIN, "re-signed")
    else:
        report.skip(FIT_PLAIN, "not present")

    # 4. rootfs - Ed25519 over exactly the signed prefix
    rootfs = info["rootfs"]
    if rootfs:
        step("Hashing rootfs")
        with open(rootfs + ".size") as f:
            size = int(f.read().strip())
        digest = ms.prehash(rootfs, size)
        step("Signing rootfs")
        key_id = ed25519_key_id(ed25519_seed)
        sig = ms.ed25519_sign(ed25519_seed, digest)
        gsig = ms.ed25519_sign(ed25519_seed, sig + ms.TRUSTED_COMMENT.encode())
        ms.write_sig(rootfs + ".minisig", ms.ALG_PREHASHED, key_id, sig,
                     ms.TRUSTED_COMMENT, gsig)
        report.add(os.path.basename(rootfs), "%d bytes signed" % size)

        embedded = info["ramdisk_rootfs_pubkey"]
        if embedded is not None:
            ours = ("untrusted comment: minisign public key %s"
                    % key_id[::-1].hex().upper()).encode()
            if not embedded.startswith(ours):
                report.warn(
                    "boot.img's verifier embeds a DIFFERENT rootfs public key, so "
                    "the device will REJECT this rootfs. The embedded key can only "
                    "be changed by rebuilding the image with it.")
    else:
        report.skip("rootfs", "no rootfs image + .size pair found")

    return report


def verify_release(folder, rsa_pubkey_n, ed25519_seed=None):
    """Re-check everything just written. Returns [(name, ok, detail)]."""
    results = []
    for name in LOADER_FILES:
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            continue
        buf = rk.read(path)
        lay = rk.layout(buf)
        sig_ok = rk.rsa_verify_digest(rk.msg_digest(buf, lay), rk.read_sig(buf, lay),
                                      rsa_pubkey_n)
        # The signature only covers the 0x600 header. The SPL and its DTB hang
        # off sha256 entries inside that header, so a stale component hash is a
        # perfectly signed image the SPL refuses to boot - check both.
        comp_ok = rk.components_ok(buf, lay)
        results.append((name, sig_ok and comp_ok,
                        "RSA-PSS header signature + components"
                        if comp_ok else "STALE COMPONENT HASH"))
    for name in (FIT_KEYED, FIT_PLAIN):
        path = os.path.join(folder, name)
        if not os.path.isfile(path):
            continue
        ok = fs.verify_buf(rk.read(path), rsa_pubkey_n)
        results.append((name, ok, "FIT signature"))
    rootfs = _rootfs_in(folder)
    if rootfs and ed25519_seed is not None:
        with open(rootfs + ".size") as f:
            size = int(f.read().strip())
        sig = ms.load_sig(rootfs + ".minisig")
        pk = ms.ed25519_public(ed25519_seed)
        ok = ms.ed25519_verify(pk, ms.prehash(rootfs, size), sig["sig"])
        results.append((os.path.basename(rootfs), ok, "minisign Ed25519"))
    return results
