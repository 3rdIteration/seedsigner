"""The device-side Luckfox build tools: check, re-sign, export keys, provision a
MicroSD update, force the rootfs check, and arm the eFuse burn.

The air-gapped signing ceremony is described in seedsigner-os
`docs/luckfox/airgapped-signing.md`. A release built by CI is signed with
*published* dev keys, so it verifies but is not protected. Re-signing it with
keys derived from the user's own seed means only they can produce an image the
device will accept.

Neither private key is ever written to storage: the RSA key arrives as a
PyCryptodome object and the Ed25519 key as 32 raw bytes, and both go straight
into the signers' in-memory entry points.

WHERE EACH SIGNATURE LIVES, which decides what a re-sign rewrites:

  1. `idblock.img` / `download.bin` - RSA key embedded + header signature.
  2. `uboot.img` - embeds the RSA key U-Boot checks boot.img with; FIT-signed.
  3. `boot.img` - FIT-signed. Its ramdisk is the rootfs verifier, which holds
     the rootfs signature, the Ed25519 key that checks it, and the pass-screen
     key classes. So re-signing the rootfs rewrites boot.img, and rootfs.img
     itself is only read.

Everything is prepared in memory and written only once all of it succeeded, so a
refusal (say, a rootfs that does not verify) leaves the folder untouched.

The signers (and `luckfox_release`, which knows how a release fits together)
come from SeedSigner OS; see `secure_boot_tools`.
"""
import hashlib
import os
import shutil

from seedsigner.helpers.secure_boot_tools import (SecureBootToolsUnavailable,  # noqa: F401
                                                  is_available, load)

_mods = None


def _tools():
    """(rkloader, fitsign, minisign, luckfox_release), imported on first use."""
    global _mods
    if _mods is None:
        _mods = load()
    return _mods


LOADER_FILES = ("idblock.img", "download.bin")
FIT_KEYED = "uboot.img"
FIT_PLAIN = "boot.img"
ROOTFS_CANDIDATES = ("rootfs.img", "rootfs.ubifs")
UPDATE_IMG = "update.img"
UPDATE_SCRIPTS = ("sd_update.txt", "tftp_update.txt")

# Anything a release folder must contain for this to be worth offering.
REQUIRED_ANY = LOADER_FILES + (FIT_KEYED, FIT_PLAIN)

# Export Pubkeys writes here, at the card root.
KEYS_DIR = "seedsigner-release-keys"


class ResignError(Exception):
    pass


class ResignReport:
    """What happened, for the result screens."""

    def __init__(self):
        self.signed = []        # [(filename, detail)]
        self.skipped = []       # [(filename, reason)]
        self.warnings = []      # [str]
        self.deleted_update_img = False

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
        if name.startswith(".") or name == "__MACOSX" or name == KEYS_DIR:
            continue
        path = os.path.join(root, name)
        if os.path.isdir(path) and looks_like_release(path):
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


def _sidecar_rootfs(folder):
    """A rootfs with a .size sidecar: builds whose boot.img has no verifier."""
    for name in ROOTFS_CANDIDATES:
        img = os.path.join(folder, name)
        if os.path.isfile(img) and os.path.isfile(img + ".size"):
            return img
    return None


def _has_verifier(boot_buf):
    return "ramdisk" in _tools()[1]._image_payloads(boot_buf)


def inspect_release(folder):
    """Describe a release folder without modifying it."""
    rk, fs, _ms, lr = _tools()
    info = {
        "folder": folder,
        "files": [n for n in REQUIRED_ANY if os.path.isfile(os.path.join(folder, n))],
        "rootfs": None,
        "rootfs_in_boot": False,
        "current_rsa_modulus": None,
        "update_img": os.path.isfile(os.path.join(folder, UPDATE_IMG)),
    }
    idb = os.path.join(folder, "idblock.img")
    if os.path.isfile(idb):
        try:
            buf = rk.read(idb)
            info["current_rsa_modulus"] = rk.read_modulus(buf, rk.layout(buf))
        except Exception:
            pass
    boot = os.path.join(folder, FIT_PLAIN)
    try:
        info["rootfs_in_boot"] = os.path.isfile(boot) and _has_verifier(rk.read(boot))
    except Exception:
        pass
    if info["rootfs_in_boot"] and lr.rootfs_kind(folder):
        info["rootfs"] = os.path.join(folder, "rootfs.img")
    else:
        info["rootfs"] = _sidecar_rootfs(folder)
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
    """sha256 of the big-endian modulus - what `rkloader.py inspect` prints."""
    return hashlib.sha256(n.to_bytes(256, "big")).hexdigest()


def ed25519_key_id(seed):
    """Same derivation minisign.py keygen uses, so the two always agree."""
    return _tools()[2].key_id_for(_tools()[2].ed25519_public(seed))


def ed25519_key_id_text(seed):
    return _tools()[2].format_key_id(ed25519_key_id(seed))


# --- keys loaded from a file or a SeedKeeper secret ------------------------------
#
# The alternative to deriving the keys: bring your own. Both kinds are parsed from
# bytes, so a MicroSD file and a SeedKeeper secret go through the same code.

# Files larger than this are not keys, and are not offered in the picker.
KEY_FILE_MAX_BYTES = 16 * 1024
_NOT_KEYS = (".img", ".bin", ".gz", ".tar", ".zip", ".png", ".jpg")
_NOT_KEY_NAMES = ("sd_update.txt", "tftp_update.txt", "README.txt")


def parse_rsa_key(data):
    """A PEM/DER RSA private key -> PyCryptodome RSA key (2048-bit, e=65537)."""
    from Cryptodome.PublicKey import RSA
    if b"ENCRYPTED" in data:
        raise ResignError("the RSA key is passphrase-protected; export it unencrypted "
                          "(e.g. openssl rsa -in key.pem -out plain.pem)")
    try:
        key = RSA.import_key(data)
    except (ValueError, IndexError, TypeError):
        raise ResignError("not an RSA private key (expected PEM or DER)")
    if not key.has_private():
        raise ResignError("that is an RSA PUBLIC key; the private key is needed to sign")
    rsa_numbers(key)                             # 2048-bit, e = 65537
    return key


def parse_ed25519_key(data):
    """An Ed25519 private key -> its 32-byte seed.

    Accepts a minisign secret key (unencrypted), a PKCS#8 PEM/DER Ed25519 key
    (`openssl genpkey -algorithm ed25519`), or the bare seed as 32 raw bytes or
    64 hex characters.
    """
    ms = _tools()[2]
    text = data.strip()
    if text.startswith(b"untrusted comment:"):
        if ms.is_encrypted_seckey(data):
            raise ResignError(
                "this minisign key is passphrase-protected. Unlocking it needs about "
                "1 GiB of RAM (minisign's scrypt default), more than this device has. "
                "Re-create it unencrypted (minisign -G -W) or use a derived key.")
        try:
            return ms.parse_seckey(data)["seed"]
        except ms.MsError as e:
            raise ResignError("not a usable minisign secret key: %s" % e)
    # A bare seed first: 64 hex characters can start with "0", which is the same
    # byte as a DER SEQUENCE tag.
    try:
        seed = bytes.fromhex(text.decode("ascii")) if len(text) == 64 else b""
    except (UnicodeDecodeError, ValueError):
        seed = b""
    if len(seed) == 32:
        return seed
    if len(data) == 32:
        return bytes(data)
    if b"PRIVATE KEY" in text or text[:1] == b"\x30":
        if b"ENCRYPTED" in text:
            raise ResignError("the Ed25519 key is passphrase-protected; export it unencrypted")
        from Cryptodome.PublicKey import ECC
        try:
            key = ECC.import_key(data)
        except (ValueError, IndexError, TypeError):
            key = None
        if key is None or key.curve not in ("Ed25519", "ed25519") or not key.has_private():
            raise ResignError("not an Ed25519 private key")
        return bytes(key.seed)
    raise ResignError("not an Ed25519 key (minisign secret key, PKCS#8, or a "
                      "32-byte seed)")


def find_key_files(card_root, max_depth=2):
    """Small files that could hold a key: the card root and `max_depth` - 1
    levels of folders below it, as paths (card root first)."""
    out = []
    root_depth = card_root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(card_root):
        dirnames[:] = sorted(d for d in dirnames
                             if not d.startswith(".") and d != "__MACOSX")
        if dirpath.rstrip(os.sep).count(os.sep) - root_depth >= max_depth - 1:
            dirnames[:] = []
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if name.startswith(".") or name in _NOT_KEY_NAMES \
                    or name.lower().endswith(_NOT_KEYS):
                continue
            try:
                if 0 < os.path.getsize(path) <= KEY_FILE_MAX_BYTES:
                    out.append(path)
            except OSError:
                pass
    return out


def load_key_file(path, kind):
    """Read and parse a key file. `kind` is "rsa" or "ed25519"."""
    with open(path, "rb") as f:
        data = f.read(KEY_FILE_MAX_BYTES + 1)
    if len(data) > KEY_FILE_MAX_BYTES:
        raise ResignError("%s is too large to be a key" % os.path.basename(path))
    return parse_rsa_key(data) if kind == "rsa" else parse_ed25519_key(data)


def seedkeeper_secret_bytes(secret_list, protocol_minor_version):
    """The payload of an exported SeedKeeper secret, without its length prefix.

    SeedKeeper v1 prefixes one length byte, later versions two (the same rule the
    GPG key views use). Anything whose prefix does not match is returned whole.
    """
    raw = bytes(secret_list)
    if protocol_minor_version == 1 and raw and raw[0] == len(raw) - 1:
        return raw[1:]
    if len(raw) >= 2:
        n = (raw[0] << 8) | raw[1]
        if n == len(raw) - 2 or (protocol_minor_version != 1 and 0 < n <= len(raw) - 2):
            return raw[2:2 + n]
    if raw and 0 < raw[0] <= len(raw) - 1:
        return raw[1:1 + raw[0]]
    return raw


def release_modulus(folder):
    """The RSA modulus the release's boot chain embeds (from idblock.img)."""
    n = inspect_release(folder)["current_rsa_modulus"]
    if n is None:
        raise ResignError("no readable idblock.img in this folder")
    return n


# --- shared finishing steps ---------------------------------------------------

def _write(path, buf):
    with open(path, "wb") as f:
        f.write(bytes(buf))


def _fix_update_scripts(folder, report):
    """Correct short write lengths; surface anything that cannot be fixed."""
    lr = _tools()[3]
    profile = lr.identify(folder).get("profile")
    for script in UPDATE_SCRIPTS:
        res = lr.sd_update_check(folder, profile, fix=True, script=script)
        if res["fixed"]:
            report.add(script, "write lengths corrected for %s" % ", ".join(res["fixed"]))
        for p in res["problems"]:
            report.warn("%s: %s" % (script, p))


def _delete_update_img(folder, report):
    """update.img packs a copy of the old chain; a re-sign leaves it stale."""
    path = os.path.join(folder, UPDATE_IMG)
    if os.path.isfile(path):
        os.remove(path)
        report.deleted_update_img = True


# --- 1. check ---------------------------------------------------------------

def check_release(folder):
    """The OS library's full report (signatures, keys, hardware, pitfalls)."""
    return _tools()[3].check_release(folder)


def report_pages(rep):
    """A check report as a few short screens of text."""
    i = rep.identity
    console = {True: "on", False: "off"}.get(i.get("serial_console"), "?")
    pages = [("Hardware",
              "%s\nMedium: %s\nRootfs: %s\nSerial console: %s\nDDR blob: %s" % (
                  i.get("model") or "unknown", i.get("medium") or "?",
                  i.get("rootfs") or "?", console, i.get("ddr") or "?"))]

    lines = []
    for name, ok, detail in rep.items:
        lines.append("%s: %s" % (name, "OK" if ok else "FAIL - " + detail))
    pages.append(("Signatures", "\n".join(lines) or "nothing to check"))

    keys = []
    if rep.boot_key:
        keys.append("Boot key:\n%s%s" % (
            rep.boot_key["fingerprint"][:16],
            "\nPUBLISHED DEV KEY" if rep.boot_key["dev"] else ""))
    if rep.rootfs_key:
        keys.append("Rootfs key:\n%s%s" % (
            rep.rootfs_key["key_id"],
            "\nPUBLISHED DEV KEY" if rep.rootfs_key["dev"] else ""))
    keys.append("Forced rootfs check: %s" % {
        True: "on", False: "off", None: "not supported"}[rep.force_rootfs])
    keys.append("eFuse burn armed: %s" % ("YES" if rep.armed else "no"))
    pages.append(("Keys", "\n\n".join(keys)))

    if rep.warnings:
        pages.append(("Warnings", "\n\n".join(rep.warnings)))
    return pages


# --- 2. export pubkeys ------------------------------------------------------

def export_pubkeys(card_root, rsa_key, ed25519_seed, rsa_index, ed_index):
    """Write the public halves of the release keys to <card>/seedsigner-release-keys/.

    For checking releases on a host: `rkloader.py inspect` / `fitsign.py verify`
    take the PEM, `minisign -V` takes the .pub. Returns the directory written.
    """
    _rk, _fs, ms, _lr = _tools()
    n, _d = rsa_numbers(rsa_key)
    out = os.path.join(card_root, KEYS_DIR)
    os.makedirs(out, exist_ok=True)

    pem = rsa_key.publickey().export_key(format="PEM")
    _write(os.path.join(out, "release-rsa.pub"), pem + b"\n")

    pk = ms.ed25519_public(ed25519_seed)
    key_id = ms.key_id_for(pk)
    _write(os.path.join(out, "release-rootfs.pub"), ms.format_pubkey(key_id, pk))

    readme = (
        "SeedSigner OS release signing keys (PUBLIC halves only)\n"
        "\n"
        "Boot chain (RSA-2048, BIP85 RSA index %d)\n"
        "  file:        release-rsa.pub\n"
        "  fingerprint: %s\n"
        "               (sha256 of the modulus, as `rkloader.py inspect` prints it)\n"
        "\n"
        "Rootfs (Ed25519 / minisign, BIP85 Ed25519 index %d)\n"
        "  file:        release-rootfs.pub\n"
        "  key id:      %s\n"
        "\n"
        "Check a release folder on a host with the seedsigner-os tools\n"
        "(opt/luckfox/secure-boot):\n"
        "  python3 luckfox_release.py check <folder>\n"
        "  python3 fitsign.py verify <folder>/boot.img --pubkey release-rsa.pub\n"
        "  python3 rkloader.py inspect <folder>/idblock.img\n"
        "\n"
        "The seed and both indexes re-derive these keys. Without them you cannot\n"
        "sign an update for a device whose secure-boot fuse is burned.\n"
        % (rsa_index, rsa_modulus_fingerprint(n), ed_index, ms.format_key_id(key_id)))
    _write(os.path.join(out, "README.txt"), readme.encode())
    return out


# --- 3. resign all -----------------------------------------------------------

def resign_release(folder, rsa_key, ed25519_seed, progress=None):
    """Re-sign the boot chain and the rootfs. Returns a ResignReport.

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

    rk, fs, ms, lr = _tools()
    report = ResignReport()
    n, d = rsa_numbers(rsa_key)
    pending = []                                  # [(path, bytes)] written at the end

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
        pending.append((path, buf))
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
        pending.append((path, buf))
        report.add(FIT_KEYED,
                   "key re-embedded (%d), re-signed" % hits if hits else "re-signed")
    else:
        report.skip(FIT_KEYED, "not present")

    # 3. boot.img, with the rootfs signature inside it
    path = os.path.join(folder, FIT_PLAIN)
    if os.path.isfile(path):
        buf = rk.read(path)
        if _has_verifier(buf):
            seed = None
            if lr.rootfs_kind(folder):
                step("Verifying rootfs")
                seed = ed25519_seed
            else:
                report.skip("rootfs.img", "not in this folder, so its key was not changed")
            try:
                buf, done = lr.rework_initramfs(buf, folder, rootfs_seed=seed, rsa_n=n)
            except lr.ReleaseError as e:
                raise ResignError(str(e))
            if seed is not None:
                report.add("rootfs.img", "signed with key %s (the signature is "
                           "stored in boot.img)" % ed25519_key_id_text(seed))
        else:
            done = []
        step("Signing %s" % FIT_PLAIN)
        fs.sign_buf(buf, n, d)
        pending.append((path, buf))
        report.add(FIT_PLAIN, "re-signed" + ("" if not done else "; " + "; ".join(done)))
    else:
        report.skip(FIT_PLAIN, "not present")

    # 3b. builds without a verifier in boot.img keep a detached .minisig
    rootfs = _sidecar_rootfs(folder)
    if rootfs and not info["rootfs_in_boot"]:
        step("Signing rootfs")
        with open(rootfs + ".size") as f:
            size = int(f.read().strip())
        digest = ms.prehash(rootfs, size)
        key_id = ed25519_key_id(ed25519_seed)
        sig = ms.ed25519_sign(ed25519_seed, digest)
        gsig = ms.ed25519_sign(ed25519_seed, sig + ms.TRUSTED_COMMENT.encode())
        pending.append((rootfs + ".minisig", ms.format_sig(
            ms.ALG_PREHASHED, key_id, sig, ms.TRUSTED_COMMENT, gsig)))
        report.add(os.path.basename(rootfs), "%d bytes signed (.minisig)" % size)

    # Nothing above wrote anything; now it all goes out together.
    step("Writing")
    for p, data in pending:
        _write(p, data)
    _delete_update_img(folder, report)
    _fix_update_scripts(folder, report)
    return report


def verify_release(folder, rsa_pubkey_n, ed25519_seed=None):
    """Re-check a release under the given keys. Returns [(name, ok, detail)]."""
    rk, fs, ms, lr = _tools()
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

    boot = os.path.join(folder, FIT_PLAIN)
    if os.path.isfile(boot) and _has_verifier(rk.read(boot)) and lr.rootfs_kind(folder):
        members = lr.initramfs_members(rk.read(boot))
        ok, detail = lr.verify_rootfs(folder, members)
        if ok and ed25519_seed is not None:
            embedded = lr.parse_pubkey_bytes(members["pubkey"])["key_id"]
            if embedded != ed25519_key_id(ed25519_seed):
                ok, detail = False, "boot.img trusts a different rootfs key"
        results.append(("rootfs.img", ok, detail))
    else:
        rootfs = _sidecar_rootfs(folder)
        if rootfs and ed25519_seed is not None:
            with open(rootfs + ".size") as f:
                size = int(f.read().strip())
            sig = ms.load_sig(rootfs + ".minisig")
            pk = ms.ed25519_public(ed25519_seed)
            ok = ms.ed25519_verify(pk, ms.prehash(rootfs, size), sig["sig"])
            results.append((os.path.basename(rootfs), ok, "minisign Ed25519"))
    return results


# --- keys that must already match the release ----------------------------------

def require_release_key(folder, rsa_key):
    """Refuse unless this RSA key is the one the release is signed with.

    Force Rootfs Check and Arm eFuse Burn re-sign a single file; the rest of the
    chain (and uboot.img's embedded key) stays as it is, so the key has to match
    it. Resign Release is the way to change keys.
    """
    rk, fs, _ms, _lr = _tools()
    n, _d = rsa_numbers(rsa_key)
    if release_modulus(folder) != n:
        raise ResignError("this key is not the one the release is signed with "
                          "(RSA fingerprint %s). Use Resign Release to change keys."
                          % rsa_modulus_fingerprint(release_modulus(folder))[:16])
    boot = os.path.join(folder, FIT_PLAIN)
    if os.path.isfile(boot) and not fs.verify_buf(rk.read(boot), n):
        raise ResignError("boot.img is not validly signed with this key")
    return n


# --- 4. provision a MicroSD update ------------------------------------------

def update_script_images(folder):
    """The images sd_update.txt flashes, in order."""
    lr = _tools()[3]
    path = os.path.join(folder, "sd_update.txt")
    names = []
    with open(path, newline="") as f:
        for line in f:
            m = lr._STEP.search(line)
            if m and m.group(3) not in names:
                names.append(m.group(3))
    return names


def provision_check(folder, card_root):
    """Everything Provision MicroSD needs to decide, without writing anything.

    Returns a dict: `problems` refuse the copy; `warnings` need a confirmation;
    `fixable` are sd_update.txt write lengths that would be corrected first.
    """
    _rk, _fs, _ms, lr = _tools()
    out = dict(problems=[], warnings=[], fixable=[], files=[], bytes=0,
               identity=lr.identify(folder), overwrite=False, in_place=False)
    if not os.path.isfile(os.path.join(folder, "sd_update.txt")):
        out["problems"].append("This release has no sd_update.txt, so it cannot be "
                               "auto-flashed from MicroSD (eMMC releases never can). "
                               "Flash it over USB.")
        return out

    rep = lr.check_release(folder)
    for name, ok, detail in rep.items:
        if not ok:
            out["problems"].append("%s: %s" % (name, detail))
    if rep.boot_key and rep.boot_key["dev"] or rep.rootfs_key and rep.rootfs_key["dev"]:
        out["warnings"].append("Signed with the PUBLISHED dev keys: anyone could "
                               "have signed it.")
    if rep.armed:
        out["warnings"].append("idblock.img is ARMED: its first boot BURNS the "
                               "secure-boot fuse, irreversibly.")

    sd = lr.sd_update_check(folder, out["identity"].get("profile"))
    out["problems"].extend(sd["problems"])
    out["fixable"] = sd["fixable"]
    out["warnings"].extend(sd["notes"])

    out["files"] = ["sd_update.txt"] + update_script_images(folder)
    for name in out["files"]:
        p = os.path.join(folder, name)
        if not os.path.isfile(p):
            if "%s is listed but missing" % name not in out["problems"]:
                out["problems"].append("%s is listed but missing" % name)
        else:
            out["bytes"] += os.path.getsize(p)

    out["in_place"] = os.path.realpath(folder) == os.path.realpath(card_root)
    if not out["in_place"]:
        out["overwrite"] = os.path.exists(os.path.join(card_root, "sd_update.txt"))
        free = shutil.disk_usage(card_root).free
        if free < out["bytes"]:
            out["problems"].append("Not enough free space on the MicroSD: need %d MiB, "
                                   "%d MiB free." % (out["bytes"] >> 20, free >> 20))
    return out


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def provision_microsd(folder, card_root, progress=None):
    """Fix the write lengths, then copy sd_update.txt + its images to the card
    root and read every copy back. Returns the list of files placed."""
    lr = _tools()[3]
    lr.sd_update_check(folder, None, fix=True)
    files = ["sd_update.txt"] + update_script_images(folder)
    if os.path.realpath(folder) == os.path.realpath(card_root):
        return files
    for name in files:
        if progress:
            progress("Copying %s" % name)
        src, dst = os.path.join(folder, name), os.path.join(card_root, name)
        shutil.copyfile(src, dst)
        if _sha256(src) != _sha256(dst):
            raise ResignError("%s did not copy correctly - the card may be failing" % name)
    return files


# --- 5. force rootfs check -----------------------------------------------------

def force_rootfs_state(folder):
    """True / False, or None when this release's verifier cannot do it."""
    rk, _fs, _ms, lr = _tools()
    boot = os.path.join(folder, FIT_PLAIN)
    if not os.path.isfile(boot) or not _has_verifier(rk.read(boot)):
        return None
    members = lr.initramfs_members(rk.read(boot))
    if not lr.supports_force_marker(members):
        return None
    return lr.FORCE_MARKER in members


def set_force_rootfs(folder, rsa_key, on):
    """Turn the forced rootfs check on/off and re-sign boot.img. Returns a report."""
    rk, fs, _ms, lr = _tools()
    n = require_release_key(folder, rsa_key)
    _n, d = rsa_numbers(rsa_key)
    if force_rootfs_state(folder) is None:
        raise ResignError("this release's verifier does not support a forced rootfs check")
    path = os.path.join(folder, FIT_PLAIN)
    try:
        buf, done = lr.rework_initramfs(rk.read(path), force=on)
    except lr.ReleaseError as e:
        raise ResignError(str(e))
    report = ResignReport()
    if done:
        fs.sign_buf(buf, n, d)
        _write(path, buf)
        report.add(FIT_PLAIN, "; ".join(done) + "; re-signed")
        _delete_update_img(folder, report)
        _fix_update_scripts(folder, report)
    return report


# --- 6. arm the eFuse burn -------------------------------------------------------

def arm_burn_check(folder):
    """Reasons to refuse arming, or [] when the release is fit to be armed."""
    lr = _tools()[3]
    rep = lr.check_release(folder)
    reasons = ["%s: %s" % (name, detail) for name, ok, detail in rep.items if not ok]
    if not rep.boot_key:
        reasons.append("no boot key found")
    elif rep.boot_key["dev"]:
        reasons.append("the boot chain is signed with the PUBLISHED dev key. Burning "
                       "it would lock the board to a key anyone can sign with.")
    if rep.armed:
        reasons.append("idblock.img is already armed")
    return reasons


def arm_burn(folder, rsa_key):
    """Arm idblock.img to burn the key hash on its next boot, and re-sign it."""
    rk, _fs, _ms, _lr = _tools()
    reasons = arm_burn_check(folder)
    if reasons:
        raise ResignError("; ".join(reasons))
    n = require_release_key(folder, rsa_key)
    _n, d = rsa_numbers(rsa_key)
    path = os.path.join(folder, "idblock.img")
    buf = rk.read(path)
    lay = rk.layout(buf)
    rk.arm_burn(buf, lay)
    rk.sign_buf(buf, lay, n, d)
    if not rk.is_burn_armed(buf) or not rk.components_ok(buf, lay):
        raise ResignError("arming did not verify; nothing was written")
    _write(path, buf)
    report = ResignReport()
    report.add("idblock.img", "ARMED: burns the secure-boot fuse on its next boot")
    _delete_update_img(folder, report)
    _fix_update_scripts(folder, report)
    return report
