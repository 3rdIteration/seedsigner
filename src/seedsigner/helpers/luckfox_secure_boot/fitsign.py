#!/usr/bin/env python3
"""fitsign.py - sign/verify a U-Boot FIT image (uboot.img, boot.img) offline.

The FIT half of air-gapped signing, and the companion to rkloader.py, which
does the Rockchip loader/idblock half. Together they cover every RSA signature
in the boot chain, with no mkimage, no SDK and no vendor blob - so the private
key can live on an air-gapped machine, a SeedSigner over QR, or a token.

WHAT IS SIGNED. mkimage signs a set of byte regions of the FIT's flattened
device tree, not the whole file. The recipe is recorded in the signature node
itself, which is why a rebuild is not needed to re-derive it:

  * `hashed-nodes`   - NUL-separated node paths whose PROPERTIES are covered.
  * `hashed-strings` - (offset, size) into the strings block; only that prefix
                       is covered, so properties added after signing (value,
                       timestamp, ...) append new names harmlessly.

The regions are then, in file order:

  1. every node's FDT_BEGIN_NODE / FDT_END_NODE token - the whole tree
     structure, so adding or removing any node anywhere breaks the signature;
  2. the FDT_PROP tokens (name + data) of the nodes listed in `hashed-nodes`,
     and only those;
  3. the FDT_END token;
  4. the strings-block prefix named by `hashed-strings`.

The FDT header and the memory-reserve block are NOT covered, and neither are
the external payloads - those are bound in by the sha256 `hash` subnodes, which
are themselves covered. Verified by reconstructing the digest
and checking it against the shipped signature under the committed dev pubkey,
for both uboot.img and boot.img.

A consequence worth knowing: the signature node's own properties are excluded,
so `value` and the wall-clock `timestamp` mkimage writes there can both be
zeroed without invalidating anything. That is what `canonicalise` does, and it
is what makes a signed release comparable against a reproducible rebuild.

Padding is RSA-PSS with MGF1-SHA256 and the MAXIMUM salt length (222 bytes for
rsa2048), which is what mkimage emits. Note this differs from the Rockchip
loader tier, which uses saltLen 32. Verification recovers the salt length from
the block, so it accepts either.

Pure stdlib.

  digest       <img> [-o <f>]            the 32 bytes to sign
  sign         <img> --key <pem> [-o]    sign locally (key on this host)
  splice       <img> --sig <f> [-o]      write an externally-made signature back
  verify       <img> --pubkey <pem>      full offline verification
  rehash       <img> [-o <f>]            recompute payload `hash` nodes
  setkey       <img> --pubkey --old-pubkey [-o]   swap the embedded RSA key
  canonicalise <img> [-o <f>]            zero the key-dependent + timestamp bytes
  info         <img>                     what would be signed, and with what

A full offline key swap of the whole chain is therefore:

  rkloader.py setkey download.bin  --pubkey new.pub   &&  rkloader.py sign ... --key new.key
  rkloader.py setkey idblock.img   --pubkey new.pub   &&  rkloader.py sign ... --key new.key
  fitsign.py  setkey uboot.img --pubkey new.pub --old-pubkey old.pub
  fitsign.py  rehash uboot.img  &&  fitsign.py sign uboot.img --key new.key
  fitsign.py  sign   boot.img   --key new.key          # carries no key itself

Exit codes: 0 ok, 1 usage/IO, 2 verification failed, 3 parse error.
"""
import sys, os, struct, hashlib, argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rkloader import (RkError, load_pubkey, load_privkey, _mgf1,      # noqa: E402
                      pss_encode, pss_verify, read, write_out)

FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9
FDT_MAGIC = 0xd00dfeed
SIG_NODE = "/configurations/conf/signature"


class FitError(RkError):
    pass


# --- flattened device tree --------------------------------------------------

def fdt_header(buf):
    magic, totalsize, off_struct, off_strings, off_memrsv, version, \
        last_comp, boot_cpu, size_strings, size_struct = struct.unpack_from(">10I", buf, 0)
    if magic != FDT_MAGIC:
        raise FitError("no FDT magic at offset 0 - not a FIT image?")
    return dict(totalsize=totalsize, off_struct=off_struct, off_strings=off_strings,
                off_memrsv=off_memrsv, size_strings=size_strings, size_struct=size_struct)


def fdt_tokens(buf):
    """Yield (kind, path, name, start, end) for every token in the struct block.

    `start`/`end` are byte offsets into the FIT, which is what the region list
    is built from.
    """
    h = fdt_header(buf)
    p, end = h["off_struct"], h["off_struct"] + h["size_struct"]
    strings = bytes(buf[h["off_strings"]:h["off_strings"] + h["size_strings"]])
    path = []
    while p < end:
        start = p
        (tok,) = struct.unpack_from(">I", buf, p)
        p += 4
        if tok == FDT_BEGIN_NODE:
            e = bytes(buf).index(b"\x00", p)
            path.append(bytes(buf[p:e]).decode("latin1"))
            p = (e + 4) & ~3
            yield "begin", "/" + "/".join(x for x in path if x), path[-1], start, p
        elif tok == FDT_END_NODE:
            yield "end", "/" + "/".join(x for x in path if x), None, start, p
            if path:
                path.pop()
        elif tok == FDT_PROP:
            ln, noff = struct.unpack_from(">II", buf, p)
            dstart = p + 8
            p = (dstart + ln + 3) & ~3
            ne = strings.index(b"\x00", noff)
            yield ("prop", "/" + "/".join(x for x in path if x),
                   strings[noff:ne].decode("latin1"), start, p)
        elif tok == FDT_NOP:
            yield "nop", None, None, start, p
        elif tok == FDT_END:
            yield "fdtend", None, None, start, p
            return
        else:
            raise FitError("bad FDT token 0x%x at 0x%x" % (tok, start))


def fdt_props(buf):
    """{node_path: {prop_name: (value_bytes, value_offset)}}"""
    out = {}
    for kind, path, name, s, e in fdt_tokens(buf):
        if kind == "prop":
            ln, _ = struct.unpack_from(">II", buf, s + 4)
            out.setdefault(path, {})[name] = (bytes(buf[s + 12:s + 12 + ln]), s + 12)
    return out


# --- the signed regions -----------------------------------------------------

def signature_node(buf):
    props = fdt_props(buf)
    if SIG_NODE not in props:
        raise FitError("%s has no %s node - it is unsigned, and this tool re-signs "
                       "an already-signed FIT (mkimage builds the node)" % ("image", SIG_NODE))
    return props[SIG_NODE]


def signed_regions(buf):
    """The byte ranges mkimage hashes, in file order. See the module docstring."""
    h = fdt_header(buf)
    sig = signature_node(buf)
    for req in ("hashed-nodes", "hashed-strings"):
        if req not in sig:
            raise FitError("signature node has no '%s' - cannot re-derive what was signed" % req)
    hashed = set(x.decode("latin1") for x in sig["hashed-nodes"][0].split(b"\x00") if x)
    str_off, str_size = struct.unpack(">II", sig["hashed-strings"][0])

    regions = []
    for kind, path, name, s, e in fdt_tokens(buf):
        if kind in ("begin", "end"):
            regions.append((s, e))               # the whole tree structure
        elif kind == "prop" and path in hashed:
            regions.append((s, e))               # only listed nodes' properties
        elif kind == "fdtend":
            regions.append((s, e))
    regions.append((h["off_strings"] + str_off, h["off_strings"] + str_off + str_size))

    merged = []
    for a, b in regions:
        if merged and a <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    return [(a, b) for a, b in merged]


def signed_digest(buf):
    return hashlib.sha256(b"".join(bytes(buf[a:b]) for a, b in signed_regions(buf))).digest()


def max_salt_len(n):
    """What mkimage uses: the largest salt the modulus allows."""
    emlen = (n.bit_length() - 1 + 7) // 8
    return emlen - 32 - 2


# --- commands ---------------------------------------------------------------

def _algo_check(sig, image):
    algo = sig.get("algo", (b"", 0))[0].rstrip(b"\x00").decode("latin1")
    padding = sig.get("padding", (b"", 0))[0].rstrip(b"\x00").decode("latin1")
    if algo and algo != "sha256,rsa2048":
        raise FitError("%s uses %s; only sha256,rsa2048 is supported" % (image, algo))
    if padding and padding != "pss":
        raise FitError("%s uses %s padding; only pss is supported" % (image, padding))


def cmd_info(a):
    buf = read(a.image)
    sig = signature_node(buf)
    regions = signed_regions(buf)
    total = sum(b - a_ for a_, b in regions)
    print("== %s" % a.image)
    for k in ("algo", "padding", "key-name-hint", "signer-name", "signer-version", "sign-images"):
        if k in sig:
            print("   %-14s : %s" % (k, sig[k][0].rstrip(b"\x00").decode("latin1").replace("\x00", " ")))
    if "timestamp" in sig:
        ts = struct.unpack(">I", sig["timestamp"][0])[0]
        print("   %-14s : %d  (wall clock, OUTSIDE the signed region - normalise it "
              "for reproducibility)" % ("timestamp", ts))
    nodes = [x.decode("latin1") for x in sig["hashed-nodes"][0].split(b"\x00") if x]
    so, ss = struct.unpack(">II", sig["hashed-strings"][0])
    print("   hashed-nodes   : %d nodes" % len(nodes))
    for n in nodes:
        print("                    %s" % n)
    print("   hashed-strings : offset 0x%x, size 0x%x" % (so, ss))
    print("   regions        : %d, %d bytes total" % (len(regions), total))
    print("   signed digest  : %s" % signed_digest(buf).hex())
    print("   value          : %d bytes" % len(sig.get("value", (b"", 0))[0]))
    return 0


def cmd_digest(a):
    d = signed_digest(read(a.image))
    if a.out:
        with open(a.out, "wb") as f:
            f.write(d)
        print("wrote %s (%d bytes)" % (a.out, len(d)))
    else:
        print(d.hex())
    return 0


def _write_value(buf, sig, value):
    raw, off = sig["value"]
    if len(value) != len(raw):
        raise FitError("signature is %d bytes but the FIT has room for %d - "
                       "key size mismatch" % (len(value), len(raw)))
    buf[off:off + len(value)] = value


def sign_buf(buf, n, d):
    """Sign an in-memory FIT. Returns the 256-byte signature value.

    The library entry point: callers holding a key in memory (a BIP85-derived
    key on a SeedSigner, say) must never have to write it to disk.
    """
    sig = signature_node(buf)
    digest = signed_digest(buf)
    em = pss_encode(digest, n.bit_length() - 1, os.urandom(max_salt_len(n)))
    value = pow(int.from_bytes(em, "big"), d, n).to_bytes(256, "big")
    _write_value(buf, sig, value)
    if not verify_buf(buf, n):
        raise FitError("internal error: freshly made signature does not verify")
    return value


def cmd_sign(a):
    buf = read(a.image)
    _algo_check(signature_node(buf), a.image)
    n, e, d = load_privkey(a.key)
    sign_buf(buf, n, d)
    print("signed %s (verified)" % write_out(buf, a.image, a.out))
    return 0


def cmd_splice(a):
    buf = read(a.image)
    sig = signature_node(buf)
    with open(a.sig, "rb") as f:
        value = f.read()
    if len(value) in (512, 513):
        value = bytes.fromhex(value.decode().strip())
    _write_value(buf, sig, value)
    if a.pubkey and not verify_buf(buf, load_pubkey(a.pubkey)[0]):
        raise FitError("spliced signature does NOT verify against %s" % a.pubkey)
    dst = write_out(buf, a.image, a.out)
    print("spliced signature into %s%s"
          % (dst, " (verified)" if a.pubkey else " (NOT verified - pass --pubkey to check)"))
    return 0


def verify_buf(buf, n):
    sig = signature_node(buf)
    value = sig["value"][0]
    s = int.from_bytes(value, "big")
    if s >= n:
        return False
    em = pow(s, 65537, n).to_bytes(256, "big")
    return pss_verify(signed_digest(buf), em, n.bit_length() - 1)


def cmd_verify(a):
    buf = read(a.image)
    _algo_check(signature_node(buf), a.image)
    n, _ = load_pubkey(a.pubkey)
    if verify_buf(buf, n):
        print("OK: %s carries a valid RSA-PSS signature over its FIT metadata" % a.image)
        return 0
    print("FAIL: %s does not verify against %s" % (a.image, a.pubkey))
    return 2


def _image_payloads(buf):
    """{name: (data_offset, size, {hash_node: (algo, value_offset, value_len)})}"""
    props = fdt_props(buf)
    out = {}
    for node, pr in props.items():
        if not node.startswith("/images/") or node.count("/") != 2:
            continue
        if "data-size" not in pr or "data-position" not in pr:
            continue
        size = struct.unpack(">I", pr["data-size"][0])[0]
        pos = struct.unpack(">I", pr["data-position"][0])[0]
        # ONLY `hash`. Rockchip's sibling `digest` node also says algo="sha256"
        # but holds the hash of the DECOMPRESSED payload (the second sha256 in
        # U-Boot's "Checking uboot ... sha256(..) + sha256(..) + OK" line), so it
        # cannot be recomputed from the stored bytes and must never be rewritten
        # from them. It is not covered by the signature either - uboot.img's
        # hashed-nodes lists /images/uboot/hash, not /images/uboot/digest.
        hashes = {}
        hn = node + "/hash"
        if hn in props and "value" in props[hn]:
            algo = props[hn].get("algo", (b"", 0))[0].rstrip(b"\x00").decode("latin1")
            raw, off = props[hn]["value"]
            hashes[hn] = (algo, off, len(raw))
        out[node.split("/")[-1]] = (pos, size, hashes)
    return out


def rehash_buf(buf, report=None):
    """Recompute every sha256 payload `hash` node. Returns the number changed."""
    changed = 0
    for name, (pos, size, hashes) in sorted(_image_payloads(buf).items()):
        actual = hashlib.sha256(bytes(buf[pos:pos + size])).digest()
        for hn, (algo, off, ln) in hashes.items():
            if algo != "sha256" or ln != 32:
                if report:
                    report("   %-10s %s: skipping algo=%r len=%d"
                           % (name, hn.split("/")[-1], algo, ln))
                continue
            if bytes(buf[off:off + ln]) != actual:
                buf[off:off + ln] = actual
                changed += 1
                if report:
                    report("   %-10s %s updated -> %s"
                           % (name, hn.split("/")[-1], actual.hex()[:16]))
    return changed


def cmd_rehash(a):
    """Recompute every sha256 payload hash. Needed after patching a payload."""
    buf = read(a.image)
    changed = rehash_buf(buf, report=print)
    if changed:
        print("rehashed %s (%d hash node(s)); the signature is now stale - re-sign it"
              % (write_out(buf, a.image, a.out), changed))
    else:
        print("%s: all payload hashes already correct" % a.image)
    return 0


def set_pubkey(buf, new_n, old_n):
    """Swap the RSA public key embedded in a FIT payload. Returns hits.

    Locating it needs the OLD key, because the payload is opaque here - there is
    no node saying where the modulus sits. Callers re-keying a whole chain can
    read the old modulus out of idblock.img with rkloader.read_modulus() before
    re-keying that.

    After this the payload has changed, so its `hash` node and the signature are
    both stale: run rehash_buf() then sign_buf().
    """
    hits = 0
    old_be, new_be = old_n.to_bytes(256, "big"), new_n.to_bytes(256, "big")
    at = bytes(buf).find(old_be)
    while at >= 0:
        buf[at:at + 256] = new_be
        hits += 1
        at = bytes(buf).find(old_be, at + 256)
    # the Montgomery constants U-Boot's verifier keeps alongside the modulus
    old_n0 = (-pow(old_n, -1, 1 << 32)) % (1 << 32)
    new_n0 = (-pow(new_n, -1, 1 << 32)) % (1 << 32)
    at = bytes(buf).find(struct.pack(">I", old_n0))
    if at >= 0:
        struct.pack_into(">I", buf, at, new_n0)
        hits += 1
    old_r2 = pow(2, 2 * 2048, old_n).to_bytes(256, "big")
    new_r2 = pow(2, 2 * 2048, new_n).to_bytes(256, "big")
    at = bytes(buf).find(old_r2)
    if at >= 0:
        buf[at:at + 256] = new_r2
        hits += 1
    return hits


def cmd_setkey(a):
    """Replace the RSA public key embedded in a payload (uboot.img's control DTB).

    boot.img carries no key, so this is a no-op there; uboot.img embeds the
    pubkey that U-Boot proper uses to verify boot.img, inside its uncompressed
    `fdt` payload (the U-Boot control DTB).

    Note this does NOT touch the lzma-compressed `uboot` payload, which has a
    Rockchip `digest` node this tool cannot recompute - see _image_payloads().
    """
    buf = read(a.image)
    new = load_pubkey(a.pubkey)[0]
    if not a.old_pubkey:
        raise FitError("--old-pubkey is required: the key to replace cannot be "
                       "located in the payload otherwise")
    hits = set_pubkey(buf, new, load_pubkey(a.old_pubkey)[0])
    if not hits:
        print("%s embeds no copy of that key - nothing to do" % a.image)
        return 0
    dst = write_out(buf, a.image, a.out)
    print("replaced the embedded key in %s (%d location(s))" % (dst, hits))
    print("   run 'fitsign.py rehash' then 'sign' - the payload changed, so its "
          "hash node and the signature are both stale")
    return 0


def cmd_canonicalise(a):
    """Zero every byte that a rebuild cannot be expected to reproduce."""
    buf = read(a.image)
    sig = signature_node(buf)
    cleared = []
    if "value" in sig:
        raw, off = sig["value"]
        buf[off:off + len(raw)] = b"\x00" * len(raw)
        cleared.append("value (%d bytes, key-dependent)" % len(raw))
    if "timestamp" in sig:
        raw, off = sig["timestamp"]
        buf[off:off + len(raw)] = b"\x00" * len(raw)
        cleared.append("timestamp (%d bytes, wall clock)" % len(raw))
    dst = write_out(buf, a.image, a.out)
    print("canonicalised %s" % dst)
    for c in cleared:
        print("   zeroed %s" % c)
    print("   sha256: %s" % hashlib.sha256(bytes(buf)).hexdigest())
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="fitsign.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, out=False):
        sp = sub.add_parser(name)
        sp.add_argument("image")
        if out:
            sp.add_argument("-o", "--out", help="write here instead of in place")
        sp.set_defaults(fn=fn)
        return sp

    add("info", cmd_info)
    d = add("digest", cmd_digest)
    d.add_argument("-o", "--out", help="write the raw 32 bytes here")
    s = add("sign", cmd_sign, out=True)
    s.add_argument("--key", required=True, help="RSA private key PEM")
    sp = add("splice", cmd_splice, out=True)
    sp.add_argument("--sig", required=True, help="256-byte (or hex) signature file")
    sp.add_argument("--pubkey", help="verify the result against this public key")
    v = add("verify", cmd_verify)
    v.add_argument("--pubkey", required=True, help="RSA public key PEM")
    add("rehash", cmd_rehash, out=True)
    sk = add("setkey", cmd_setkey, out=True)
    sk.add_argument("--pubkey", required=True, help="the new RSA public key PEM")
    sk.add_argument("--old-pubkey", required=True, help="the key currently embedded")
    add("canonicalise", cmd_canonicalise, out=True)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except RkError as e:
        print("fitsign: %s" % e, file=sys.stderr)
        return 3
    except (OSError, IOError) as e:
        print("fitsign: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
