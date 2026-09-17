"""Luckfox secure-boot signers, vendored from seedsigner-os.

`rkloader.py`, `fitsign.py` and `minisign.py` are copied VERBATIM from
`opt/luckfox/secure-boot/` in the seedsigner-os repo, which is their source of
truth. They are vendored here so the app is self-contained on-device: the
signing tools are not otherwise present in the image.

Do not edit them here. Change them in seedsigner-os and re-copy; the sync is
checked by tests/test_resign_release.py when a seedsigner-os checkout is a
sibling of this repo.

All three are pure stdlib, which is what makes them usable on a SeedSigner:
RSA-PSS is a single pow(), and hashing streams in 64 KiB chunks, so peak memory
does not scale with image size.
"""
