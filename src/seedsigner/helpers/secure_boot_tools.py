"""Locate and import the Luckfox secure-boot signers provided by SeedSigner OS.

The signers (`rkloader.py`, `fitsign.py`, `minisign.py`) and `luckfox_release.py`,
which knows how a whole release fits together, live in the
**seedsigner-os** repo and are installed onto the image by its build. They are
deliberately not vendored here: one copy means nothing can drift, and it keeps
them usable as CLIs on a build machine with or without this app.

They are pure stdlib, so "installing" them is just putting the files somewhere
and importing them.

Resolution order:

  1. ``$SEEDSIGNER_SECURE_BOOT_DIR`` -- explicit override, used by the tests and
     by anyone running the app from a checkout.
  2. ``/usr/lib/seedsigner/secure-boot`` -- where SeedSigner OS installs them.
  3. a sibling ``seedsigner-os`` checkout next to this repo, so the feature is
     developable on a desktop without installing anything.

When none of those exist the tooling is simply absent: `is_available()` returns
False and callers hide the feature, the same way the Network Info entry hides
when ``/usr/bin/network-info`` is not on the image. `load()` raises
`SecureBootToolsUnavailable` with the paths it tried, so a failure explains
itself rather than surfacing as an ImportError.
"""
import importlib
import os
import sys

MODULES = ("rkloader", "fitsign", "minisign", "luckfox_release")

# Every board can run the tools: they are ~55 KB of stdlib and every heavy path
# streams (a full mini-bundle re-sign peaks at ~14 MB measured), so even the
# Pico Mini's 64 MB DRAM fits them. An earlier OOM there was a full-file read
# bug since fixed; the views warn when free memory is low before running the
# heavy actions instead of blocking boards by name.

ENV_VAR = "SEEDSIGNER_SECURE_BOOT_DIR"
IMAGE_DIR = "/usr/lib/seedsigner/secure-boot"


class SecureBootToolsUnavailable(Exception):
    """The seedsigner-os signing tools are not present on this system."""


def _sibling_checkout_dir():
    """<parent>/seedsigner-os/opt/luckfox/secure-boot, for desktop development."""
    here = os.path.dirname(os.path.abspath(__file__))              # .../src/seedsigner/helpers
    repo = os.path.abspath(os.path.join(here, "..", "..", ".."))   # the app repo root
    return os.path.join(os.path.dirname(repo), "seedsigner-os",
                        "opt", "luckfox", "secure-boot")


def candidate_dirs():
    """Every directory that might hold the signers, in priority order."""
    out = []
    override = os.environ.get(ENV_VAR)
    if override:
        out.append(override)
    out.append(IMAGE_DIR)
    out.append(_sibling_checkout_dir())
    return out


def find_dir():
    """The first candidate that actually holds all of MODULES, or None."""
    for d in candidate_dirs():
        if all(os.path.isfile(os.path.join(d, "%s.py" % m)) for m in MODULES):
            return d
    return None


def is_available():
    """Cheap enough to call from menu-building code."""
    return find_dir() is not None


def load():
    """Import the tools. Returns (rkloader, fitsign, minisign, luckfox_release).

    The modules import each other by bare name (fitsign needs rkloader), so the
    directory goes on sys.path rather than being loaded file-by-file.
    """
    directory = find_dir()
    if directory is None:
        raise SecureBootToolsUnavailable(
            "SeedSigner OS signing tools not found. Looked in: %s. They are "
            "installed by the seedsigner-os build at %s; set %s to point at a "
            "seedsigner-os checkout's opt/luckfox/secure-boot to use them "
            "elsewhere." % (", ".join(candidate_dirs()), IMAGE_DIR, ENV_VAR))

    if directory not in sys.path:
        sys.path.insert(0, directory)
    try:
        return tuple(importlib.import_module(m) for m in MODULES)
    except ImportError as e:
        raise SecureBootToolsUnavailable(
            "found the signing tools in %s but could not import them: %s"
            % (directory, e))
