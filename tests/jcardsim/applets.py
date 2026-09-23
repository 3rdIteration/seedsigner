"""
    Which applets can be simulated, where their source lives, and how to build them.

    Class names and AIDs are deliberately cross-checked against the registry the app
    itself ships -- ``_JAVACARD_APPLETS`` in ``seedsigner.views.smartcard_views`` -- so
    the two cannot silently drift apart. See ``test_registry_matches_the_app``.

    Repositories are *never* mutated. A pinned revision is extracted with ``git archive``
    into a build cache, so a contributor's working checkout of an applet repo is left
    exactly as they had it. That is also what makes SeedKeeper v0.1 and v0.2 buildable
    side by side from one repo.
"""

import os
import shutil
import subprocess
import tarfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

from .simulator import JCardSimUnavailable, REPO_ROOT, SIBLING_ROOT

BUILD_CACHE = REPO_ROOT / "tests" / "jcardsim" / "build" / "applets"


@dataclass(frozen=True)
class AppletSpec:
    name: str
    repo: str                      # directory name under SIBLING_ROOT
    applet_class: str
    aid: str                       # instance AID, hex
    sources_rel: str               # package root of the .java sources, within the repo
    sdk_rel: str = "sdks/jc304_kit/lib/api_classic.jar"
    revision: str | None = None    # git tag/sha; None means the repo's working tree
    install_params: str = ""       # hex, the "applet data" section of the install block
    # How install() expects its parameters laid out. "gp" is the full GlobalPlatform
    # [aidLen][aid][ctrlLen][ctrl][dataLen][data] that SeedKeeper and Satochip parse;
    # "aid_only" is the [aidLen][aid] Keycard's install() expects (and is what
    # status-keycard's own JUnit tests pass).
    install_style: str = "gp"
    # The AID jcardsim registers the applet under. Usually the same as `aid`, but
    # Keycard registers under its *package* AID while its install block carries the
    # *instance* AID -- which is exactly what status-keycard's own tests do.
    install_aid: str = ""
    prebuilt_classes_rel: str | None = None  # use these if present and no revision pinned
    # Jars/dirs the applet needs to compile and to load, e.g. Keycard's keycard-math.jar,
    # a prebuilt JavaCard library the repo ships with no sources.
    extra_classpath_rel: tuple[str, ...] = ()
    env_var: str = ""              # per-applet override for the repo location
    # One-off source edits applied after the revision is exported (or before compiling
    # from the working tree). Each entry is (file relative to sources_rel, old text, new
    # text); the build fails if the old text does not occur exactly once. This stands in
    # for GNU patch, which is not available on every dev machine or CI runner: SmartPGP's
    # rsa-4096.patch is a single constant bump that their own CI applies this way.
    source_edits: tuple[tuple[str, str, str], ...] = ()

    @property
    def repo_env_var(self) -> str:
        return self.env_var or f"SEEDSIGNER_APPLET_{self.name.upper()}_REPO"

    @property
    def registration_aid(self) -> str:
        return self.install_aid or self.aid

    def install_block(self) -> str:
        """The install parameter block for this applet, as hex."""
        aid = bytes.fromhex(self.aid)
        data = bytes.fromhex(self.install_params) if self.install_params else b""
        if self.install_style == "aid_only":
            return (bytes([len(aid)]) + aid).hex()
        return (bytes([len(aid)]) + aid + bytes([0, len(data)]) + data).hex()


# SeedKeeper's install() recovers OM_SIZE from the install parameters and indexes into
# that array unconditionally, so it must be given some: 0x0FFF is the value its own
# source comments use as the GlobalPlatform example.
SEEDKEEPER_PARAMS = "0FFF"

APPLETS: dict[str, AppletSpec] = {
    # Both SeedKeeper versions are the same repo at two tags. v0.1 is the one this fork
    # pins in tests/javacard-cap-legacy/, and the version whose status words (0x9C01 card
    # full) have been the source of real bugs.
    "seedkeeper_v02": AppletSpec(
        name="seedkeeper_v02",
        repo="Seedkeeper-Applet",
        applet_class="org.seedkeeper.applet.SeedKeeper",
        aid="536565644B656570657200",
        sources_rel="src/main/java/org/seedkeeper/applet",
        install_params=SEEDKEEPER_PARAMS,
        prebuilt_classes_rel="build/classes/java/main",
    ),
    "seedkeeper_v01": AppletSpec(
        name="seedkeeper_v01",
        repo="Seedkeeper-Applet",
        applet_class="org.seedkeeper.applet.SeedKeeper",
        aid="536565644B656570657200",
        # v0.1 predates the move to the gradle source layout, so its package root sits
        # at src/ rather than src/main/java/.
        sources_rel="src/org/seedkeeper/applet",
        install_params=SEEDKEEPER_PARAMS,
        revision="v0.1",
    ),
    # Satochip-DIY is the aggregator: the applet sources and the JavaCard SDKs are all
    # submodules of it.
    "satochip": AppletSpec(
        name="satochip",
        repo="Satochip-DIY",
        applet_class="org.satochip.applet.CardEdge",
        aid="5361746F4368697000",
        sources_rel="applets/satochip/src/org/satochip/applet",
    ),
    "satodime": AppletSpec(
        name="satodime",
        repo="Satochip-DIY",
        applet_class="org.satodime.applet.Satodime",
        aid="5361746F44696D6500",
        sources_rel="applets/satodime/src/org/satodime/applet",
    ),
    # Pinned to the release this fork ships as javacard-cap/Keycard_v3.2.cap, not the
    # repo's working tree: master has since moved on (SecureChannelV2, an IdentApplet
    # certificate gate in process(), BIP85) and would test code that is not what users
    # have on their cards. `git archive` exports the tag without touching a contributor's
    # checkout of status-keycard.
    "keycard": AppletSpec(
        name="keycard",
        repo="status-keycard",
        applet_class="im.status.keycard.KeycardApplet",
        aid="A000000804000101",
        sources_rel="src/main/java/im/status/keycard",
        revision="3.2",
        extra_classpath_rel=("keycard-math/keycard-math.jar",),
        install_style="aid_only",
        install_aid="A0000008040001",  # package AID; the block carries the instance AID
    ),
    # Only the built CAPs ship in javacard-cap/; the source has to be cloned from
    # ANSSI-FR/SmartPGP (named in docs/gpg_tools.md).
    #
    # Pinned to the JavaCard 3.0.4 release, not the repo's default 3.1 branch: jcardsim
    # implements the 3.0.x API and has neither NamedParameterSpec nor XECKey, which the
    # 3.1 sources import. The 3.0.4 tag compiles cleanly against jc304_kit -- the same kit
    # its own ant build (build.xml) points at.
    #
    # source_edits applies their .github/workflows/rsa-4096.patch: bumping the transient
    # buffer from 0x3B0 to 0x730 so a full RSA-4096 CRT key import (1819 chained PUT DATA
    # bytes) fits. Without it, importing keys above 2048 bits fails with SW=6581.
    "smartpgp": AppletSpec(
        name="smartpgp",
        repo="SmartPGP",
        applet_class="fr.anssi.smartpgp.SmartPGPApplet",
        aid="D276000124010304AFAF000000000000",
        sources_rel="src/fr/anssi/smartpgp",
        sdk_rel="oracle_javacard_sdks/jc304_kit/lib/api_classic.jar",
        revision="v1.23.2.0-javacard-3.0.4",
        # install() reads [aidLen][AID] out of its parameters and registers under that AID;
        # anything after the AID is ignored (their GP LOAD control data included).
        install_style="aid_only",
        source_edits=(
            ("Constants.java", "(short)0x3b0;", "(short)0x730;"),
        ),
    ),
    # SpecterDIY is the MemoryCardApplet from specter-javacard: an encrypted data store
    # behind a secp256k1 ECDH secure channel. The whole toys package compiles together
    # (MemoryCardApplet needs Secure*, Crypto, PinCode, DataEntry and friends); only the
    # registered applet is live in jcardsim. Pinned to 0.1-pytest: master is one commit
    # ahead of it and that commit only adds py/, so a plain clone compiles identical
    # bytecode either way; install() takes [aidLen][AID] like Keycard's.
    "specterdij": AppletSpec(
        name="specterdij",
        repo="specter-javacard",
        applet_class="toys.MemoryCardApplet",
        aid="B00B5111CB01",
        sources_rel="src/main/java/toys",
        revision="0.1-pytest",
        install_style="aid_only",
    ),
}


def repo_path(spec: AppletSpec) -> Path | None:
    """Where this applet's repo is, or None if it isn't anywhere we look."""
    override = os.environ.get(spec.repo_env_var)
    if override:
        path = Path(override)
        return path if path.is_dir() else None
    path = SIBLING_ROOT / spec.repo
    return path if path.is_dir() else None


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _export_revision(repo: Path, revision: str, dest: Path) -> None:
    """
    Extract `revision` into `dest` without touching the repo's working tree.

    A contributor may well have an applet repo checked out on a branch they are working
    on; checking out a tag under them would be rude and would break the other version's
    build anyway. `git archive` sidesteps both problems.
    """
    result = subprocess.run(
        ["git", "-C", str(repo), "archive", revision],
        capture_output=True,
    )
    if result.returncode != 0:
        raise JCardSimUnavailable(
            f"could not export {revision} from {repo}: {result.stderr.decode(errors='replace').strip()}"
        )
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=BytesIO(result.stdout)) as tar:
        try:
            # The archive is a `git archive` of a pinned revision we trust outright.
            tar.extractall(dest, filter="fully_trusted")
        except TypeError:
            # Python < 3.10.13 has no filter argument.
            tar.extractall(dest)


def _java_sources(root: Path) -> list[str]:
    return [str(p) for p in sorted(root.rglob("*.java"))]


def extra_classpath(spec: AppletSpec, repo: Path) -> list[Path]:
    """Absolute paths for the spec's extra classpath entries that actually exist."""
    return [repo / rel for rel in spec.extra_classpath_rel if (repo / rel).exists()]


def _compile(sources_root: Path, sdk_jar: Path, out: Path, extra: list[Path] | None = None) -> None:
    """
    Compile the applet with javac directly.

    Not with the repo's own ant build: `Satochip-DIY/build.xml` sets no `classes=`
    attribute on its <cap> elements, so ant-javacard compiles into a temp directory and
    keeps only the CAP -- and jcardsim needs the .class files, not the CAP. Going
    straight to javac also avoids needing ant installed at all.
    """
    sources = _java_sources(sources_root)
    if not sources:
        raise JCardSimUnavailable(f"no .java sources under {sources_root}")

    out.mkdir(parents=True, exist_ok=True)
    classpath = os.pathsep.join(str(p) for p in [sdk_jar, *(extra or [])])
    result = _run([
        "javac",
        # JavaCard applets are Java 1.x source; -source/-target 7 is the oldest modern
        # JDKs still accept, and is enough for this bytecode.
        "-source", "7", "-target", "7", "-nowarn",
        "-cp", classpath,
        "-d", str(out),
        *sources,
    ])
    if result.returncode != 0:
        raise JCardSimUnavailable(
            f"javac failed for {sources_root.name}:\n{result.stderr.strip()[:2000]}"
        )


def open_card(name: str, **kwargs):
    """
    A ready-to-start `SimulatedCard` for `name`, with its classpath worked out.

    Prefer this over calling resolve_applet() and constructing the card by hand: some
    applets need extra classpath entries to load at all, and forgetting them shows up as
    a confusing failure inside the JVM.
    """
    from .simulator import SimulatedCard

    spec, classes = resolve_applet(name)
    repo = repo_path(spec)
    extra = extra_classpath(spec, repo) if repo else []
    return SimulatedCard(spec, classes, extra_classpath=extra, **kwargs)


def resolve_applet(name: str) -> tuple[AppletSpec, Path]:
    """
    Return the spec and a directory of compiled classes, building only if needed.

    Raises JCardSimUnavailable with a specific reason -- which repo, which path -- so a
    skipped test says what is actually missing rather than just "unavailable".
    """
    spec = APPLETS[name]
    repo = repo_path(spec)
    if repo is None:
        raise JCardSimUnavailable(
            f"{spec.repo} not found under {SIBLING_ROOT} (set {spec.repo_env_var})"
        )

    # Fast path: the repo has already built the classes we need and we are not pinned to
    # a different revision. Seedkeeper-Applet ships in this state.
    if spec.revision is None and spec.prebuilt_classes_rel:
        prebuilt = repo / spec.prebuilt_classes_rel
        if (prebuilt / Path(spec.applet_class.replace(".", "/") + ".class")).is_file():
            return spec, prebuilt

    if spec.source_edits and not spec.revision:
        raise JCardSimUnavailable(
            f"{spec.name}: source_edits require a pinned revision so the edits apply to an "
            f"export, never the repo's working tree"
        )

    out = BUILD_CACHE / spec.name / "classes"
    marker = out / ".built"
    # The stamp covers both inputs that change what gets compiled: the revision and any
    # source edits layered on top of it.
    stamp = f"{spec.revision or 'worktree'}\n{repr(spec.source_edits)}\n"
    if marker.is_file() and marker.read_text(encoding="utf-8") == stamp:
        return spec, out

    if out.exists():
        shutil.rmtree(out)

    if spec.revision:
        export = BUILD_CACHE / spec.name / "src"
        if export.exists():
            shutil.rmtree(export)
        _export_revision(repo, spec.revision, export)
        sources_root = export / spec.sources_rel
        sdk_jar = repo / spec.sdk_rel  # SDKs come from the working repo, not the export
    else:
        sources_root = repo / spec.sources_rel
        sdk_jar = repo / spec.sdk_rel

    if not sources_root.is_dir():
        raise JCardSimUnavailable(f"applet sources not at {sources_root}")
    if not sdk_jar.is_file():
        raise JCardSimUnavailable(
            f"JavaCard SDK jar not at {sdk_jar} (is the repo's sdks/ submodule checked out?)"
        )

    for rel, old, new in spec.source_edits:
        path = sources_root / rel
        text = path.read_text(encoding="utf-8")
        if text.count(old) != 1:
            raise JCardSimUnavailable(
                f"source edit for {spec.name}/{rel}: expected exactly one occurrence of "
                f"{old!r}, found {text.count(old)}"
            )
        path.write_text(text.replace(old, new), encoding="utf-8")

    _compile(sources_root, sdk_jar, out, extra_classpath(spec, repo))
    marker.write_text(stamp, encoding="utf-8")
    return spec, out
