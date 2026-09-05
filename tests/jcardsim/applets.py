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
    install_params: str = ""       # hex, passed through to the applet's install()
    prebuilt_classes_rel: str | None = None  # use these if present and no revision pinned
    env_var: str = ""              # per-applet override for the repo location

    @property
    def repo_env_var(self) -> str:
        return self.env_var or f"SEEDSIGNER_APPLET_{self.name.upper()}_REPO"


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
    "keycard": AppletSpec(
        name="keycard",
        repo="status-keycard",
        applet_class="im.status.keycard.KeycardApplet",
        aid="A000000804000101",
        sources_rel="src/main/java/im/status/keycard",
        prebuilt_classes_rel="build/classes/java/main",
    ),
    # Only the built CAPs ship in javacard-cap/; the source has to be cloned. See
    # docs/gpg_tools.md, which names ANSSI-FR/SmartPGP as the upstream.
    "smartpgp": AppletSpec(
        name="smartpgp",
        repo="SmartPGP",
        applet_class="fr.anssi.smartpgp.SmartPGPApplet",
        aid="D276000124010304000000000000000000",
        sources_rel="src/fr/anssi/smartpgp",
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
        tar.extractall(dest)


def _java_sources(root: Path) -> list[str]:
    return [str(p) for p in sorted(root.rglob("*.java"))]


def _compile(sources_root: Path, sdk_jar: Path, out: Path) -> None:
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
    result = _run([
        "javac",
        # JavaCard applets are Java 1.x source; -source/-target 7 is the oldest modern
        # JDKs still accept, and is enough for this bytecode.
        "-source", "7", "-target", "7", "-nowarn",
        "-cp", str(sdk_jar),
        "-d", str(out),
        *sources,
    ])
    if result.returncode != 0:
        raise JCardSimUnavailable(
            f"javac failed for {sources_root.name}:\n{result.stderr.strip()[:2000]}"
        )


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

    out = BUILD_CACHE / spec.name / "classes"
    marker = out / ".built"
    stamp = f"{spec.revision or 'worktree'}\n"
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

    _compile(sources_root, sdk_jar, out)
    marker.write_text(stamp, encoding="utf-8")
    return spec, out
