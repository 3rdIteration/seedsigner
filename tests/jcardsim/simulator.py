"""
    Start a jcardsim JVM holding one applet, and speak APDUs to it.

    Three things here were learned the hard way and are the reason this does not just
    reuse specter-javacard's `simulator.jar`:

    * **Install parameters.** `simulator.jar`'s CLI calls jcardsim's two-argument
      `installApplet(aid, class)`, which passes no install parameters. SeedKeeper's
      `install()` indexes into that array unconditionally to recover OM_SIZE, so it
      throws SystemException before the port ever opens. `java/SimLauncher.java` builds
      the real `[aidLen][aid][ctrlLen][ctrl][dataLen][data]` block instead.

    * **`-noverify`.** jcardsim's JavaCard API stubs predate stackmap frames, so the JVM
      verifier rejects them with `VerifyError: Expecting a stackmap frame`.
      status-keycard's own test setup passes `-noverify` for exactly this reason.

    * **Framing.** The wire protocol is a 2-byte big-endian length followed by the
      payload, in both directions, and both sides must reassemble. specter's version
      reads one APDU per `recv()` with a 256-byte cap, which silently truncates larger
      responses (SeedKeeper secret exports, RSA reads) into what looks like an applet
      bug. `recv()` returning fewer bytes than asked for is normal, not an error.
"""

import os
import shutil
import socket
import struct
import subprocess
import threading
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
LAUNCHER_SRC = Path(__file__).resolve().parent / "java" / "SimLauncher.java"

# Where a sibling checkout of the applet/simulator repos is expected when the
# environment does not say otherwise.
SIBLING_ROOT = Path(os.environ.get("SEEDSIGNER_APPLET_ROOT", Path.home() / "Documents" / "GitHub"))

# jcardsim 3.0.5 rather than the 3.0.4 shaded inside specter's simulator.jar: it is a
# plain jar on disk, it is what status-keycard tests against, and its algorithm coverage
# is the better of the two.
JCARDSIM_JAR_ENV = "SEEDSIGNER_JCARDSIM_JAR"
DEFAULT_JCARDSIM_JAR = SIBLING_ROOT / "status-keycard" / "jcardsim" / "jcardsim-3.0.5-SNAPSHOT.jar"

_MAX_FRAME = 65535


class JCardSimUnavailable(Exception):
    """The simulator cannot run here (no Java, no jcardsim jar, no applet classes)."""


def jcardsim_jar() -> Path:
    override = os.environ.get(JCARDSIM_JAR_ENV)
    return Path(override) if override else DEFAULT_JCARDSIM_JAR


def why_unavailable() -> str | None:
    """A human-readable reason the simulator can't run, or None if it can."""
    if shutil.which("java") is None:
        return "java not on PATH"
    if shutil.which("javac") is None:
        return "javac not on PATH (a JDK is needed to build the launcher)"
    jar = jcardsim_jar()
    if not jar.is_file():
        return f"jcardsim jar not found at {jar} (set {JCARDSIM_JAR_ENV})"
    return None


def simulator_available() -> bool:
    return why_unavailable() is None


def _launcher_classes() -> Path:
    """Compile SimLauncher.java once per session; returns the classes directory."""
    out = REPO_ROOT / "tests" / "jcardsim" / "build" / "classes"
    stamp = out / "SimLauncher.class"
    if stamp.is_file() and stamp.stat().st_mtime >= LAUNCHER_SRC.stat().st_mtime:
        return out

    out.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["javac", "-cp", str(jcardsim_jar()), "-d", str(out), str(LAUNCHER_SRC)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise JCardSimUnavailable(f"could not compile SimLauncher: {result.stderr.strip()}")
    return out


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SimulatedCard:
    """
    A running applet, with a pyscard-shaped `transmit`.

    `transmit` returns `(data, sw1, sw2)` -- the same shape pyscard's
    `CardConnection.transmit` returns -- so the pcsc shim can hand this straight to
    SeedSigner's client code.
    """

    def __init__(self, applet, classes_dir: Path, port: int | None = None, timeout: float = 30.0,
                 extra_classpath=()):
        self.applet = applet
        self.classes_dir = Path(classes_dir)
        # Anything else the applet needs to load, e.g. Keycard's keycard-math.jar.
        self.extra_classpath = [Path(p) for p in extra_classpath]
        self.port = port or _free_port()
        self.timeout = timeout
        self._proc: subprocess.Popen | None = None
        self._sock: socket.socket | None = None
        self._stderr: list[str] = []

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "SimulatedCard":
        reason = why_unavailable()
        if reason:
            raise JCardSimUnavailable(reason)
        if not self.classes_dir.is_dir():
            raise JCardSimUnavailable(f"applet classes not built at {self.classes_dir}")

        spec = (f"{self.applet.registration_aid}:{self.applet.applet_class}"
                f":{self.applet.install_block()}")

        cmd = [
            "java", "-noverify",
            "-cp", os.pathsep.join([str(_launcher_classes()), str(jcardsim_jar())]),
            "SimLauncher",
            "--port", str(self.port),
            "--classes", os.pathsep.join(
                str(p) for p in [self.classes_dir, *self.extra_classpath]
            ),
            "--applet", spec,
        ]
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1
        )
        threading.Thread(target=self._drain_stderr, daemon=True).start()

        # Wait for the launcher's own READY line rather than sleeping and hoping.
        line = self._proc.stdout.readline()
        if not line.startswith("READY"):
            self.stop()
            detail = "".join(self._stderr[-25:]).strip()
            raise JCardSimUnavailable(
                f"{self.applet.name} did not start in jcardsim:\n{detail or line.strip()}"
            )

        self._sock = socket.create_connection(("127.0.0.1", self.port), timeout=self.timeout)
        self._sock.settimeout(self.timeout)
        return self

    def _drain_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        for line in self._proc.stderr:
            self._stderr.append(line)

    def stop(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        if self._proc is not None:
            self._proc.kill()
            self._proc.wait(timeout=10)
            self._proc = None

    def __enter__(self) -> "SimulatedCard":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()

    @property
    def simulator_log(self) -> str:
        """Whatever the JVM wrote to stderr -- applet stack traces land here."""
        return "".join(self._stderr)

    # -- transport ---------------------------------------------------------

    def _recv_exact(self, n: int) -> bytes:
        assert self._sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError(
                    f"simulator closed the connection; log:\n{self.simulator_log}"
                )
            buf += chunk
        return buf

    def transmit_raw(self, apdu: bytes) -> bytes:
        """Send one APDU, return the full response including SW1SW2."""
        if self._sock is None:
            raise RuntimeError("simulator is not running")
        if len(apdu) > _MAX_FRAME:
            raise ValueError(f"APDU too long for the frame header: {len(apdu)} bytes")
        self._sock.sendall(struct.pack(">H", len(apdu)) + apdu)
        (length,) = struct.unpack(">H", self._recv_exact(2))
        return self._recv_exact(length)

    def transmit(self, apdu) -> tuple[list[int], int, int]:
        """pyscard-shaped: takes a list of ints, returns (data, sw1, sw2)."""
        response = self.transmit_raw(bytes(apdu))
        if len(response) < 2:
            raise ConnectionError(f"short response from simulator: {response.hex()}")
        return list(response[:-2]), response[-2], response[-1]

    def select(self) -> tuple[list[int], int, int]:
        """SELECT the applet by AID; the fresh-card starting point for every test."""
        aid = bytes.fromhex(self.applet.aid)
        return self.transmit([0x00, 0xA4, 0x04, 0x00, len(aid)] + list(aid))
