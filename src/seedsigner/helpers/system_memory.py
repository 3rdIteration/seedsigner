"""Read system RAM usage from the kernel's own virtual files.

Deliberately app-side only: ``/proc/meminfo`` and ``/proc/self/status`` are
provided by the kernel and readable by an unprivileged ``open()``, so no
seedsigner-os helper script is needed. Shelling out to busybox ``free`` would
mean spawning a process on a RAM-starved board just to re-read these same
files, and busybox's column layout differs from coreutils'.

Follows the ``helpers.hardening`` / ``helpers.seedsigner_os`` precedent: probe
the live system, return plain data, never raise. Every field degrades on its own
so a partial read still reports whatever it could get, and a desktop/CI host
without ``/proc`` simply gets ``None`` everywhere.
"""
import logging
import re
from dataclasses import dataclass


logger = logging.getLogger(__name__)


MEMINFO_PATH = "/proc/meminfo"
SELF_STATUS_PATH = "/proc/self/status"

# "MemTotal:       110284 kB" -- the unit is always kB on Linux, but a handful
# of fields (e.g. HugePages_Total) carry no unit at all, hence the optional group.
_MEMINFO_LINE = re.compile(r"^(?P<key>\w+):\s+(?P<value>\d+)(?:\s+kB)?\s*$")


@dataclass
class MemoryStats:
    """A snapshot of system memory, all values in kB. ``None`` means "couldn't read"."""
    total_kb: int | None = None
    available_kb: int | None = None
    free_kb: int | None = None
    buffers_cached_kb: int | None = None
    swap_total_kb: int | None = None
    swap_used_kb: int | None = None
    app_rss_kb: int | None = None

    @property
    def available_percent(self) -> float | None:
        if not self.total_kb or self.available_kb is None:
            return None
        return 100.0 * self.available_kb / self.total_kb


def parse_meminfo(text: str) -> dict[str, int]:
    """Parse ``/proc/meminfo`` text into ``{key: kB}``. Unparseable lines are skipped."""
    values: dict[str, int] = {}
    for line in text.splitlines():
        match = _MEMINFO_LINE.match(line.strip())
        if match:
            values[match.group("key")] = int(match.group("value"))
    return values


def _read_file(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8") as file:
            return file.read()
    except Exception:
        return None


def _get_app_rss_kb() -> int | None:
    """This process's resident set size, from ``/proc/self/status``.

    On a 64MB Luckfox this is the number that actually says how close to OOM the
    app is, so it's worth showing alongside the system-wide figures.
    """
    text = _read_file(SELF_STATUS_PATH)
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            match = _MEMINFO_LINE.match(line.strip())
            if match:
                return int(match.group("value"))
            break
    return None


def get_memory_stats() -> MemoryStats:
    """Snapshot current memory usage. Always returns a MemoryStats; never raises."""
    stats = MemoryStats()

    # Read RSS first so it still reports if /proc/meminfo is the thing that fails.
    stats.app_rss_kb = _get_app_rss_kb()

    text = _read_file(MEMINFO_PATH)
    if not text:
        return stats

    values = parse_meminfo(text)
    stats.total_kb = values.get("MemTotal")
    stats.free_kb = values.get("MemFree")

    buffers = values.get("Buffers")
    cached = values.get("Cached")
    if buffers is not None or cached is not None:
        stats.buffers_cached_kb = (buffers or 0) + (cached or 0)

    stats.available_kb = values.get("MemAvailable")
    if stats.available_kb is None and stats.free_kb is not None:
        # MemAvailable has existed since Linux 3.14 so both the Luckfox (5.10)
        # and the Pi have it; approximate rather than show nothing if some other
        # kernel doesn't.
        stats.available_kb = stats.free_kb + (stats.buffers_cached_kb or 0)

    stats.swap_total_kb = values.get("SwapTotal")
    swap_free = values.get("SwapFree")
    if stats.swap_total_kb is not None and swap_free is not None:
        stats.swap_used_kb = stats.swap_total_kb - swap_free

    return stats


def format_kb(value: int | None) -> str:
    """Render a kB value as MB for display; ``None`` becomes a placeholder."""
    if value is None:
        return "--"
    return f"{value / 1024:.1f} MB"
