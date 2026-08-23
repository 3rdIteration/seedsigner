import pytest

from seedsigner.helpers import system_memory
from seedsigner.helpers.system_memory import MemoryStats, format_kb, get_memory_stats, parse_meminfo


# Captured from a Luckfox Pico Pro Max (trimmed to the keys we consume, plus a
# couple of unit-less lines to prove they don't break the parser).
MEMINFO_SAMPLE = """MemTotal:         241084 kB
MemFree:           12408 kB
MemAvailable:      41728 kB
Buffers:            2064 kB
Cached:            32872 kB
SwapCached:            0 kB
SwapTotal:             0 kB
SwapFree:              0 kB
HugePages_Total:       0
HugePages_Free:        0
"""


class TestParseMeminfo:
    def test_parses_expected_keys(self):
        values = parse_meminfo(MEMINFO_SAMPLE)
        assert values["MemTotal"] == 241084
        assert values["MemAvailable"] == 41728
        assert values["SwapTotal"] == 0

    def test_parses_unitless_lines(self):
        assert parse_meminfo(MEMINFO_SAMPLE)["HugePages_Total"] == 0

    def test_ignores_garbage(self):
        assert parse_meminfo("not a meminfo line\n\nMemTotal: bogus kB\n") == {}

    def test_empty_input(self):
        assert parse_meminfo("") == {}


class TestGetMemoryStats:
    def _patch_reads(self, monkeypatch, meminfo, status="VmRSS:\t   39112 kB\n"):
        def fake_read(path):
            if path == system_memory.MEMINFO_PATH:
                return meminfo
            if path == system_memory.SELF_STATUS_PATH:
                return status
            return None

        monkeypatch.setattr(system_memory, "_read_file", fake_read)

    def test_derived_values(self, monkeypatch):
        self._patch_reads(monkeypatch, MEMINFO_SAMPLE)
        stats = get_memory_stats()

        assert stats.total_kb == 241084
        assert stats.free_kb == 12408
        assert stats.available_kb == 41728
        assert stats.buffers_cached_kb == 2064 + 32872
        assert stats.swap_total_kb == 0
        assert stats.swap_used_kb == 0
        assert stats.app_rss_kb == 39112

    def test_swap_used(self, monkeypatch):
        self._patch_reads(monkeypatch, "SwapTotal: 65536 kB\nSwapFree: 20480 kB\n")
        assert get_memory_stats().swap_used_kb == 65536 - 20480

    def test_falls_back_when_memavailable_absent(self, monkeypatch):
        """Pre-3.14 kernels have no MemAvailable; approximate rather than show nothing."""
        without = "\n".join(
            line for line in MEMINFO_SAMPLE.splitlines() if not line.startswith("MemAvailable")
        )
        self._patch_reads(monkeypatch, without)
        stats = get_memory_stats()

        assert stats.available_kb == 12408 + 2064 + 32872

    def test_rss_survives_missing_meminfo(self, monkeypatch):
        """Fields must degrade independently."""
        self._patch_reads(monkeypatch, None)
        stats = get_memory_stats()

        assert stats.app_rss_kb == 39112
        assert stats.total_kb is None

    def test_no_proc_at_all(self, monkeypatch):
        """Desktop/Windows/CI: returns an all-None snapshot rather than raising."""
        monkeypatch.setattr(system_memory, "_read_file", lambda path: None)
        stats = get_memory_stats()

        assert isinstance(stats, MemoryStats)
        assert stats.total_kb is None
        assert stats.available_percent is None

    def test_does_not_raise_on_real_system(self):
        """Runs unpatched against whatever host this is, including Windows."""
        assert isinstance(get_memory_stats(), MemoryStats)


class TestAvailablePercent:
    def test_computes_percent(self):
        assert MemoryStats(total_kb=1000, available_kb=250).available_percent == pytest.approx(25.0)

    def test_none_when_unknown(self):
        assert MemoryStats(total_kb=1000).available_percent is None
        assert MemoryStats(available_kb=250).available_percent is None

    def test_no_zero_division(self):
        assert MemoryStats(total_kb=0, available_kb=0).available_percent is None


class TestFormatKb:
    def test_placeholder_for_none(self):
        assert format_kb(None) == "--"

    def test_renders_mb(self):
        assert format_kb(41728) == "40.8 MB"
        assert format_kb(0) == "0.0 MB"
