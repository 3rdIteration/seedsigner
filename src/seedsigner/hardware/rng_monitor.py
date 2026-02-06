import logging
import math
import os
import threading
import time
from collections import deque

from seedsigner.models.threads import BaseThread

logger = logging.getLogger(__name__)


class HardwareRngHealthMonitor:
    """Tracks health of hardware RNG output samples."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._samples: deque[bytes] = deque(maxlen=10)
        self._failed = False
        self._failure_reason: str | None = None
        self._last_entropy: float | None = None

    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        entropy = 0.0
        data_len = len(data)
        for count in counts:
            if count == 0:
                continue
            p = count / data_len
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _detect_loop(samples: list[bytes]) -> bool:
        sample_count = len(samples)
        if sample_count < 4:
            return False

        # Detect short cycles (ABAB, ABCABC, etc.) at the tail of history.
        max_cycle = min(5, sample_count // 2)
        for cycle_size in range(1, max_cycle + 1):
            tail = samples[-(2 * cycle_size) :]
            if tail[:cycle_size] == tail[cycle_size:]:
                return True
        return False

    def note_failure(self, reason: str) -> None:
        with self._lock:
            self._failed = True
            self._failure_reason = reason

    def add_sample(self, sample: bytes, *, min_entropy: float = 4.0) -> bool:
        with self._lock:
            if self._failed:
                return False

            entropy = self.shannon_entropy(sample)
            self._last_entropy = entropy
            self._samples.append(sample)

            if entropy < min_entropy:
                self._failed = True
                self._failure_reason = f"Low System RNG entropy: {entropy:.2f}"
                return False

            if len(set(sample)) == 1:
                self._failed = True
                self._failure_reason = "System RNG sample appears constant"
                return False

            samples = list(self._samples)
            if len(samples) >= 10 and len(set(samples)) == 1:
                self._failed = True
                self._failure_reason = "System RNG repeated identical samples"
                return False

            if self._detect_loop(samples):
                self._failed = True
                self._failure_reason = "System RNG sample loop detected"
                return False

            return True

    def is_healthy(self) -> bool:
        with self._lock:
            return not self._failed

    def failure_reason(self) -> str | None:
        with self._lock:
            return self._failure_reason


class HardwareRngMonitorThread(BaseThread):
    def __init__(self, monitor: HardwareRngHealthMonitor):
        super().__init__()
        self.monitor = monitor

    @staticmethod
    def _read_system_rng_bytes(num_bytes: int) -> bytes:
        data = os.urandom(num_bytes)
        if len(data) != num_bytes:
            raise OSError(f"Expected {num_bytes} bytes from system RNG, got {len(data)}")
        return data

    def run(self):
        while self.keep_running:
            try:
                sample = self._read_system_rng_bytes(32)
                healthy = self.monitor.add_sample(sample)
                if not healthy:
                    logger.error("System RNG monitor failure: %s", self.monitor.failure_reason())
            except Exception as e:
                self.monitor.note_failure(f"System RNG read failed: {e}")
                logger.error("System RNG monitor read failed", exc_info=True)

            # Poll once per minute.
            for _ in range(60):
                if not self.keep_running:
                    break
                time.sleep(1)
