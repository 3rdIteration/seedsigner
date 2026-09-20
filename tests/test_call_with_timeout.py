# pylint: disable=missing-function-docstring
import threading
import time
from concurrent.futures import TimeoutError as FuturesTimeoutError

import pytest

from seedsigner.helpers.satochip_signer import _call_with_timeout


class TestATimeoutActuallyReturns:
    """A stalled card must not hold the caller past the timeout."""

    def test_a_stalled_call_raises_without_waiting_for_the_worker(self):
        release = threading.Event()

        def stalls():
            release.wait(30)
            return "too late"

        start = time.monotonic()
        try:
            with pytest.raises((TimeoutError, FuturesTimeoutError)):
                _call_with_timeout(stalls, 0.2)
            elapsed = time.monotonic() - start
        finally:
            release.set()

        # Waiting on the worker would make this ~30s
        assert elapsed < 3, f"took {elapsed:.1f}s: the worker was waited on"
