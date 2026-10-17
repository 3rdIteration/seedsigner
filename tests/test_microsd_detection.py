"""MicroSD insert/remove detection: mount state is the truth, the FIFO a hint."""
import os
import threading
import time

import pytest

from seedsigner.hardware.microsd import MicroSD

ADD = MicroSD.ACTION__INSERTED
REMOVE = MicroSD.ACTION__REMOVED


def test_parse_single_messages():
    assert MicroSD.parse_fifo_actions(b"add") == [ADD]
    assert MicroSD.parse_fifo_actions(b"remove") == [REMOVE]


def test_parse_coalesced_messages_in_order():
    # Hotplug helpers write without a separator; a quick swap reads as one chunk.
    assert MicroSD.parse_fifo_actions(b"removeadd") == [REMOVE, ADD]
    assert MicroSD.parse_fifo_actions(b"addaddremove") == [ADD, ADD, REMOVE]


def test_parse_ignores_noise():
    assert MicroSD.parse_fifo_actions(b"") == []
    assert MicroSD.parse_fifo_actions(b"\n garbage \xff") == []
    assert MicroSD.parse_fifo_actions(b"xxadd\n") == [ADD]


def test_state_change_without_any_fifo_message_is_detected():
    # The poll catches a mount the FIFO never told us about (e.g. one that
    # happened before the FIFO existed).
    assert MicroSD.detect_state_change(False, True, []) == ADD
    assert MicroSD.detect_state_change(True, False, []) == REMOVE


def test_no_change_reports_nothing():
    assert MicroSD.detect_state_change(False, False, []) is None
    assert MicroSD.detect_state_change(True, True, []) is None


def test_fifo_message_contradicting_mount_state_is_ignored():
    # "add" while nothing is mounted (mount failed) must not claim a card.
    assert MicroSD.detect_state_change(False, False, [ADD]) is None
    # A stale "remove" while a card is still mounted changes nothing.
    assert MicroSD.detect_state_change(True, True, [REMOVE]) is None


def test_fast_card_swap_reports_insert():
    # Swapped within one poll: still mounted, but a new card was added, so its
    # settings.json must be (re)loaded.
    assert MicroSD.detect_state_change(True, True, [REMOVE, ADD]) == ADD


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs POSIX FIFOs")
def test_detection_loop_end_to_end(monkeypatch, tmp_path):
    """Drive the real run() loop: startup sample, FIFO wake-up, poll fallback."""
    from seedsigner.controller import Controller
    from seedsigner.models.settings import Settings

    mounted = {"value": False}
    reported = []

    monkeypatch.setattr(Settings, "is_seedsigner_os", classmethod(lambda cls: True))
    monkeypatch.setattr(
        Settings, "handle_microsd_state_change", classmethod(lambda cls, action: reported.append(action))
    )

    class _StubController:
        def activate_toast(self, toast):
            pass

    monkeypatch.setattr(Controller, "get_instance", classmethod(lambda cls: _StubController()))
    import seedsigner.gui.toast as toast_module
    monkeypatch.setattr(toast_module, "SDCardStateChangeToastManagerThread", lambda action: None)
    monkeypatch.setattr(MicroSD, "is_inserted", property(lambda self: mounted["value"]))
    monkeypatch.setattr(MicroSD, "POLL_INTERVAL_SECONDS", 0.05)

    microsd = object.__new__(MicroSD)
    threading.Thread.__init__(microsd, daemon=True)
    microsd.FIFO_PATH = str(tmp_path / "mdev_fifo")
    # A stale regular file left by a hotplug write before the app started.
    (tmp_path / "mdev_fifo").write_text("add")
    microsd.keep_running = True
    microsd.start = threading.Thread.start.__get__(microsd)
    microsd.start()

    def wait_for(n):
        deadline = time.time() + 5
        while len(reported) < n and time.time() < deadline:
            time.sleep(0.01)
        assert len(reported) >= n, reported

    try:
        wait_for(1)
        assert reported == [MicroSD.ACTION__REMOVED]  # startup sample: no card

        # Mounted, then the OS helper writes the hint (must not block: the
        # app holds the FIFO open).
        mounted["value"] = True
        fd = os.open(microsd.FIFO_PATH, os.O_WRONLY | os.O_NONBLOCK)
        os.write(fd, b"add")
        os.close(fd)
        wait_for(2)
        assert reported[1] == MicroSD.ACTION__INSERTED

        # Unmounted with NO FIFO message at all: the poll still notices.
        mounted["value"] = False
        wait_for(3)
        assert reported[2] == MicroSD.ACTION__REMOVED
    finally:
        microsd.keep_running = False
        microsd.join(timeout=2)
