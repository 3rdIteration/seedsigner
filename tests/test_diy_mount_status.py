"""View-level tests for ToolsDIYMountStatusView (the "Mount Status" item in the
Javacard DIY menu). The log reader is patched so no real /tmp/diy-mount.log is
needed; run_screen captures what would be shown on the display."""

# Bootstrap the shared test environment (hardware mocks, singleton resets) the
# same way the full suite and other view tests do, so importing the heavy
# smartcard_views module here doesn't run ahead of the mock setup.
import tests.base  # noqa: F401

from seedsigner.views import smartcard_views


def _run_mount_status_view(monkeypatch, status):
    monkeypatch.setattr(smartcard_views, "read_diy_mount_status", lambda: status)

    view = object.__new__(smartcard_views.ToolsDIYMountStatusView)
    screens = []

    def fake_run_screen(screen_cls, *args, **kwargs):
        screens.append((screen_cls, kwargs))
        return 0

    view.run_screen = fake_run_screen
    destination = view.run()
    return destination, screens


def test_truncate_hash_middle():
    value = "22e289c2caa58ed4d460735b03155a57537fa7e29b354ca4fc72a508fe3bdff8"
    assert smartcard_views._truncate_hash_middle(value) == "22e289c2...fe3bdff8"

    # Short values are returned unchanged (nothing to elide).
    short = "abc123"
    assert smartcard_views._truncate_hash_middle(short) == short


def test_no_log_means_no_information_not_an_error(monkeypatch):
    """A missing /tmp/diy-mount.log (no events since boot on tmpfs) must show a
    neutral info screen, not an error."""
    destination, screens = _run_mount_status_view(monkeypatch, None)

    assert len(screens) == 1
    _, kwargs = screens[0]
    assert "No mount events since boot." in kwargs["text"]
    # Backing out returns to the DIY Tools menu via the back stack.
    from seedsigner.views.view import BackStackView
    assert destination.View_cls is BackStackView


def test_ok_status_shows_reason_single_screen(monkeypatch):
    status = {
        "status": "OK",
        "reason": "diy-tools verified and mounted at /mnt/diy",
        "arch": "armhf",
        "computed": "22e289c2" * 8,
        "pinned": "22e289c2" * 8,
        "mount": "/mnt/diy",
    }
    _, screens = _run_mount_status_view(monkeypatch, status)

    assert len(screens) == 1
    _, kwargs = screens[0]
    assert kwargs["text"] == "diy-tools verified and mounted at /mnt/diy"


def test_hash_mismatch_reports_only_the_found_hash_truncated(monkeypatch):
    """On a mismatch only the hash actually found on the card is reported, and
    it's truncated in the middle (head...tail) -- not the full 64 chars, and
    not the expected/pinned value."""
    computed = "deadbeef0000c0ffee1234567890abcdef1234567890abcdef12345678"
    pinned = "22e289c2caa58ed4d460735b03155a57537fa7e29b354ca4fc72a508fe3bdff8"
    status = {
        "status": "REFUSED_HASH_MISMATCH",
        "reason": ("diy-tools.squashfs hash does not match the pinned value; "
                   "refusing to mount an unverified image"),
        "arch": "armhf",
        "computed": computed,
        "pinned": pinned,
    }
    _, screens = _run_mount_status_view(monkeypatch, status)

    # Status screen + one screen for the found hash.
    assert len(screens) == 2
    reason_kwargs = screens[0][1]
    assert "hash does not match" in reason_kwargs["text"]

    shown = screens[1][1]["text"]
    assert shown == f"{computed[:8]}...{computed[-8:]}"
    # The full hash and the expected (pinned) value must never be displayed.
    for kwargs in [s[1] for s in screens]:
        assert computed not in str(kwargs)
        assert pinned not in str(kwargs)


def test_hash_mismatch_missing_fields_degrades_gracefully(monkeypatch):
    """If a field is absent/empty for some reason, skip that screen rather than
    rendering an empty one."""
    status = {
        "status": "REFUSED_HASH_MISMATCH",
        "reason": "hash mismatch",
        "computed": "",
    }
    _, screens = _run_mount_status_view(monkeypatch, status)

    assert len(screens) == 1


def test_unknown_status_falls_back_to_warning_presentation(monkeypatch):
    """A future/unknown status value must still render (status + reason), not crash."""
    status = {"status": "SOMETHING_NEW", "reason": "new thing happened"}
    _, screens = _run_mount_status_view(monkeypatch, status)

    assert len(screens) == 1
    _, kwargs = screens[0]
    assert kwargs["text"] == "new thing happened"
    assert kwargs["status_headline"] == "SOMETHING_NEW"
