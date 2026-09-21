"""Helpers for capturing documentation screenshots from real screens.

``DocsCaptureSession`` wraps a ``ui_driver.UISession`` and saves the first rendered
frame of each contiguous screen, so a multi-screen flow produces one image per screen
rather than one per animation frame. Images are written to
``$SEEDSIGNER_DOCS_OUT/<topic>/NN_<ScreenClassName>.png``.

The topic directory is cleared once per process (so re-running regenerates a stable
set instead of accumulating files), and the sequence number keeps counting across
sessions for the same topic so images from several flows stay in order.
"""

import os
from pathlib import Path

# tests/ is added to sys.path by this package's conftest.
from ui_driver import UISession

DOCS_OUT_ENV = "SEEDSIGNER_DOCS_OUT"

# topic -> whether its directory has been cleared this process
_CLEANED_TOPICS: set[str] = set()
# topic -> number of images written so far this process
_TOPIC_COUNTS: dict[str, int] = {}


def docs_out_dir() -> Path | None:
    value = os.environ.get(DOCS_OUT_ENV)
    return Path(value) if value else None


def _screen_name(screen) -> str:
    """A descriptive, filename-safe label for a screen (its title when it has one)."""
    if screen is None:
        return "Screen"
    title = getattr(screen, "title", None)
    if title:
        cleaned = "".join(c if c.isalnum() else "_" for c in str(title)).strip("_")
        while "__" in cleaned:
            cleaned = cleaned.replace("__", "_")
        if cleaned:
            return cleaned
    return type(screen).__name__


def _reset_topic(topic: str) -> None:
    out = docs_out_dir()
    if out is None:
        return
    topic_dir = out / topic
    if topic not in _CLEANED_TOPICS:
        if topic_dir.is_dir():
            for existing in topic_dir.glob("*.png"):
                existing.unlink()
        topic_dir.mkdir(parents=True, exist_ok=True)
        _CLEANED_TOPICS.add(topic)
        _TOPIC_COUNTS.setdefault(topic, 0)


class DocsCaptureSession:
    """A ``UISession`` that also writes one PNG per screen it renders."""

    def __init__(self, topic: str, script=None, poll_responses=None, camera_frames=None):
        self.topic = topic
        self.session = UISession(
            script=script,
            poll_responses=poll_responses,
            camera_frames=camera_frames,
        )
        self.saved: list[str] = []
        self._current_screen: str | None = None

    def __enter__(self) -> "DocsCaptureSession":
        _reset_topic(self.topic)
        self.session.__enter__()

        inner_show_image = self.session.renderer.show_image.side_effect

        def capturing_show_image(image=None, alpha_overlay=None, is_background_thread=False, show_direct=False):
            inner_show_image(
                image=image,
                alpha_overlay=alpha_overlay,
                is_background_thread=is_background_thread,
                show_direct=show_direct,
            )
            if is_background_thread:
                return
            self._capture()

        self.session.renderer.show_image.side_effect = capturing_show_image
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self.session.__exit__(exc_type, exc_value, traceback)

    @property
    def renderer(self):
        return self.session.renderer

    @property
    def remaining_script(self):
        return self.session.remaining_script

    def _capture(self) -> None:
        screen = self.session.current_screen
        name = _screen_name(screen)

        # Screens like ButtonListScreen render once; QR/animation screens render many
        # frames. Keep only the first frame of each contiguous screen.
        if name == self._current_screen:
            return
        self._current_screen = name

        frames = self.session.renderer.frames
        if not frames:
            return
        frame = frames[-1].copy()

        out = docs_out_dir()
        if out is None:
            return

        _TOPIC_COUNTS[self.topic] = _TOPIC_COUNTS.get(self.topic, 0) + 1
        filename = f"{_TOPIC_COUNTS[self.topic]:02d}_{name}.png"
        (out / self.topic / filename).parent.mkdir(parents=True, exist_ok=True)
        frame.save(out / self.topic / filename)
        self.saved.append(filename)


def save_frame(topic: str, name: str, frame) -> None:
    """Save a single explicit frame (e.g. one a test selected from a flow)."""
    out = docs_out_dir()
    if out is None:
        return
    _reset_topic(topic)
    _TOPIC_COUNTS[topic] = _TOPIC_COUNTS.get(topic, 0) + 1
    filename = f"{_TOPIC_COUNTS[topic]:02d}_{name}.png"
    (out / topic).mkdir(parents=True, exist_ok=True)
    frame.save(out / topic / filename)
