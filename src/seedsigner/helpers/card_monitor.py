"""Background PC/SC card-event observer.

Listens for card insertion / removal across all readers via pyscard's
``CardMonitor`` singleton and dispatches the events to ``Controller``
callbacks. Removal wipes every cached card secret in RAM (Keycard PINs
and the Satochip/SeedKeeper session) so a card swap or yank cannot leak
PINs through a still-running session.

The module is deliberately card-agnostic and lives outside ``keycard/``
because it serves Keycard, Satochip, SeedKeeper, and any future card
backend equally. It does NOT import from ``seedsigner.models.seed*`` —
no seed material flows through this thread of execution.

Threat model:

* Removal events MUST run regardless of whether the UI is responsive.
  We therefore avoid acquiring the ``Renderer.lock`` and write directly
  to ``Controller`` attributes.
* The CardMonitor thread is owned by pyscard; we only attach an
  observer. The thread is a daemon and dies with the process.
* ``CardMonitor`` is a singleton — if pysatochip / other code already
  holds a reference, our observer attaches in addition. No conflict.
* ATR / reader_name are deliberately NOT logged (would fingerprint the
  card to anyone reading the device's logs).
"""

from __future__ import annotations

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)


# Window in which a "removed" event will be cancelled by a matching
# "inserted" on the same reader. Long enough to absorb typical contact
# bounce on ACR1252U/PN532 (~50–150 ms observed) without masking real
# card swaps (mechanically >500 ms). Tuned conservatively; raise only
# if real-world hardware shows longer bounce traces.
REMOVAL_DEBOUNCE_S = 0.25


class _RemovalDebouncer:
    """Coalesces spurious ``removed`` events from PC/SC drivers.

    Some readers briefly fire ``removed`` then ``added`` for the same
    card during a normal insertion (contact bounce). Without debouncing,
    the user sees a "Card removed" toast in the middle of inserting
    their card, plus any registered removal listener fires uselessly.

    Indexed by ``reader_name`` so two reader slots in parallel can't
    cancel each other. ``None`` is treated as a single anonymous slot.
    Timers are daemon threads so the process can exit cleanly.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._timers: dict = {}

    def schedule(self, reader_name, callback, delay: float = REMOVAL_DEBOUNCE_S) -> None:
        with self._lock:
            existing = self._timers.pop(reader_name, None)
            if existing is not None:
                existing.cancel()
            timer = threading.Timer(delay, self._fire, args=(reader_name, callback))
            timer.daemon = True
            self._timers[reader_name] = timer
            timer.start()

    def cancel(self, reader_name) -> None:
        with self._lock:
            existing = self._timers.pop(reader_name, None)
        if existing is not None:
            existing.cancel()

    def cancel_all(self) -> None:
        with self._lock:
            timers = list(self._timers.values())
            self._timers.clear()
        for timer in timers:
            timer.cancel()

    def _fire(self, reader_name, callback) -> None:
        # Drop our reference before calling so a callback that re-enters
        # schedule()/cancel() sees a clean slot.
        with self._lock:
            self._timers.pop(reader_name, None)
        try:
            callback()
        except Exception:
            logger.exception("debounced card-removed callback failed")


class _PinWipingObserver:
    """``smartcard.CardMonitoring.CardObserver`` subclass that routes
    events to the controller. Defined as a plain class so the module
    imports cleanly when ``smartcard`` is mocked in tests; the real
    base class is mixed in lazily inside :func:`start_card_monitor`.

    The wipe of cached card secrets runs immediately on every ``removed``
    event (defensive — see :meth:`Controller.wipe_card_session_secrets`).
    The user-visible toast and removal-listener fan-out are deferred via
    a :class:`_RemovalDebouncer` so a quick re-insertion cancels both.
    """

    def __init__(self, controller):
        self._controller = controller
        self._removal_debouncer = _RemovalDebouncer()

    def update(self, observable, handlers) -> None:
        # ``handlers`` is ``(addedcards, removedcards)`` per pyscard.
        try:
            added, removed = handlers
        except (TypeError, ValueError):
            return
        for card in removed or []:
            try:
                reader_name = getattr(card, "reader", None)
                # Defensive wipe runs no matter what: a glitch costs the
                # user one extra PIN entry; skipping a real wipe leaks
                # secrets across cards.
                try:
                    self._controller.wipe_card_session_secrets()
                except Exception:
                    logger.exception("wipe_card_session_secrets failed")
                # Defer the visible event. A matching ``added`` on the
                # same reader within REMOVAL_DEBOUNCE_S cancels it.
                ctrl = self._controller
                self._removal_debouncer.schedule(
                    reader_name,
                    lambda r=reader_name: ctrl.dispatch_card_removed_event(r),
                )
            except Exception:
                logger.exception("on_card_removed callback failed")
        for card in added or []:
            try:
                reader_name = getattr(card, "reader", None)
                # Suppress any pending removal dispatch for this reader
                # — the card came back before we'd reported it gone.
                self._removal_debouncer.cancel(reader_name)
                atr_attr = getattr(card, "atr", None)
                atr = bytes(atr_attr) if atr_attr else b""
                self._controller.on_card_inserted(atr, reader_name)
            except Exception:
                logger.exception("on_card_inserted callback failed")


def start_card_monitor(controller) -> Optional[object]:
    """Register a card observer with pyscard's ``CardMonitor`` singleton.

    Returns the observer instance on success, or ``None`` if the
    smartcard stack is unavailable (e.g. during unit tests with a
    mocked ``smartcard`` module). The returned handle should be passed
    to :func:`stop_card_monitor` at shutdown.
    """
    try:
        from smartcard.CardMonitoring import CardMonitor, CardObserver
    except Exception:
        logger.info("smartcard.CardMonitoring unavailable; card monitor disabled")
        return None

    # When the test harness replaces ``smartcard`` with a ``MagicMock``,
    # ``CardObserver`` is itself a Mock instance whose metaclass forbids
    # subclassing. Detect that and fall back to a no-op observer.
    if not isinstance(CardObserver, type):
        logger.info("smartcard.CardObserver is mocked; card monitor disabled")
        return None

    # Build a real ``CardObserver`` subclass at runtime so we can ship
    # this module even when ``smartcard`` is a MagicMock at import time.
    try:
        class _Observer(_PinWipingObserver, CardObserver):  # type: ignore[misc]
            def __init__(self, ctrl):
                CardObserver.__init__(self)
                _PinWipingObserver.__init__(self, ctrl)
    except TypeError:
        logger.exception("could not subclass CardObserver; card monitor disabled")
        return None

    try:
        observer = _Observer(controller)
        CardMonitor().addObserver(observer)
        return observer
    except Exception:
        logger.exception("could not register CardMonitor observer")
        return None


def stop_card_monitor(observer) -> None:
    """Detach an observer previously returned by :func:`start_card_monitor`."""
    if observer is None:
        return
    try:
        from smartcard.CardMonitoring import CardMonitor
        CardMonitor().deleteObserver(observer)
    except Exception:
        logger.exception("could not detach CardMonitor observer")
