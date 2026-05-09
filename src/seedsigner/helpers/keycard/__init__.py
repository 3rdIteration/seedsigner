"""Status Keycard protocol helpers (APDU builders, secure channel,
pairing storage, signing glue).
"""


class KeycardCardChangedError(Exception):
    """Raised by ``open_unlocked_session`` when the inserted card has no
    pairing in the in-memory cache for this boot.

    Carries ``instance_uid`` so the UI can surface it (e.g. "Pair this
    card first") and route to ``ToolsKeycardPairView``.
    """

    def __init__(self, instance_uid: bytes, message: str = "card not paired in this session"):
        super().__init__(message)
        self.instance_uid = bytes(instance_uid) if instance_uid is not None else b""


__all__ = ["KeycardCardChangedError"]
