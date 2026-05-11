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


class KeycardNotInitialisedError(Exception):
    """Raised when the SELECT response is the pre-init template (tag 0x80).

    The applet is loaded on the card but has never run INIT — there is no
    PIN, PUK, pairing secret or master key. UI must route the user to the
    Initialise blank card flow.
    """


class KeycardNoMasterKeyError(Exception):
    """Raised by ``open_unlocked_session`` when SELECT reports an empty
    ``key_uid`` — the applet is initialised (PIN/PUK/pairing-secret set)
    but no master key has been generated or imported yet.

    The UI must route the user to ``Generate key`` or ``Import seed``.
    Detecting this up-front prevents derive/export operations from
    returning the cryptic SW=0x6985 inside the secure channel.
    """

    def __init__(self, instance_uid: bytes, message: str = "no master key on card"):
        super().__init__(message)
        self.instance_uid = bytes(instance_uid) if instance_uid is not None else b""


class KeycardPinRequiredError(Exception):
    """Raised by ``open_unlocked_session`` when the caller did not supply a
    PIN and no cached PIN exists for the inserted card. The view layer
    should prompt the user for the PIN and call ``open_unlocked_session``
    again with the captured value.
    """

    def __init__(self, instance_uid: bytes, message: str = "PIN required"):
        super().__init__(message)
        self.instance_uid = bytes(instance_uid) if instance_uid is not None else b""


class KeycardPinPromptCancelled(Exception):
    """Raised by ``open_unlocked_session_cached_or_prompt`` when the user
    backs out of the PIN keyboard. The view should treat this as a
    BackStackView redirect.
    """


__all__ = [
    "KeycardCardChangedError",
    "KeycardNotInitialisedError",
    "KeycardNoMasterKeyError",
    "KeycardPinRequiredError",
    "KeycardPinPromptCancelled",
]
