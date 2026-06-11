import pytest

from seedsigner.views import tools_views


def test_normalize_bip39_mnemonic_text_normalizes_whitespace():
    text = (
        " Abandon   abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon abandon abandon ART "
    )
    normalized = tools_views._normalize_bip39_mnemonic_text(text)
    assert normalized.startswith("abandon abandon")
    assert normalized.endswith("art")
    assert len(normalized.split(" ")) == 24


def test_normalize_bip39_mnemonic_text_rejects_invalid_word_count():
    with pytest.raises(ValueError):
        tools_views._normalize_bip39_mnemonic_text("abandon " * 11)


def test_javacard_keys_menu_routes_to_load_mnemonic():
    view = object.__new__(tools_views.ToolsJavacardKeysView)

    def fake_run_screen(*args, **kwargs):
        for i, option in enumerate(kwargs["button_data"]):
            if option.button_label == "Load Mnemonic":
                return i
        return 0

    view.run_screen = fake_run_screen
    destination = view.run()

    assert destination.View_cls == tools_views.ToolsJavacardLoadMnemonicView


def test_javacard_keys_menu_routes_to_save_mnemonic():
    view = object.__new__(tools_views.ToolsJavacardKeysView)

    def fake_run_screen(*args, **kwargs):
        for i, option in enumerate(kwargs["button_data"]):
            if option.button_label == "Save Mnemonic":
                return i
        return 0

    view.run_screen = fake_run_screen
    destination = view.run()

    assert destination.View_cls == tools_views.ToolsJavacardSaveMnemonicView


def test_specter_menu_routes_to_wipe_seed():
    view = object.__new__(tools_views.ToolsSpecterDIYView)

    def fake_run_screen(*args, **kwargs):
        for i, option in enumerate(kwargs["button_data"]):
            if option.button_label == "Wipe Seed":
                return i
        return 0

    view.run_screen = fake_run_screen
    destination = view.run()

    assert destination.View_cls == tools_views.ToolsJavacardWipeMnemonicView


def test_javacard_load_mnemonic_decodes_sdiy_blob(monkeypatch):
    class FakeLoadingScreenThread:
        def __init__(self, text):
            self.text = text

        def start(self):
            pass

        def stop(self):
            pass

    class FakeStorage:
        def __init__(self):
            self.words = []
            self.word_count = None

        def init_pending_mnemonic(self, num_words):
            self.word_count = num_words

        def update_pending_mnemonic(self, word, index):
            self.words.append((index, word))

        def convert_pending_mnemonic_to_pending_seed(self, wordlist_language_code):
            self.wordlist_language_code = wordlist_language_code

    class FakeController:
        def __init__(self):
            self.storage = FakeStorage()

    class FakeSettings:
        def get_value(self, _key):
            return "en"

    class FakeSecureChannel:
        def close(self):
            pass

    class FakeCard:
        def __init__(self, _aid):
            pass

        def connect(self):
            pass

        def disconnect(self):
            pass

    class FakeSecureApplet:
        def __init__(self, _conn):
            pass

        def open_secure_channel(self):
            return FakeSecureChannel()

    class FakeMemoryCardApplet:
        def __init__(self, _conn):
            pass

        def get_data(self, _secure_channel):
            return bytes.fromhex("097364697900000000009b")

        def decode_diy_data(self, _secure_channel):
            return {
                "encrypted": False,
                "mnemonic": (
                    "stock million price success you push rifle embrace "
                    "tone limb december isolate"
                ),
            }

    import seedsigner.gui.screens.screen as screen_module

    monkeypatch.setattr(screen_module, "LoadingScreenThread", FakeLoadingScreenThread)
    monkeypatch.setattr(
        tools_views,
        "_get_specter_card_api",
        lambda: (FakeCard, FakeMemoryCardApplet, FakeSecureApplet),
    )
    monkeypatch.setattr(tools_views, "_unlock_specter_card_if_needed", lambda *a, **k: True)

    view = object.__new__(tools_views.ToolsJavacardLoadMnemonicView)
    view.controller = FakeController()
    view.settings = FakeSettings()
    view.run_screen = lambda *args, **kwargs: None

    destination = view.run()

    assert destination.View_cls == tools_views.SeedFinalizeView
    assert view.controller.storage.word_count == 12
    assert [word for _, word in sorted(view.controller.storage.words)] == [
        "stock",
        "million",
        "price",
        "success",
        "you",
        "push",
        "rifle",
        "embrace",
        "tone",
        "limb",
        "december",
        "isolate",
    ]


def test_specter_change_pin_prompts_current_then_new_only(monkeypatch):
    prompts = []
    changed = {}

    class FakePrompt:
        def __init__(self, title):
            self.title = title

        def display(self):
            prompts.append(self.title)
            if self.title == "Current PIN":
                return {"passphrase": "1234"}
            if self.title == "New PIN":
                return {"passphrase": "9999"}
            return {"passphrase": ""}

    class FakeSecureChannel:
        def close(self):
            pass

    class FakeCard:
        def __init__(self, _aid):
            pass

        def connect(self):
            pass

        def disconnect(self):
            pass

    class FakeSecureApplet:
        def __init__(self, _conn):
            pass

        def open_secure_channel(self):
            return FakeSecureChannel()

        def pin_status(self, _secure_channel):
            return {"status": "locked"}

        def change_pin(self, _secure_channel, old_pin, new_pin):
            changed["old"] = old_pin
            changed["new"] = new_pin

    class FakeMemoryCardApplet:
        def __init__(self, _conn):
            pass

    monkeypatch.setattr(
        tools_views,
        "_get_specter_card_api",
        lambda: (FakeCard, FakeMemoryCardApplet, FakeSecureApplet),
    )
    monkeypatch.setattr(tools_views.seed_screens, "SeedAddPassphraseScreen", FakePrompt)

    view = object.__new__(tools_views.ToolsSpecterDIYChangePinView)
    view.run_screen = lambda *args, **kwargs: 0

    destination = view.run()

    assert destination.View_cls == tools_views.BackStackView
    assert prompts == ["Current PIN", "New PIN"]
    assert changed == {"old": b"1234", "new": b"9999"}


def test_unlock_specter_card_shows_bricked_reinstall_warning():
    class FakeParentView:
        def __init__(self):
            self.calls = []

        def run_screen(self, _screen, **kwargs):
            self.calls.append(kwargs)
            return 0

    class FakeSecureApplet:
        def pin_status(self, _secure_channel):
            return {"status": "bricked"}

    parent = FakeParentView()
    unlocked = tools_views._unlock_specter_card_if_needed(
        parent,
        FakeSecureApplet(),
        secure_channel=object(),
    )

    assert unlocked is False
    assert len(parent.calls) == 1
    assert parent.calls[0]["title"] == "Card Locked"
    assert "Reinstall Specter-DIY applet" in parent.calls[0]["text"]
    assert "No factory reset available" in parent.calls[0]["text"]


def test_prompt_specter_new_pin_warns_and_can_continue(monkeypatch):
    prompts = iter([
        {"passphrase": "12ab"},
    ])

    class FakePrompt:
        def __init__(self, title):
            self.title = title

        def display(self):
            return next(prompts)

    class FakeParentView:
        def __init__(self):
            self.calls = []

        def run_screen(self, _screen, **kwargs):
            self.calls.append(kwargs)
            return 0

    monkeypatch.setattr(tools_views.seed_screens, "SeedAddPassphraseScreen", FakePrompt)
    parent = FakeParentView()

    pin = tools_views._prompt_specter_new_pin(parent, "New PIN")

    assert pin == "12ab"
    assert len(parent.calls) == 1
    assert parent.calls[0]["title"] == "Non-Numeric PIN"
    assert "digits 0-9" in parent.calls[0]["text"]


def test_prompt_specter_new_pin_warns_and_can_reenter(monkeypatch):
    prompts = iter([
        {"passphrase": "12ab"},
        {"passphrase": "1234"},
    ])

    class FakePrompt:
        def __init__(self, title):
            self.title = title

        def display(self):
            return next(prompts)

    class FakeParentView:
        def __init__(self):
            self.calls = []

        def run_screen(self, _screen, **kwargs):
            self.calls.append(kwargs)
            return 1

    monkeypatch.setattr(tools_views.seed_screens, "SeedAddPassphraseScreen", FakePrompt)
    parent = FakeParentView()

    pin = tools_views._prompt_specter_new_pin(parent, "New PIN")

    assert pin == "1234"
    assert len(parent.calls) == 1
    assert parent.calls[0]["title"] == "Non-Numeric PIN"


def test_unlock_specter_card_wrong_pin_shows_attempts_remaining():
    class FakeParentView:
        def __init__(self):
            self.calls = []

        def run_screen(self, _screen, **kwargs):
            self.calls.append(kwargs)
            return 0

    class FakeSecureApplet:
        def __init__(self):
            self._status_calls = 0

        def pin_status(self, _secure_channel):
            self._status_calls += 1
            if self._status_calls == 1:
                return {"status": "locked", "attempts_left": 5}
            return {"status": "locked", "attempts_left": 4}

        def unlock(self, _secure_channel, _pin):
            raise Exception("Secure channel error: 0502")

    class FakePrompt:
        def __init__(self, title):
            self.title = title

        def display(self):
            return {"passphrase": "0000"}

    parent = FakeParentView()
    secure_applet = FakeSecureApplet()

    original = tools_views.seed_screens.SeedAddPassphraseScreen
    tools_views.seed_screens.SeedAddPassphraseScreen = FakePrompt
    try:
        unlocked = tools_views._unlock_specter_card_if_needed(
            parent,
            secure_applet,
            secure_channel=object(),
        )
    finally:
        tools_views.seed_screens.SeedAddPassphraseScreen = original

    assert unlocked is False
    assert len(parent.calls) == 1
    assert parent.calls[0]["title"] == "Incorrect PIN"
    assert "4 attempts remaining" in parent.calls[0]["text"]


def test_javacard_save_mnemonic_prompts_before_overwrite_and_can_abort(monkeypatch):
    class FakeLoadingScreenThread:
        def __init__(self, text):
            self.text = text

        def start(self):
            pass

        def stop(self):
            pass

    class FakeSeed:
        mnemonic_list = [
            "stock", "million", "price", "success", "you", "push",
            "rifle", "embrace", "tone", "limb", "december", "isolate",
        ]

        def get_fingerprint(self, _network):
            return "f00dbabe"

    class FakeStorage:
        def __init__(self):
            self.seeds = [FakeSeed()]

    class FakeController:
        def __init__(self):
            self.storage = FakeStorage()

    class FakeSettings:
        def get_value(self, _key):
            return "main"

    class FakeSecureChannel:
        def close(self):
            pass

    class FakeCard:
        def __init__(self, _aid):
            pass

        def connect(self):
            pass

        def disconnect(self):
            pass

    class FakeSecureApplet:
        def __init__(self, _conn):
            pass

        def open_secure_channel(self, mode=None):
            _ = mode
            return FakeSecureChannel()

        def pin_status(self, _secure_channel):
            return {"status": "locked"}

    stored = {"called": False}

    class FakeMemoryCardApplet:
        def __init__(self, _conn):
            pass

        def get_data(self, _secure_channel):
            return b"already-there"

        def store_data(self, _secure_channel, _payload):
            stored["called"] = True

    import seedsigner.gui.screens.screen as screen_module

    monkeypatch.setattr(screen_module, "LoadingScreenThread", FakeLoadingScreenThread)
    monkeypatch.setattr(tools_views, "Seed", FakeSeed)
    monkeypatch.setattr(
        tools_views,
        "_get_specter_card_api",
        lambda: (FakeCard, FakeMemoryCardApplet, FakeSecureApplet),
    )
    monkeypatch.setattr(tools_views, "_unlock_specter_card_if_needed", lambda *a, **k: True)

    prompts = []

    def fake_run_screen(*args, **kwargs):
        prompts.append(kwargs.get("title"))
        if kwargs.get("title") == "Overwrite Data?":
            return 1
        return 0

    view = object.__new__(tools_views.ToolsJavacardSaveMnemonicView)
    view.controller = FakeController()
    view.settings = FakeSettings()
    view.run_screen = fake_run_screen

    destination = view.run()

    assert destination.View_cls == tools_views.BackStackView
    assert "Overwrite Data?" in prompts
    assert stored["called"] is False


def test_javacard_save_mnemonic_overwrite_can_continue(monkeypatch):
    class FakeLoadingScreenThread:
        def __init__(self, text):
            self.text = text

        def start(self):
            pass

        def stop(self):
            pass

    class FakeSeed:
        mnemonic_list = [
            "stock", "million", "price", "success", "you", "push",
            "rifle", "embrace", "tone", "limb", "december", "isolate",
        ]

        def get_fingerprint(self, _network):
            return "f00dbabe"

    class FakeStorage:
        def __init__(self):
            self.seeds = [FakeSeed()]

    class FakeController:
        def __init__(self):
            self.storage = FakeStorage()

    class FakeSettings:
        def get_value(self, _key):
            return "main"

    class FakeSecureChannel:
        def close(self):
            pass

    class FakeCard:
        def __init__(self, _aid):
            pass

        def connect(self):
            pass

        def disconnect(self):
            pass

    class FakeSecureApplet:
        def __init__(self, _conn):
            pass

        def open_secure_channel(self, mode=None):
            _ = mode
            return FakeSecureChannel()

        def pin_status(self, _secure_channel):
            return {"status": "locked"}

    stored = {"called": False, "payload": None}

    class FakeMemoryCardApplet:
        def __init__(self, _conn):
            pass

        def get_data(self, _secure_channel):
            return b"already-there"

        def store_data(self, _secure_channel, payload):
            stored["called"] = True
            stored["payload"] = payload

    import seedsigner.gui.screens.screen as screen_module

    monkeypatch.setattr(screen_module, "LoadingScreenThread", FakeLoadingScreenThread)
    monkeypatch.setattr(tools_views, "Seed", FakeSeed)
    monkeypatch.setattr(
        tools_views,
        "_get_specter_card_api",
        lambda: (FakeCard, FakeMemoryCardApplet, FakeSecureApplet),
    )
    monkeypatch.setattr(tools_views, "_unlock_specter_card_if_needed", lambda *a, **k: True)

    def fake_run_screen(*args, **kwargs):
        if kwargs.get("title") == "Overwrite Data?":
            return 0
        return 0

    view = object.__new__(tools_views.ToolsJavacardSaveMnemonicView)
    view.controller = FakeController()
    view.settings = FakeSettings()
    view.run_screen = fake_run_screen

    destination = view.run()

    assert destination.View_cls == tools_views.BackStackView
    assert stored["called"] is True
    assert isinstance(stored["payload"], bytes)


def test_javacard_save_mnemonic_empty_card_prompts_create_pin(monkeypatch):
    class FakeLoadingScreenThread:
        def __init__(self, text):
            self.text = text

        def start(self):
            pass

        def stop(self):
            pass

    class FakeSeed:
        mnemonic_list = [
            "stock", "million", "price", "success", "you", "push",
            "rifle", "embrace", "tone", "limb", "december", "isolate",
        ]

        def get_fingerprint(self, _network):
            return "f00dbabe"

    class FakeStorage:
        def __init__(self):
            self.seeds = [FakeSeed()]

    class FakeController:
        def __init__(self):
            self.storage = FakeStorage()

    class FakeSettings:
        def get_value(self, _key):
            return "main"

    class FakeSecureChannel:
        def close(self):
            pass

    class FakeCard:
        def __init__(self, _aid):
            pass

        def connect(self):
            pass

        def disconnect(self):
            pass

    class FakeSecureApplet:
        def __init__(self, _conn):
            self.set_pin_calls = []

        def open_secure_channel(self, mode=None):
            _ = mode
            return FakeSecureChannel()

        def pin_status(self, _secure_channel):
            return {"status": "no_pin"}

        def set_pin(self, _secure_channel, pin):
            self.set_pin_calls.append(pin)

    secure_applet_ref = {"instance": None}

    class FakeMemoryCardApplet:
        def __init__(self, _conn):
            pass

        def get_data(self, _secure_channel):
            return b""

        def store_data(self, _secure_channel, _payload):
            pass

    def fake_get_api():
        class _FakeSecureAppletFactory(FakeSecureApplet):
            def __init__(self, _conn):
                super().__init__(_conn)
                secure_applet_ref["instance"] = self

        return (FakeCard, FakeMemoryCardApplet, _FakeSecureAppletFactory)

    import seedsigner.gui.screens.screen as screen_module

    monkeypatch.setattr(screen_module, "LoadingScreenThread", FakeLoadingScreenThread)
    monkeypatch.setattr(tools_views, "Seed", FakeSeed)
    monkeypatch.setattr(tools_views, "_get_specter_card_api", fake_get_api)
    monkeypatch.setattr(tools_views, "_unlock_specter_card_if_needed", lambda *a, **k: True)

    prompt_titles = []

    def fake_prompt(parent, title):
        _ = parent
        prompt_titles.append(title)
        return "1234"

    monkeypatch.setattr(tools_views, "_prompt_specter_new_pin", fake_prompt)

    view = object.__new__(tools_views.ToolsJavacardSaveMnemonicView)
    view.controller = FakeController()
    view.settings = FakeSettings()
    view.run_screen = lambda *args, **kwargs: 0

    destination = view.run()

    assert destination.View_cls == tools_views.BackStackView
    assert prompt_titles == ["Create PIN"]
    assert secure_applet_ref["instance"].set_pin_calls == [b"1234"]


def test_javacard_save_mnemonic_empty_card_create_pin_cancel_aborts(monkeypatch):
    class FakeLoadingScreenThread:
        def __init__(self, text):
            self.text = text

        def start(self):
            pass

        def stop(self):
            pass

    class FakeSeed:
        mnemonic_list = [
            "stock", "million", "price", "success", "you", "push",
            "rifle", "embrace", "tone", "limb", "december", "isolate",
        ]

        def get_fingerprint(self, _network):
            return "f00dbabe"

    class FakeStorage:
        def __init__(self):
            self.seeds = [FakeSeed()]

    class FakeController:
        def __init__(self):
            self.storage = FakeStorage()

    class FakeSettings:
        def get_value(self, _key):
            return "main"

    class FakeSecureChannel:
        def close(self):
            pass

    class FakeCard:
        def __init__(self, _aid):
            pass

        def connect(self):
            pass

        def disconnect(self):
            pass

    class FakeSecureApplet:
        def __init__(self, _conn):
            self.set_pin_calls = []

        def open_secure_channel(self, mode=None):
            _ = mode
            return FakeSecureChannel()

        def pin_status(self, _secure_channel):
            return {"status": "no_pin"}

        def set_pin(self, _secure_channel, pin):
            self.set_pin_calls.append(pin)

    store_called = {"value": False}

    class FakeMemoryCardApplet:
        def __init__(self, _conn):
            pass

        def get_data(self, _secure_channel):
            return b""

        def store_data(self, _secure_channel, _payload):
            store_called["value"] = True

    monkeypatch.setattr(
        tools_views,
        "_get_specter_card_api",
        lambda: (FakeCard, FakeMemoryCardApplet, FakeSecureApplet),
    )
    monkeypatch.setattr(tools_views, "Seed", FakeSeed)
    monkeypatch.setattr(tools_views, "_unlock_specter_card_if_needed", lambda *a, **k: True)
    monkeypatch.setattr(tools_views, "_prompt_specter_new_pin", lambda *a, **k: None)

    import seedsigner.gui.screens.screen as screen_module
    monkeypatch.setattr(screen_module, "LoadingScreenThread", FakeLoadingScreenThread)

    view = object.__new__(tools_views.ToolsJavacardSaveMnemonicView)
    view.controller = FakeController()
    view.settings = FakeSettings()
    view.run_screen = lambda *args, **kwargs: 0

    destination = view.run()

    assert destination.View_cls == tools_views.BackStackView
    assert store_called["value"] is False


def test_prompt_keycard_new_pin_requires_numeric_and_6_digits():
    class FakeParentView:
        def __init__(self):
            self.calls = []

        def run_screen(self, _screen, **kwargs):
            self.calls.append(kwargs)
            return 0

    responses = iter([
        {"passphrase": "12ab56"},
        {"passphrase": "12345"},
        {"passphrase": "123456"},
    ])

    class FakePrompt:
        def __init__(self, title):
            self.title = title

        def display(self):
            return next(responses)

    parent = FakeParentView()
    original = tools_views.seed_screens.SeedAddPassphraseScreen
    tools_views.seed_screens.SeedAddPassphraseScreen = FakePrompt
    try:
        pin = tools_views._prompt_keycard_new_pin(parent, "New PIN")
    finally:
        tools_views.seed_screens.SeedAddPassphraseScreen = original

    assert pin == "123456"
    assert len(parent.calls) == 2
    assert parent.calls[0]["title"] == "Non-Numeric PIN"
    assert parent.calls[1]["title"] == "Invalid PIN Length"
