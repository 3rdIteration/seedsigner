"""SeedKeeper descriptor save/load regression tests.

Two regressions that the hardware (card-present) suite never exercised:

* #416 — ToolsSeedkeeperSaveDescriptorView read back an existing V2 "Descriptor"
  secret with a hard-coded 1-byte length strip; V2 Descriptor secrets are stored
  with a 2-byte prefix, so the low length byte was left as the first content
  byte and produced ``'utf-8' codec can't decode byte 0xc0``.
* #413 — ensure_seedkeeper_capacity() unconditionally queried the Seedkeeper
  status (INS 0xA7); applets that answer 0x6D00 ("instruction not supported")
  would block every write instead of allowing the card to reject an
  out-of-memory import itself.

These use a mocked connector so they run in CI without hardware.
"""

import base
from embit.descriptor import Descriptor
from unittest.mock import MagicMock

from seedsigner.controller import Controller
from seedsigner.gui.screens import seed_screens
from seedsigner.views import smartcard_views
from seedsigner.helpers import seedkeeper_utils
from seedsigner.views.smartcard_views import ToolsSeedkeeperSaveDescriptorView


# A valid two-key multisig descriptor so embit can parse it; the stored text is
# derived from the Descriptor object so the duplicate-skip comparison is
# deterministic. It must be long enough (> ~128 bytes) that the 2-byte length
# prefix's low byte is non-ASCII (>= 0x80) — otherwise the OLD buggy [1:] strip
# would coincidentally decode as printable ASCII and not reproduce #416.
DESCRIPTOR_STRING = (
    "wsh(sortedmulti(1,"
    "[22bde1a9/48h/1h/0h/2h]"
    "tpubDFfsBrmpj226ZYiRszYi2qK6iGvh2vkkghfGB2YiRUVY4rqqedHCFEgw12FwDkm7rUoVtq9wLTKc6BN2sxswvQeQgp7m8st4FP8WtP8go76/{0,1}/*,"
    "[73c5da0a/48h/1h/0h/2h]"
    "tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/{0,1}/*))"
    "#3jhtf6yx"
)


def _fresh_controller_with_descriptor():
    base.BaseTest.reset_controller()
    base.BaseTest.reset_settings()
    controller = Controller.get_instance()
    controller.multisig_wallet_descriptor = Descriptor.from_string(DESCRIPTOR_STRING)
    return controller


def test_seedkeeper_save_descriptor_reads_back_v2_without_crashing(monkeypatch):
    """Regression for #416.

    The view must be able to read back an already-stored V2 "Descriptor" secret
    (2-byte length prefix) without crashing on the utf-8 decode, and therefore
    detect it as a duplicate and skip re-importing it.
    """
    desc = _fresh_controller_with_descriptor().multisig_wallet_descriptor
    stored_text = desc.to_string()
    stored_len = len(stored_text.encode("utf-8"))
    stored_payload = list(stored_len.to_bytes(2, "big")) + list(stored_text.encode("utf-8"))

    class FakeLabelScreen:
        def __init__(self, **kwargs):
            pass

        def display(self):
            return {"passphrase": "mydesc"}

    class FakeConnector:
        def __init__(self):
            self.imported = []
            self.exported = []

        def card_get_status(self):
            return (None, None, None, {"protocol_minor_version": 2})

        def seedkeeper_list_secret_headers(self):
            return [
                {
                    "id": 0x0001,
                    "type": 0xC1,  # Descriptor (V2)
                    "subtype": 0x00,
                    "label": "mydesc",
                    "origin": 0x01,
                    "export_rights": 0x01,
                    "export_nbplain": 0,
                    "export_nbsecure": 0,
                    "export_counter": 0,
                    "fingerprint": b"\x00\x00\x00\x00",
                }
            ]

        def seedkeeper_export_secret(self, sid, _pubkey):
            # Round-trip exactly what the save view writes (2-byte prefix).
            self.exported.append(sid)
            return {"secret": bytes(stored_payload).hex(), "secret_list": stored_payload}

        def make_header(self, secret_type, export_rights, label):
            return "00" * 20

        def seedkeeper_import_secret(self, secret_dic):
            self.imported.append(secret_dic)
            return (0x0002, "00" * 4)

        def seedkeeper_get_status(self):
            return (None, None, None, {"free_memory": 4096})

    fake = FakeConnector()

    # pysatochip is mocked in the unit-test env, so the constants imported by the
    # view are MagicMocks and the 0xC1 -> "Descriptor" classification would fail.
    # Provide the real (minimal) mappings so the header is treated as a V2
    # Descriptor, mirroring the runtime behaviour.
    monkeypatch.setattr(smartcard_views, "SEEDKEEPER_DIC_TYPE", {0xC0: "Data", 0xC1: "Descriptor"})
    monkeypatch.setattr(
        smartcard_views,
        "SEEDKEEPER_DIC_EXPORT_RIGHTS",
        {0x01: "Plaintext export allowed"},
    )
    monkeypatch.setattr(
        smartcard_views,
        "SEEDKEEPER_DIC_ORIGIN",
        {0x01: "Plaintext import"},
    )
    monkeypatch.setattr(seedkeeper_utils, "init_satochip", lambda *a, **k: fake)
    monkeypatch.setattr(seed_screens, "SeedAddPassphraseScreen", FakeLabelScreen)
    monkeypatch.setattr("seedsigner.gui.screens.screen.LoadingScreenThread", MagicMock)
    shown_screens = []
    monkeypatch.setattr(
        ToolsSeedkeeperSaveDescriptorView,
        "run_screen",
        lambda self, screen, *a, **k: shown_screens.append(screen),
    )

    view = ToolsSeedkeeperSaveDescriptorView()
    view.run()

    # The pre-existing V2 Descriptor was read back (exported) without a utf-8
    # crash, and since it matches the descriptor being saved it was skipped. The
    # view must reach its success screen, NOT an error screen (the outer
    # try/except swallows a decode failure into an "Error" WarningScreen).
    assert fake.exported == [0x0001]
    assert fake.imported == []
    assert smartcard_views.LargeIconStatusScreen in shown_screens
    assert smartcard_views.WarningScreen not in shown_screens


def test_seedkeeper_ensure_capacity_tolerates_unsupported_status(monkeypatch):
    """Regression for #413.

    A Seedkeeper applet that does not implement the status command (INS 0xA7,
    answered 0x6D00) must not block writes. The capacity pre-check should treat
    the import as fitting and let the card reject an out-of-memory import with
    its own error instead.
    """

    class UnsupportedStatusError(Exception):
        pass

    # The function catches `UnexpectedSW12Error` by module-global name; in the
    # mocked-pysatochip test env that symbol is a MagicMock (not a real exception
    # class), so substitute a real exception class for the test.
    monkeypatch.setattr(seedkeeper_utils, "UnexpectedSW12Error", UnsupportedStatusError)

    class StatusUnsupportedConnector:
        def seedkeeper_get_status(self):
            raise UnsupportedStatusError(
                "Error while fetching SeedKeeper status: (error code 0x6d00)"
            )

    header_hex = ("00" * 2 + "900101" + "000000" + "00000000" + "0000" + "04") + "74657374"
    # id(2) + type/origin/export(3) + export_counters(3) + fingerprint(4) + rfu(2) + label_size(1) + label(4)
    secret_dic = {"header": header_hex, "secret_list": [len(b"secret")] + list(b"secret")}

    fits, required_bytes, free_bytes = seedkeeper_utils.ensure_seedkeeper_capacity(
        StatusUnsupportedConnector(), secret_dic
    )

    assert fits is True
    assert required_bytes > 0
    assert free_bytes is None
