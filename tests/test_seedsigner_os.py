import os

from seedsigner.helpers.seedsigner_os import is_seedsigner_os_dev_build


def test_is_seedsigner_os_dev_build(monkeypatch):
    # Simulate developer OS by faking the presence of the indicator file.
    monkeypatch.setattr(os.path, "exists", lambda p: p == "/usr/bin/microsd_notice.py")
    assert is_seedsigner_os_dev_build()

    # Simulate non-developer OS where the file is absent.
    monkeypatch.setattr(os.path, "exists", lambda p: False)
    assert not is_seedsigner_os_dev_build()

