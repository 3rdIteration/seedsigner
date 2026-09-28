"""SeedSigner OS is recognised by its marker, not by the hostname."""
# Must import base before any seedsigner modules
from base import BaseTest

from seedsigner.models.settings import Settings
from seedsigner.views import microsd_views


class TestTheOSIsTheMarkerNotTheHostname(BaseTest):

    def test_flash_images_dir_follows_the_os_marker(self, monkeypatch, tmp_path):
        monkeypatch.setattr("platform.uname", lambda: ("Linux", "luckfox", "", "", "", ""))
        monkeypatch.setattr(Settings, "is_seedsigner_os", classmethod(lambda cls: True))
        monkeypatch.setattr(microsd_views, "resolve_microsd_images_dir", lambda: tmp_path)

        assert microsd_views.flash_images_dir() == tmp_path
