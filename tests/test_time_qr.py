from unittest.mock import patch

from base import BaseTest
from seedsigner.views import scan_views


class TestTimeQr(BaseTest):
    def test_time_qr_resets_timers(self):
        view = scan_views.ScanView()
        view.decoder.add_data("oT230906235204")
        with patch.object(view, "run_screen"), \
             patch("seedsigner.views.scan_views.MicroSD.is_desktop_mode", return_value=False), \
             patch("seedsigner.views.scan_views.subprocess.run") as mock_run, \
             patch.object(view.controller, "reset_screensaver_timeout") as mock_reset:
            view.run()
            assert mock_run.called
            # Should reset once after the scan completes and again after setting time
            assert mock_reset.call_count == 2
