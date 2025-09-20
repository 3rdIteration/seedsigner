from datetime import datetime, timedelta
from unittest.mock import patch, Mock

from base import BaseTest
from seedsigner.views import tools_views


class TestGpgTimeUpdate(BaseTest):
    def test_future_key_resets_timers(self):
        view = tools_views.ToolsGPGImportPubkeyMenuView()
        future_dt = datetime.now() + timedelta(days=1)
        fake_key = Mock(created=future_dt)
        with patch.object(view, "run_screen", return_value=0), \
             patch("pgpy.PGPKey.from_blob", return_value=(fake_key, None)), \
             patch("subprocess.run") as mock_run, \
             patch.object(view.controller, "reset_screensaver_timeout") as mock_reset:
            tools_views._check_future_key_creation(view, "dummy")
            assert mock_run.called
            assert mock_reset.called
