"""UI authorization/lifecycle tests; hardware and OS protocol independently tested."""
from types import SimpleNamespace
from unittest.mock import MagicMock
import pytest
import base  # repository hardware/renderer test doubles
from seedsigner.views import forgebox_views as views
from seedsigner.views.view import BackStackView
from seedsigner.gui.screens import RET_CODE__BACK_BUTTON
from seedsigner.models.seed import Seed, XprvSeed
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.helpers import forgebox_tools


def make_view(monkeypatch, action='sign', seed=None):
    request = dict(action='firmware', name='test.bin', original_size=123,
                   original_hash='aa'*32, compressed_hash='bb'*32, public_key='04'+'11'*64)
    tools = MagicMock()
    tools.read_json.return_value = request
    tools.validate_request.side_effect = lambda value: value
    tools.public_hex.return_value = request['public_key']
    tools.fingerprint.return_value = 'cc'*32
    tools.sign_request.return_value = {'signatures':['public signature']}
    monkeypatch.setattr(forgebox_tools, 'load', lambda: tools)
    monkeypatch.setattr(views.MicroSD, 'get_microsd_dir', lambda: '/test-card')
    view = object.__new__(views.ToolsForgeBoxRunView)
    view.action = action
    view.controller = SimpleNamespace(storage=SimpleNamespace(seeds=[seed or MagicMock()]))
    view.settings = MagicMock()
    view.settings.get_value.return_value = SettingsConstants.MAINNET
    text = []
    view.show_text = lambda title, message: text.append((title, message)) or True
    calls = []
    def screen(kind, **kwargs):
        calls.append((kind, kwargs))
        return '0' if kind is views.SeedBIP85SelectChildIndexScreen else 0
    view.run_screen = screen
    return view, tools, request, calls, text


@pytest.mark.parametrize('xprv', [False, True])
def test_sign_with_bip39_and_xprv_uses_get_root(monkeypatch, xprv):
    seed = Seed(mnemonic=['abandon']*11+['about'])
    if xprv:
        seed = XprvSeed(seed.get_root().to_base58())
        assert seed.seed_bytes is None
    view, tools, request, calls, text = make_view(monkeypatch, seed=seed)
    result = view.run()
    assert result.View_cls is views.ToolsForgeBoxMenuView
    assert tools.key_from_root.call_args.args[0].to_base58() == seed.get_root(SettingsConstants.MAINNET).to_base58()
    assert tools.key_from_root.call_args.args[1] == 0
    tools.sign_request.assert_called_once_with(request, tools.key_from_root.return_value)
    tools.write_json.assert_called_once_with('/test-card', 'response.json', tools.sign_request.return_value)
    assert calls[-1][1]['button_data'][0].button_label == 'Sign'
    assert not hasattr(view.controller, 'forgebox_key')


@pytest.mark.parametrize('stop_at', range(4))
def test_back_at_every_input_stops_signing(monkeypatch, stop_at):
    view, tools, request, calls, text = make_view(monkeypatch)
    real_screen = view.run_screen
    count = [0]
    def screen(kind, **kwargs):
        i = count[0]
        count[0] += 1
        return RET_CODE__BACK_BUTTON if i == stop_at else real_screen(kind, **kwargs)
    view.run_screen = screen
    assert view.run().View_cls is BackStackView
    tools.sign_request.assert_not_called()
    tools.write_json.assert_not_called()


def test_cancel_hash_or_public_review_and_wrong_key(monkeypatch):
    for cancel_at in (0, 1):
        view, tools, request, calls, text = make_view(monkeypatch)
        count = [0]
        def review(*args):
            value = count[0] != cancel_at
            count[0] += 1
            return value
        view.show_text = review
        assert view.run().View_cls is BackStackView
        tools.sign_request.assert_not_called()
    view, tools, request, calls, text = make_view(monkeypatch)
    tools.public_hex.return_value = 'different key'
    assert view.run().View_cls is BackStackView
    tools.sign_request.assert_not_called()


def test_export_and_failure_do_not_export_private_key(monkeypatch):
    view, tools, request, calls, text = make_view(monkeypatch, action='export')
    assert view.run().View_cls is views.ToolsForgeBoxMenuView
    tools.read_json.assert_not_called()
    tools.export_public.assert_called_once()
    tools.sign_request.assert_not_called()
    view, tools, request, calls, text = make_view(monkeypatch)
    tools.sign_request.side_effect = ValueError('sensitive exception must not reach UI')
    assert view.run().View_cls is views.ToolsForgeBoxMenuView
    tools.write_json.assert_not_called()
    assert all('sensitive exception' not in message for _, message in text)


def test_missing_seed_and_registration_review(monkeypatch):
    view, tools, request, calls, text = make_view(monkeypatch)
    view.controller.storage.seeds = []
    assert view.run().View_cls is BackStackView
    tools.key_from_root.assert_not_called()
    view, tools, request, calls, text = make_view(monkeypatch)
    request.update(action='register', legacy=False, nonce='ab'*32)
    assert view.run().View_cls is views.ToolsForgeBoxMenuView
    assert 'lifetime' in calls[0][1]['text']
    assert any('Nonce' in message for _, message in text)


def test_missing_os_tools_hidden_and_loader_refuses(monkeypatch):
    monkeypatch.setattr(forgebox_tools, 'candidate_dirs', lambda: [])
    assert not forgebox_tools.is_available()
    with pytest.raises(RuntimeError, match='not installed'):
        forgebox_tools.load()
