"""
Tools → Chess on real Screens: moves typed with the joystick, the device's
reply, promotion, undo, the game menu, and a game played to checkmate.
"""
import threading
import time

import pytest

import base  # ensure hardware mocks
from base import BaseTest, FlowStep, FlowTest
from ui_driver import UISession

from seedsigner.controller import Controller
from seedsigner.gui.screens import chess_screens
from seedsigner.gui.screens.chess_screens import ChessBoardScreen
from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.hardware.buttons import HardwareButtonsConstants as K
from seedsigner.helpers.chess import search
from seedsigner.helpers.chess.board import Board, square_index
from seedsigner.helpers.chess.game import ChessGame
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import chess_views, tools_views
from seedsigner.views.view import Destination, MainMenuView


def walk(game: ChessGame, to: str) -> list:
    """Joystick presses that move the cursor from where it is to `to`."""
    screen = object.__new__(ChessBoardScreen)
    screen.game = game
    row, col = screen._row_col(game.cursor)
    target_row, target_col = screen._row_col(square_index(to))
    keys = []
    keys += [K.KEY_DOWN if target_row > row else K.KEY_UP] * abs(target_row - row)
    keys += [K.KEY_RIGHT if target_col > col else K.KEY_LEFT] * abs(target_col - col)
    game.cursor = square_index(to)  # so the next walk() starts from here
    return keys


def play(game: ChessGame, uci: str) -> list:
    """Presses that pick up the piece on uci[:2] and drop it on uci[2:4]."""
    return walk(game, uci[:2]) + [K.KEY_PRESS] + walk(game, uci[2:4]) + [K.KEY_PRESS]


@pytest.fixture
def instant_opponent(monkeypatch):
    """The device answers at once with the first legal move, so scripts do not depend on timing."""
    def fake_best_move(board, **kwargs):
        moves = board.legal_moves()
        return sorted(moves)[0] if moves else None
    monkeypatch.setattr(search, "best_move", fake_best_move)


def display(game, script, held=None, **session_kwargs):
    """
    Run the board screen. `held` = (keys, seconds) holds those keys down for
    that long, counted from the first time the screen checks a key.
    """
    start_cursor = game.cursor
    with UISession(script=script, **session_kwargs) as session:
        if held:
            keys, seconds = held
            started = []

            def is_pressed(key):
                if not started:
                    started.append(time.monotonic())
                return key in keys and time.monotonic() - started[0] < seconds

            session.buttons.is_pressed = is_pressed
        game.cursor = start_cursor
        result = ChessBoardScreen(game=game).display()
    assert len(session.renderer.frames) > 0
    display.last_frame = session.renderer.frames[-1]
    return result


@pytest.fixture
def quick_unlock(monkeypatch):
    """A 0.1 s hold opens the wallet, so tests do not wait the real 2 s."""
    monkeypatch.setattr(chess_screens, "UNLOCK_HOLD_SECONDS", 0.1)


class TestChessBoardScreen(BaseTest):

    def test_a_move_then_the_device_replies(self, instant_opponent):
        game = ChessGame(human="w")
        script = play(ChessGame(human="w"), "e2e4") + [K.KEY1]
        assert display(game, script) == ChessBoardScreen.RET_MENU
        assert game.board.move_count == 2
        assert game.board.piece_at("e4") == "P"
        assert game.board.turn == "w"

    def test_playing_black_the_device_opens(self, instant_opponent):
        game = ChessGame(human="b")
        assert game.flipped
        assert display(game, [K.KEY1]) == ChessBoardScreen.RET_MENU
        assert game.board.move_count == 1 and game.board.turn == "b"

    def test_illegal_drop_and_empty_click_change_nothing(self, instant_opponent):
        game = ChessGame(human="w")
        planner = ChessGame(human="w")
        script = (walk(planner, "e4") + [K.KEY_PRESS]  # empty square: nothing to pick up
                  + play(planner, "e2e5")  # a pawn cannot go three squares
                  + [K.KEY1])
        display(game, script)
        assert game.board.move_count == 0

    def test_undo_takes_back_both_sides(self, instant_opponent):
        game = ChessGame(human="w")
        script = play(ChessGame(human="w"), "d2d4") + [K.KEY3, K.KEY1]
        display(game, script)
        assert game.board.move_count == 0 and game.board.fen() == Board().fen()

    def test_flip_key_turns_the_board(self, instant_opponent):
        game = ChessGame(human="w")
        display(game, [K.KEY2, K.KEY1])
        assert game.flipped

    def test_promotion_offers_every_piece(self):
        game = ChessGame(human=None, board=Board("7k/P7/8/8/8/8/8/K7 w - - 0 1"))
        game.cursor = square_index("a1")
        script = play(ChessGame(human=None, board=Board("7k/P7/8/8/8/8/8/K7 w - - 0 1"), cursor=square_index("a1")), "a7a8")
        script += [K.KEY_RIGHT, K.KEY_PRESS, K.KEY1]  # queen -> rook, take it
        display(game, script)
        assert game.board.piece_at("a8") == "R"

    def test_two_players_play_to_checkmate(self):
        game = ChessGame(human=None)
        planner = ChessGame(human=None)
        script = []
        for uci in ["f2f3", "e7e5", "g2g4", "d8h4"]:
            script += play(planner, uci)
        assert display(game, script) == ChessBoardScreen.RET_GAME_OVER
        assert game.result_text() == "Checkmate. Black wins."

    def test_wide_screen_draws_the_status_panel(self, instant_opponent):
        game = ChessGame(human="w")
        script = play(ChessGame(human="w"), "e2e4") + [K.KEY1]
        with UISession(script=script, canvas_size=(320, 240)) as session:
            screen = ChessBoardScreen(game=game)
            assert screen.has_panel
            assert screen.display() == ChessBoardScreen.RET_MENU
        frame = session.renderer.frames[-1]
        assert frame.size == (320, 240)
        # The panel beside the board is drawn on, not left black.
        assert frame.crop((240, 0, 320, 240)).getbbox() is not None

    def test_narrow_screen_has_no_panel(self):
        with UISession(script=[]):
            assert not ChessBoardScreen(game=ChessGame(human="w")).has_panel

    def test_key1_and_key3_held_open_the_wallet(self, quick_unlock):
        game = ChessGame(human="w")
        result = display(game, [K.KEY1], held=({K.KEY1, K.KEY3}, 0.3))
        assert result == ChessBoardScreen.RET_UNLOCK
        assert game.board.move_count == 0
        # The only sign on screen: it goes blank.
        assert display.last_frame.getbbox() is None

    def test_key1_and_key3_let_go_early_do_nothing(self, monkeypatch):
        monkeypatch.setattr(chess_screens, "UNLOCK_HOLD_SECONDS", 1.0)
        game = ChessGame(human="w")
        # Both held for 0.1 s: no unlock, and neither the menu nor undo. Then
        # KEY2 flips and a plain KEY1 opens the menu as usual.
        result = display(game, [K.KEY3, K.KEY2, K.KEY1], held=({K.KEY1, K.KEY3}, 0.1))
        assert result == ChessBoardScreen.RET_MENU
        assert game.flipped

    def test_key3_alone_still_takes_a_move_back(self, instant_opponent):
        game = ChessGame(human="w")
        script = play(ChessGame(human="w"), "e2e4") + [K.KEY3, K.KEY1]
        display(game, script, held=({K.KEY3}, 0.1))
        assert game.board.move_count == 0

    def test_unlock_while_the_device_thinks(self, monkeypatch, quick_unlock):
        def slow_best_move(board, should_stop=None, **kwargs):
            while not should_stop():
                time.sleep(0.01)
            return board.legal_moves()[0]

        monkeypatch.setattr(search, "best_move", slow_best_move)
        game = ChessGame(human="b")  # the device opens
        result = display(game, [], held=({K.KEY1, K.KEY3}, 0.5), poll_responses=[True])
        assert result == ChessBoardScreen.RET_UNLOCK
        assert game.board.move_count == 0

    def test_menu_key_interrupts_the_device_thinking(self, monkeypatch):
        started = threading.Event()

        def slow_best_move(board, should_stop=None, **kwargs):
            started.set()
            while not should_stop():
                time.sleep(0.01)
            return board.legal_moves()[0]

        monkeypatch.setattr(search, "best_move", slow_best_move)
        game = ChessGame(human="b")  # the device opens
        # The first poll comes back False, the second is the press.
        assert display(game, [], poll_responses=[False, True]) == ChessBoardScreen.RET_MENU
        assert started.is_set()
        assert game.board.move_count == 0  # an interrupted search plays nothing


class TestChessViews(FlowTest):

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(SettingsConstants.SETTING__CHESS, SettingsConstants.OPTION__ENABLED)
        self.settings.set_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION,
                                SettingsConstants.DISPLAY_CONFIGURATION__ST7789__320x240)
        chess_views.set_game(None)

    def teardown_method(self):
        chess_views.set_game(None)
        super().teardown_method()

    def test_new_game_menu_exit_and_resume(self, instant_opponent):
        V = chess_views
        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.TOOLS),
            FlowStep(tools_views.ToolsMenuView, button_data_selection=tools_views.ToolsMenuView.CHESS),
            FlowStep(V.ChessMenuView, button_data_selection=V.ChessMenuView.NEW),
            FlowStep(V.ChessNewGameView, button_data_selection=V.ChessNewGameView.WHITE),
            FlowStep(V.ChessLevelView, button_data_selection=V.ChessLevelView.LEVELS[0]),
            FlowStep(V.ChessGameView, screen_return_value=ChessBoardScreen.RET_MENU),
            FlowStep(V.ChessGameMenuView, button_data_selection=V.ChessGameMenuView.EXIT),
            FlowStep(V.ChessMenuView, button_data_selection=V.ChessMenuView.RESUME),
            FlowStep(V.ChessGameView, screen_return_value=ChessBoardScreen.RET_MENU),
            FlowStep(V.ChessGameMenuView, button_data_selection=V.ChessGameMenuView.CONTINUE),
            FlowStep(V.ChessGameView),
        ])
        game = chess_views.current_game()
        assert game.human == "w" and game.level == 0

    def test_resign_ends_the_game_and_clears_resume(self):
        V = chess_views
        chess_views.set_game(ChessGame(human="w"))
        self.run_sequence([
            FlowStep(V.ChessGameMenuView, button_data_selection=V.ChessGameMenuView.RESIGN),
            FlowStep(V.ChessResultView, button_data_selection=V.ChessResultView.DONE),
            FlowStep(V.ChessMenuView),
        ])
        assert chess_views.current_game() is None

    @pytest.mark.parametrize("human, has_resign", [("w", True), (None, False)])
    def test_resign_only_against_the_device(self, human, has_resign):
        chess_views.set_game(ChessGame(human=human))
        captured = {}

        def fake_run_screen(view, Screen_cls, **kwargs):
            captured["buttons"] = kwargs["button_data"]
            return RET_CODE__BACK_BUTTON

        view = chess_views.ChessGameMenuView()
        view.run_screen = fake_run_screen.__get__(view)
        view.run()
        assert (chess_views.ChessGameMenuView.RESIGN in captured["buttons"]) == has_resign


class TestStartInChess(FlowTest):
    """Settings → Chess → Start in chess: the device starts in the game and hides the way out."""

    def setup_method(self):
        super().setup_method()
        self.settings.set_value(SettingsConstants.SETTING__CHESS, SettingsConstants.CHESS__START)
        self.settings.set_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION,
                                SettingsConstants.DISPLAY_CONFIGURATION__ST7789__320x240)
        chess_views.set_game(None)
        chess_views._state["unlocked"] = False

    def teardown_method(self):
        chess_views.set_game(None)
        chess_views._state["unlocked"] = False
        super().teardown_method()

    def test_power_on_goes_to_the_game(self):
        assert Controller.get_instance().startup_destination() == Destination(chess_views.ChessBootView)

    @pytest.mark.parametrize("value, display", [
        (SettingsConstants.CHESS__TOOLS, SettingsConstants.DISPLAY_CONFIGURATION__ST7789__320x240),
        (SettingsConstants.OPTION__DISABLED, SettingsConstants.DISPLAY_CONFIGURATION__ST7789__320x240),
        # Too small to play on, so it must never start there and trap the wallet.
        (SettingsConstants.CHESS__START, SettingsConstants.DISPLAY_CONFIGURATION__ST7789__240x240),
    ])
    def test_power_on_goes_home_otherwise(self, value, display):
        self.settings.set_value(SettingsConstants.SETTING__CHESS, value)
        self.settings.set_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION, display)
        assert Controller.get_instance().startup_destination() == Destination(MainMenuView)

    def test_boot_starts_a_game_and_the_combo_reaches_home(self, monkeypatch):
        cleared = []
        monkeypatch.setattr(chess_views, "clear_boot_failover", lambda: cleared.append(True))
        V = chess_views
        self.run_sequence([
            FlowStep(V.ChessBootView, is_redirect=True),
            FlowStep(V.ChessGameView, screen_return_value=ChessBoardScreen.RET_UNLOCK),
            FlowStep(MainMenuView),
        ])
        assert cleared == [True]
        game = chess_views.current_game()
        assert game.human == "w" and game.level == 1

        # Once opened, chess from Tools has its Exit and screensaver back.
        view = chess_views.ChessGameMenuView()
        assert view.is_screensaver_allowed
        captured = {}
        view.run_screen = (lambda v, S, **kw: captured.update(kw) or RET_CODE__BACK_BUTTON).__get__(view)
        view.run()
        assert chess_views.ChessGameMenuView.EXIT in captured["button_data"]

    def test_no_exit_and_no_screensaver(self):
        chess_views.set_game(ChessGame(human="w"))
        captured = {}

        def fake_run_screen(view, Screen_cls, **kwargs):
            captured.update(kwargs)
            return RET_CODE__BACK_BUTTON

        view = chess_views.ChessGameMenuView()
        assert not view.is_screensaver_allowed
        view.run_screen = fake_run_screen.__get__(view)
        view.run()
        assert chess_views.ChessGameMenuView.EXIT not in captured["button_data"]

        view = chess_views.ChessMenuView()
        view.run_screen = fake_run_screen.__get__(view)
        view.run()
        assert captured["show_back_button"] is False

    def test_in_tools_mode_the_menus_keep_their_way_out(self):
        self.settings.set_value(SettingsConstants.SETTING__CHESS, SettingsConstants.CHESS__TOOLS)
        chess_views.set_game(ChessGame(human="w"))
        view = chess_views.ChessGameMenuView()
        assert view.is_screensaver_allowed
        captured = {}
        view.run_screen = (lambda v, S, **kw: captured.update(kw) or RET_CODE__BACK_BUTTON).__get__(view)
        view.run()
        assert chess_views.ChessGameMenuView.EXIT in captured["button_data"]


class TestBootFailoverClear(BaseTest):
    """Home and the chess start share one boot-counter clear: once per boot, Luckfox only."""

    def _calls(self, monkeypatch, profile):
        import subprocess
        from seedsigner.models.settings import Settings
        from seedsigner.views import view as view_module
        calls = []
        monkeypatch.setattr(Settings, "is_seedsigner_os", staticmethod(lambda: True))
        monkeypatch.setattr(Settings, "RUNTIME_PROFILE", profile)
        monkeypatch.setattr(subprocess, "run", lambda args, **kwargs: calls.append(args))
        monkeypatch.setattr(Controller.get_instance(), "boot_failover_cleared", False, raising=False)
        view_module.clear_boot_failover()
        view_module.clear_boot_failover()
        return calls

    def test_cleared_once_on_luckfox(self, monkeypatch):
        from seedsigner.views.view import PowerOptionsView
        calls = self._calls(monkeypatch, PowerOptionsView.LUCKFOX_PROFILES[0])
        assert calls == [["devmem", "0xFF020218", "32", "0"]]

    def test_never_off_luckfox(self, monkeypatch):
        assert self._calls(monkeypatch, "desktop") == []
