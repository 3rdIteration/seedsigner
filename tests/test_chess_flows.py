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

from seedsigner.gui.screens.chess_screens import ChessBoardScreen
from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON
from seedsigner.hardware.buttons import HardwareButtonsConstants as K
from seedsigner.helpers.chess import search
from seedsigner.helpers.chess.board import Board, square_index
from seedsigner.helpers.chess.game import ChessGame
from seedsigner.models.settings_definition import SettingsConstants
from seedsigner.views import chess_views, tools_views
from seedsigner.views.view import MainMenuView


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


def display(game, script, **session_kwargs):
    start_cursor = game.cursor
    with UISession(script=script, **session_kwargs) as session:
        game.cursor = start_cursor
        result = ChessBoardScreen(game=game).display()
    assert len(session.renderer.frames) > 0
    return result


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
