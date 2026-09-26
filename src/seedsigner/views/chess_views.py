"""
Tools → Chess: play the device, or a friend on the same device.

With the setting at "Start in chess" the device also starts straight into a
game, with no logo, no way out in the menus and no screensaver (it would show
the logo). Holding KEY1 and KEY3 together on the board opens the wallet. This
only hides what the device is from someone looking at the screen; the firmware
on the device still says what it is.

The game in progress lives in this module, in memory only, so leaving for the
game menu and coming back resumes it. It holds no key material and is never
written to disk.
"""
from gettext import gettext as _

from seedsigner.gui.screens.chess_screens import ChessBoardScreen
from seedsigner.gui.screens.screen import RET_CODE__BACK_BUTTON, ButtonListScreen, ButtonOption, LargeIconStatusScreen
from seedsigner.helpers.chess.game import ChessGame
from seedsigner.models.settings_definition import SettingsConstants

from .view import BackStackView, Destination, MainMenuView, View, clear_boot_failover

# The game in progress, or None, and whether the KEY1 + KEY3 hold has opened
# the wallet since power-on (after that, chess from Tools has its way out back).
_state = {"game": None, "unlocked": False}


# The board needs a 320x240 screen or larger: on 240x240 the pieces are too
# small to play comfortably, so Chess is not offered there.
LARGE_DISPLAYS = (
    SettingsConstants.DISPLAY_CONFIGURATION__ST7789__320x240,
    SettingsConstants.DISPLAY_CONFIGURATION__ILI9341__320x240,
    SettingsConstants.DISPLAY_CONFIGURATION__ILI9486__480x320,
    SettingsConstants.DISPLAY_CONFIGURATION__DESKTOP__320x240,
)


def chess_available(settings) -> bool:
    """Chess is on in Settings and the display is large enough to play on."""
    return (
        settings.get_value(SettingsConstants.SETTING__CHESS) != SettingsConstants.OPTION__DISABLED
        and settings.get_value(SettingsConstants.SETTING__DISPLAY_CONFIGURATION) in LARGE_DISPLAYS
    )


def starts_in_chess(settings) -> bool:
    """The device starts in the game, and the wallet is behind the KEY1 + KEY3 hold."""
    return (
        settings.get_value(SettingsConstants.SETTING__CHESS) == SettingsConstants.CHESS__START
        and chess_available(settings)
    )


def current_game():
    return _state["game"]


def set_game(game):
    _state["game"] = game


class ChessView(View):
    """
    Base for the chess views. Until the wallet is opened on a device that starts
    in chess, the menus offer no way out and the screensaver stays off.
    """
    def __init__(self):
        super().__init__()
        self.hidden = starts_in_chess(self.settings) and not _state["unlocked"]
        self.is_screensaver_allowed = not self.hidden


class ChessBootView(ChessView):
    """The first View when the device starts in chess: a new game against the device."""
    def run(self):
        # Home is never reached before the wallet is opened, so tell the boot
        # failover here that the app started.
        clear_boot_failover()
        if current_game() is None:
            set_game(ChessGame(human="w", level=1))
        # It is the first View, so there is no history to skip it from.
        return Destination(ChessGameView, clear_history=True)


class ChessMenuView(ChessView):
    RESUME = ButtonOption("Resume game")
    NEW = ButtonOption("New game")

    def run(self):
        game = current_game()
        button_data = []
        if game is not None and game.board.outcome() is None:
            button_data.append(self.RESUME)
        button_data.append(self.NEW)

        selected_menu_num = self.run_screen(
            ButtonListScreen, title=_("Chess"), button_data=button_data,
            show_back_button=not self.hidden,
        )

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if button_data[selected_menu_num] == self.RESUME:
            return Destination(ChessGameView)
        return Destination(ChessNewGameView)


class ChessNewGameView(ChessView):
    WHITE = ButtonOption("Play white")
    BLACK = ButtonOption("Play black")
    TWO_PLAYERS = ButtonOption("Two players")

    def run(self):
        button_data = [self.WHITE, self.BLACK, self.TWO_PLAYERS]
        selected_menu_num = self.run_screen(ButtonListScreen, title=_("New game"), button_data=button_data)

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        if button_data[selected_menu_num] == self.TWO_PLAYERS:
            set_game(ChessGame(human=None))
            return Destination(ChessGameView)
        human = "w" if button_data[selected_menu_num] == self.WHITE else "b"
        return Destination(ChessLevelView, view_args=dict(human=human))


class ChessLevelView(ChessView):
    # In LEVEL_SECONDS order.
    LEVELS = [ButtonOption("Easy"), ButtonOption("Medium"), ButtonOption("Hard")]

    def __init__(self, human: str):
        super().__init__()
        self.human = human

    def run(self):
        button_data = self.LEVELS
        selected_menu_num = self.run_screen(ButtonListScreen, title=_("Level"), button_data=button_data)

        if selected_menu_num == RET_CODE__BACK_BUTTON:
            return Destination(BackStackView)
        set_game(ChessGame(human=self.human, level=selected_menu_num))
        return Destination(ChessGameView)


class ChessGameView(ChessView):
    def run(self):
        game = current_game()
        if game is None:
            return Destination(ChessMenuView)

        ret = self.run_screen(ChessBoardScreen, game=game)

        if ret == ChessBoardScreen.RET_UNLOCK:
            _state["unlocked"] = True
            return Destination(MainMenuView)
        if ret == ChessBoardScreen.RET_GAME_OVER:
            return Destination(ChessResultView, view_args=dict(text=game.result_text()))
        return Destination(ChessGameMenuView)


class ChessGameMenuView(ChessView):
    CONTINUE = ButtonOption("Continue")
    FLIP = ButtonOption("Flip board")
    RESIGN = ButtonOption("Resign")
    NEW = ButtonOption("New game")
    EXIT = ButtonOption("Exit")

    def run(self):
        game = current_game()
        if game is None:
            return Destination(ChessMenuView)

        button_data = [self.CONTINUE, self.FLIP]
        if game.human is not None:
            button_data.append(self.RESIGN)
        button_data.append(self.NEW)
        if not self.hidden:
            button_data.append(self.EXIT)

        selected_menu_num = self.run_screen(ButtonListScreen, title=_("Game"), button_data=button_data)

        if selected_menu_num == RET_CODE__BACK_BUTTON or button_data[selected_menu_num] == self.CONTINUE:
            return Destination(ChessGameView)
        selected = button_data[selected_menu_num]
        if selected == self.FLIP:
            game.flipped = not game.flipped
            return Destination(ChessGameView)
        if selected == self.RESIGN:
            return Destination(ChessResultView, view_args=dict(text=_("You resigned.")))
        if selected == self.NEW:
            return Destination(ChessNewGameView)
        # Exit keeps the game, so "Resume game" can pick it up.
        return Destination(ChessMenuView)


class ChessResultView(ChessView):
    NEW = ButtonOption("New game")
    DONE = ButtonOption("Done")

    def __init__(self, text: str):
        super().__init__()
        self.text = text

    def run(self):
        set_game(None)
        button_data = [self.NEW, self.DONE]
        selected_menu_num = self.run_screen(
            LargeIconStatusScreen,
            title=_("Game over"),
            status_icon_size=0,
            status_headline=self.text,
            text="",
            show_back_button=False,
            button_data=button_data,
        )
        if selected_menu_num != RET_CODE__BACK_BUTTON and button_data[selected_menu_num] == self.NEW:
            return Destination(ChessNewGameView)
        return Destination(ChessMenuView)
