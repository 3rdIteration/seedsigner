import logging
import time

from dataclasses import dataclass
from gettext import gettext as _

from seedsigner.gui.components import FontAwesomeIconConstants, Fonts, GUIConstants
from seedsigner.hardware.buttons import HardwareButtonsConstants
from seedsigner.helpers.chess import search
from seedsigner.helpers.chess.board import EMPTY, PROMOTIONS
from seedsigner.helpers.chess.game import ChessGame
from seedsigner.models.threads import BaseThread

from .screen import BaseScreen

logger = logging.getLogger(__name__)


SQUARE = 30  # 8 x 30 px: the board is 240 px square
PANEL_MIN_WIDTH = 60  # a wider canvas (320x240) gets a status panel beside the board
LIGHT = "#e8d6b0"
DARK = "#a67c52"
LAST_MOVE_LIGHT = "#d9d98a"
LAST_MOVE_DARK = "#aaa24c"
SELECTED = "#f0e060"
IN_CHECK = "#d04040"

# Holding KEY1 and KEY3 together opens the wallet. The game only ever taps one
# of them at a time, so the combination is never pressed by accident.
UNLOCK_KEYS = (HardwareButtonsConstants.KEY1, HardwareButtonsConstants.KEY3)
UNLOCK_HOLD_SECONDS = 2.0
UNLOCK_PARTNER_WINDOW = 0.25  # the second key may land a moment after the first

GLYPHS = {
    "K": FontAwesomeIconConstants.CHESS_KING,
    "Q": FontAwesomeIconConstants.CHESS_QUEEN,
    "R": FontAwesomeIconConstants.CHESS_ROOK,
    "B": FontAwesomeIconConstants.CHESS_BISHOP,
    "N": FontAwesomeIconConstants.CHESS_KNIGHT,
    "P": FontAwesomeIconConstants.CHESS_PAWN,
}


class _DeviceMoveThread(BaseThread):
    """Searches for the device's move off the screen's thread, so KEY1 still opens the menu."""
    def __init__(self, game: ChessGame):
        super().__init__()
        self.game = game
        self.move = None

    def run(self):
        self.move = search.best_move(
            self.game.board,
            time_budget=self.game.time_budget,
            should_stop=lambda: not self.keep_running,
        )


@dataclass
class ChessBoardScreen(BaseScreen):
    """
    The board, full screen. Joystick moves the cursor, click picks a piece and
    drops it, KEY1 opens the game menu, KEY2 flips the board, KEY3 takes a move
    back, and KEY1 with KEY3 held together opens the wallet. Returns RET_MENU,
    RET_GAME_OVER or RET_UNLOCK; the move itself is recorded on `game`, which
    outlives the screen.
    """
    RET_MENU = "menu"
    RET_GAME_OVER = "game over"
    RET_UNLOCK = "unlock"

    game: ChessGame = None

    def __post_init__(self):
        super().__post_init__()
        self.selected = None
        self.promotion_choices = None  # the four promotion moves while choosing
        self.promotion_index = 0
        self.thinking = False
        self.piece_font = Fonts.get_font(GUIConstants.ICON_FONT_NAME__FONT_AWESOME, 22)
        self.panel_icon_font = Fonts.get_font(GUIConstants.ICON_FONT_NAME__FONT_AWESOME, 36)
        self.text_font = Fonts.get_font(GUIConstants.get_body_font_name(), GUIConstants.get_body_font_size())
        self.small_font = Fonts.get_font(GUIConstants.get_body_font_name(), 14)
        # On a 320x240 canvas the board sits on the left and the rest is a status panel.
        self.has_panel = self.canvas_width - 8 * SQUARE >= PANEL_MIN_WIDTH

    # ------------------------------------------------------------ geometry

    def _index_at(self, row: int, col: int) -> int:
        if self.game.flipped:
            row, col = 7 - row, 7 - col
        return 21 + row * 10 + col

    def _row_col(self, index: int):
        row, col = index // 10 - 2, index % 10 - 1
        if self.game.flipped:
            row, col = 7 - row, 7 - col
        return row, col

    # ------------------------------------------------------------- drawing

    def _render(self):
        board = self.game.board
        draw = self.image_draw
        self.clear_screen()
        targets = {m[1]: board.board[m[1]] != EMPTY for m in self.game.moves_from(self.selected)} \
            if self.selected is not None else {}
        last = set(self.game.last_move[:2]) if self.game.last_move else set()
        checked_king = board.kings[board.turn] if board.in_check() else None

        for row in range(8):
            for col in range(8):
                index = self._index_at(row, col)
                x, y = col * SQUARE, row * SQUARE
                light = (row + col) % 2 == 0
                fill = LIGHT if light else DARK
                if index in last:
                    fill = LAST_MOVE_LIGHT if light else LAST_MOVE_DARK
                if index == self.selected:
                    fill = SELECTED
                if index == checked_king:
                    fill = IN_CHECK
                draw.rectangle((x, y, x + SQUARE - 1, y + SQUARE - 1), fill=fill)

                piece = board.board[index]
                if piece != EMPTY:
                    white = piece.isupper()
                    draw.text(
                        (x + SQUARE // 2, y + SQUARE // 2),
                        GLYPHS[piece.upper()],
                        font=self.piece_font,
                        anchor="mm",
                        fill="#ffffff" if white else "#000000",
                        stroke_width=1,
                        stroke_fill="#000000" if white else "#ffffff",
                    )
                if index in targets:
                    cx, cy = x + SQUARE // 2, y + SQUARE // 2
                    if targets[index]:
                        draw.ellipse((x + 2, y + 2, x + SQUARE - 3, y + SQUARE - 3), outline=GUIConstants.ACCENT_COLOR, width=2)
                    else:
                        draw.ellipse((cx - 4, cy - 4, cx + 4, cy + 4), fill=GUIConstants.ACCENT_COLOR)

        row, col = self._row_col(self.game.cursor)
        x, y = col * SQUARE, row * SQUARE
        draw.rectangle((x, y, x + SQUARE - 1, y + SQUARE - 1), outline=GUIConstants.ACCENT_COLOR, width=3)

        if self.has_panel:
            self._render_panel()
        elif self.thinking and not self.promotion_choices:
            self._render_banner(_("Thinking..."))
        if self.promotion_choices:
            self._render_promotion()

    def _status_text(self) -> str:
        board = self.game.board
        if self.thinking:
            return _("Thinking...")
        if board.outcome() is not None:
            return _("Game over")
        if board.in_check():
            return _("Check!")
        if self.game.human is None:
            return _("White to move") if board.turn == "w" else _("Black to move")
        return _("Your move")

    def _render_panel(self):
        left = 8 * SQUARE
        center = left + (self.canvas_width - left) // 2
        white = self.game.board.turn == "w"
        # Whose move it is, as a king in that side's colour.
        self.image_draw.text(
            (center, 40), GLYPHS["K"], font=self.panel_icon_font, anchor="mm",
            fill="#ffffff" if white else "#000000", stroke_width=2,
            stroke_fill="#000000" if white else "#ffffff",
        )
        # Two short lines fit the 80 px panel where one long one would not.
        text = self._status_text()
        lines = text.split(" ", 1) if " " in text and len(text) > 9 else [text]
        y = 80
        for line in lines:
            self.image_draw.text((center, y), line, font=self.small_font, fill=GUIConstants.BODY_FONT_COLOR, anchor="mm")
            y += 18
        hints = [("1", _("Menu")), ("2", _("Flip")), ("3", _("Undo"))]
        y = self.canvas_height - 3 * 20 - 4
        for key, label in hints:
            self.image_draw.text((left + 8, y), key, font=self.small_font, fill=GUIConstants.ACCENT_COLOR, anchor="lm")
            self.image_draw.text((left + 22, y), label, font=self.small_font, fill=GUIConstants.BODY_FONT_COLOR, anchor="lm")
            y += 20

    def _render_banner(self, text: str):
        top = self.canvas_height - 26
        self.image_draw.rectangle((0, top, self.canvas_width, self.canvas_height), fill=GUIConstants.BACKGROUND_COLOR)
        self.image_draw.text(
            (self.canvas_width // 2, top + 13), text, font=self.text_font,
            fill=GUIConstants.BODY_FONT_COLOR, anchor="mm",
        )

    def _render_promotion(self):
        white = self.game.board.turn == "w"
        width = 4 * (SQUARE + 8) + 8
        left = (self.canvas_width - width) // 2
        top = (self.canvas_height - SQUARE - 16) // 2
        self.image_draw.rectangle((left, top, left + width, top + SQUARE + 16), fill=GUIConstants.BACKGROUND_COLOR,
                                  outline=GUIConstants.ACCENT_COLOR, width=2)
        for i, move in enumerate(self.promotion_choices):
            x = left + 8 + i * (SQUARE + 8)
            y = top + 8
            if i == self.promotion_index:
                self.image_draw.rectangle((x - 2, y - 2, x + SQUARE + 1, y + SQUARE + 1), outline=GUIConstants.ACCENT_COLOR, width=2)
            self.image_draw.text(
                (x + SQUARE // 2, y + SQUARE // 2), GLYPHS[move[2].upper()], font=self.piece_font, anchor="mm",
                fill="#ffffff" if white else "#000000", stroke_width=1,
                stroke_fill="#000000" if white else "#ffffff",
            )

    def _redraw(self):
        with self.renderer.lock:
            self._render()
            self.renderer.show_image()

    # ---------------------------------------------------------------- input

    def _run(self):
        while True:
            if self.game.board.outcome() is not None:
                self._redraw()
                return self.RET_GAME_OVER
            if self.game.device_to_move():
                ret = self._device_turn()
                if ret is not None:
                    return ret
                continue
            ret = self._human_input()
            if ret is not None:
                return ret

    def _device_turn(self):
        self.thinking = True
        self._redraw()
        thread = _DeviceMoveThread(self.game)
        thread.start()
        try:
            while True:
                thread.join(timeout=0.05)
                if not thread.is_alive():
                    break
                menu = self.hw_inputs.check_for_low(key=HardwareButtonsConstants.KEY1)
                if not menu and not self.hw_inputs.is_pressed(HardwareButtonsConstants.KEY3):
                    continue
                combo = self._unlock_combo(HardwareButtonsConstants.KEY1 if menu else HardwareButtonsConstants.KEY3)
                if combo is None and not menu:
                    continue  # KEY3 alone does nothing while the device thinks
                if combo is False:
                    continue  # both keys, let go too soon
                thread.stop()
                thread.join()
                return self.RET_UNLOCK if combo else self.RET_MENU
        finally:
            self.thinking = False
        if thread.move is not None:
            self.game.play(thread.move)
        self._redraw()
        return None

    def _human_input(self):
        user_input = self.hw_inputs.wait_for(HardwareButtonsConstants.ALL_KEYS)

        if user_input in UNLOCK_KEYS:
            combo = self._unlock_combo(user_input)
            if combo:
                return self.RET_UNLOCK
            if combo is False:
                return None  # both keys, let go too soon: neither key's own action

        if self.promotion_choices:
            if user_input == HardwareButtonsConstants.KEY_LEFT:
                self.promotion_index = (self.promotion_index - 1) % len(self.promotion_choices)
            elif user_input == HardwareButtonsConstants.KEY_RIGHT:
                self.promotion_index = (self.promotion_index + 1) % len(self.promotion_choices)
            elif user_input == HardwareButtonsConstants.KEY_PRESS:
                self.game.play(self.promotion_choices[self.promotion_index])
                self.promotion_choices = None
                self.selected = None
            elif user_input == HardwareButtonsConstants.KEY1:
                self.promotion_choices = None
            self._redraw()
            return None

        row, col = self._row_col(self.game.cursor)
        if user_input == HardwareButtonsConstants.KEY_UP:
            row = max(0, row - 1)
        elif user_input == HardwareButtonsConstants.KEY_DOWN:
            row = min(7, row + 1)
        elif user_input == HardwareButtonsConstants.KEY_LEFT:
            col = max(0, col - 1)
        elif user_input == HardwareButtonsConstants.KEY_RIGHT:
            col = min(7, col + 1)
        elif user_input == HardwareButtonsConstants.KEY_PRESS:
            self._click()
        elif user_input == HardwareButtonsConstants.KEY1:
            self.selected = None
            return self.RET_MENU
        elif user_input == HardwareButtonsConstants.KEY2:
            self.game.flipped = not self.game.flipped
        elif user_input == HardwareButtonsConstants.KEY3:
            self.game.undo()
            self.selected = None

        if user_input in HardwareButtonsConstants.KEYS__LEFT_RIGHT_UP_DOWN:
            self.game.cursor = self._index_at(row, col)
        self._redraw()
        return None

    def _unlock_combo(self, first_key):
        """
        After `first_key` (KEY1 or KEY3) is pressed: None when the other key does
        not join it, so the key keeps its own meaning; False when both were held
        but let go before UNLOCK_HOLD_SECONDS; True once both have been held that
        long. On True the screen goes blank at once, as the only sign, and this
        returns after both keys are released so the next screen does not read
        them as presses.
        """
        other = UNLOCK_KEYS[1] if first_key == UNLOCK_KEYS[0] else UNLOCK_KEYS[0]
        is_pressed = self.hw_inputs.is_pressed
        start = time.monotonic()
        while not is_pressed(other):
            if not is_pressed(first_key) or time.monotonic() - start > UNLOCK_PARTNER_WINDOW:
                return None
            time.sleep(0.01)

        start = time.monotonic()
        while is_pressed(first_key) and is_pressed(other):
            if time.monotonic() - start >= UNLOCK_HOLD_SECONDS:
                with self.renderer.lock:
                    self.clear_screen()
                    self.renderer.show_image()
                while is_pressed(first_key) or is_pressed(other):
                    time.sleep(0.02)
                return True
            time.sleep(0.02)
        return False

    def _click(self):
        board = self.game.board
        cursor = self.game.cursor
        piece = board.board[cursor]
        own = piece != EMPTY and piece.isupper() == (board.turn == "w")

        if self.selected is None:
            if own and self.game.moves_from(cursor):
                self.selected = cursor
            return
        if cursor == self.selected:
            self.selected = None
            return
        if own:
            self.selected = cursor if self.game.moves_from(cursor) else None
            return
        moves = [m for m in self.game.moves_from(self.selected) if m[1] == cursor]
        if not moves:
            return
        if len(moves) > 1:
            # Promotion: queen first, then rook, bishop, knight.
            self.promotion_choices = sorted(moves, key=lambda m: PROMOTIONS.index(m[2]))
            self.promotion_index = 0
            return
        self.game.play(moves[0])
        self.selected = None
