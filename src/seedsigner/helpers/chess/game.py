"""
One game in progress: the board plus who plays what, kept between screens so a
game survives a trip to its menu. Held in memory only, never written to disk.
"""
from dataclasses import dataclass, field
from gettext import gettext as _

from .board import Board, square_index

# Seconds the device may think per move, by level. Strength follows the CPU,
# so the same three levels suit a Pi Zero and a desktop.
LEVEL_SECONDS = (0.5, 2.0, 5.0)


@dataclass
class ChessGame:
    human: str = "w"  # "w", "b", or None for two players on one device
    level: int = 1
    board: Board = field(default_factory=Board)
    flipped: bool = None  # None: follow the human's colour
    cursor: int = None
    last_move: tuple = None

    def __post_init__(self):
        if self.flipped is None:
            self.flipped = self.human == "b"
        if self.cursor is None:
            self.cursor = square_index("e2" if self.human != "b" else "e7")

    @property
    def time_budget(self) -> float:
        return LEVEL_SECONDS[self.level]

    def device_to_move(self) -> bool:
        return self.human is not None and self.board.turn != self.human

    def play(self, move):
        self.board.push(move)
        self.last_move = move

    def undo(self) -> bool:
        """
        Take back the last move, or the last move of each side against the
        device, so it is the human's turn again. False when there is nothing
        to take back.
        """
        plies = 1 if self.human is None else (2 if self.board.turn == self.human else 1)
        if self.board.move_count < plies:
            return False
        for _ply in range(plies):
            self.board.pop()
        self.last_move = None
        return True

    def moves_from(self, index: int):
        return [m for m in self.board.legal_moves() if m[0] == index]

    def result_text(self) -> str:
        outcome = self.board.outcome()
        if outcome is None:
            return ""
        reason, winner = outcome
        if reason == "checkmate":
            if self.human is None:
                return _("Checkmate. White wins.") if winner == "w" else _("Checkmate. Black wins.")
            return _("Checkmate. You win!") if winner == self.human else _("Checkmate. You lose.")
        return {
            "stalemate": _("Draw by stalemate."),
            "fifty-move": _("Draw by the fifty-move rule."),
            "repetition": _("Draw by repetition."),
            "insufficient material": _("Draw: not enough pieces to mate."),
        }[reason]
