"""
The device's chess opponent.

Negamax with alpha-beta pruning, a capture-only quiescence search at the
leaves, and iterative deepening: it searches one move deep, then two, and so on
until its time runs out, then plays the best move of the last depth it
finished. Strength therefore follows the CPU and the time allowed, so the same
levels work on a Pi Zero and on a desktop.

The evaluation is material plus piece-square tables (Tomasz Michniewski's
"Simplified Evaluation Function"), with a separate king table once the queens
and most pieces are gone.

`random` only breaks ties between equal moves so games vary; nothing here is
security-relevant.
"""
import random
import time

from .board import Board, EMPTY, OFF

MATE = 100_000
_INF = 10 * MATE
_CHECK_EVERY = 128  # nodes between clock / stop checks

VALUES = {"P": 100, "N": 320, "B": 330, "R": 500, "Q": 900, "K": 0}

# Rank 8 first, from White's side of the board.
_PST = {
    "P": [0, 0, 0, 0, 0, 0, 0, 0,
          50, 50, 50, 50, 50, 50, 50, 50,
          10, 10, 20, 30, 30, 20, 10, 10,
          5, 5, 10, 25, 25, 10, 5, 5,
          0, 0, 0, 20, 20, 0, 0, 0,
          5, -5, -10, 0, 0, -10, -5, 5,
          5, 10, 10, -20, -20, 10, 10, 5,
          0, 0, 0, 0, 0, 0, 0, 0],
    "N": [-50, -40, -30, -30, -30, -30, -40, -50,
          -40, -20, 0, 0, 0, 0, -20, -40,
          -30, 0, 10, 15, 15, 10, 0, -30,
          -30, 5, 15, 20, 20, 15, 5, -30,
          -30, 0, 15, 20, 20, 15, 0, -30,
          -30, 5, 10, 15, 15, 10, 5, -30,
          -40, -20, 0, 5, 5, 0, -20, -40,
          -50, -40, -30, -30, -30, -30, -40, -50],
    "B": [-20, -10, -10, -10, -10, -10, -10, -20,
          -10, 0, 0, 0, 0, 0, 0, -10,
          -10, 0, 5, 10, 10, 5, 0, -10,
          -10, 5, 5, 10, 10, 5, 5, -10,
          -10, 0, 10, 10, 10, 10, 0, -10,
          -10, 10, 10, 10, 10, 10, 10, -10,
          -10, 5, 0, 0, 0, 0, 5, -10,
          -20, -10, -10, -10, -10, -10, -10, -20],
    "R": [0, 0, 0, 0, 0, 0, 0, 0,
          5, 10, 10, 10, 10, 10, 10, 5,
          -5, 0, 0, 0, 0, 0, 0, -5,
          -5, 0, 0, 0, 0, 0, 0, -5,
          -5, 0, 0, 0, 0, 0, 0, -5,
          -5, 0, 0, 0, 0, 0, 0, -5,
          -5, 0, 0, 0, 0, 0, 0, -5,
          0, 0, 0, 5, 5, 0, 0, 0],
    "Q": [-20, -10, -10, -5, -5, -10, -10, -20,
          -10, 0, 0, 0, 0, 0, 0, -10,
          -10, 0, 5, 5, 5, 5, 0, -10,
          -5, 0, 5, 5, 5, 5, 0, -5,
          0, 0, 5, 5, 5, 5, 0, -5,
          -10, 5, 5, 5, 5, 5, 0, -10,
          -10, 0, 5, 0, 0, 0, 0, -10,
          -20, -10, -10, -5, -5, -10, -10, -20],
    "K": [-30, -40, -40, -50, -50, -40, -40, -30,
          -30, -40, -40, -50, -50, -40, -40, -30,
          -30, -40, -40, -50, -50, -40, -40, -30,
          -30, -40, -40, -50, -50, -40, -40, -30,
          -20, -30, -30, -40, -40, -30, -30, -20,
          -10, -20, -20, -20, -20, -20, -20, -10,
          20, 20, 0, 0, 0, 0, 20, 20,
          20, 30, 10, 0, 0, 10, 30, 20],
}
_KING_ENDGAME = [-50, -40, -30, -20, -20, -30, -40, -50,
                 -30, -20, -10, 0, 0, -10, -20, -30,
                 -30, -10, 20, 30, 30, 20, -10, -30,
                 -30, -10, 30, 40, 40, 30, -10, -30,
                 -30, -10, 30, 40, 40, 30, -10, -30,
                 -30, -10, 20, 30, 30, 20, -10, -30,
                 -30, -30, 0, 0, 0, 0, -30, -30,
                 -50, -30, -30, -30, -30, -30, -30, -50]


def _by_index(table):
    """64-entry table (rank 8 first) -> (white values, black values) by mailbox index."""
    white, black = [0] * 120, [0] * 120
    for r in range(8):
        for f in range(8):
            white[21 + r * 10 + f] = table[r * 8 + f]
            black[21 + r * 10 + f] = table[(7 - r) * 8 + f]
    return white, black


_SQUARE_VALUE = {}
for _kind, _table in _PST.items():
    _w, _b = _by_index(_table)
    _SQUARE_VALUE[_kind] = [v + VALUES[_kind] for v in _w]
    _SQUARE_VALUE[_kind.lower()] = [v + VALUES[_kind] for v in _b]
_KING_END = dict(zip("Kk", _by_index(_KING_ENDGAME)))


def evaluate(board: Board) -> int:
    """Centipawns from the side to move's point of view."""
    b = board.board
    score = 0
    material = 0
    for s in range(21, 99):
        p = b[s]
        if p == EMPTY or p == OFF:
            continue
        if p in "Kk":
            continue
        if p not in "Pp":
            material += VALUES[p.upper()]
        v = _SQUARE_VALUE[p][s]
        score += v if p.isupper() else -v
    # Endgame: few pieces left, the king should come to the centre.
    endgame = material <= 2600
    for side, sign in (("K", 1), ("k", -1)):
        s = board.kings["w" if side == "K" else "b"]
        score += sign * (_KING_END[side][s] if endgame else _SQUARE_VALUE[side][s])
    return score if board.turn == "w" else -score


class _Stop(Exception):
    pass


def _order_score(board: Board, move) -> int:
    b = board.board
    victim = b[move[1]]
    if victim != EMPTY:
        return 10 * VALUES[victim.upper()] - VALUES[b[move[0]].upper()] // 10 + 10_000
    if move[2]:
        return VALUES[move[2].upper()]
    return 0


class _Searcher:
    def __init__(self, board, deadline, clock, should_stop):
        self.board = board
        self.deadline = deadline
        self.clock = clock
        self.should_stop = should_stop
        self.nodes = 0

    def _tick(self):
        self.nodes += 1
        if self.nodes % _CHECK_EVERY == 0:
            if self.deadline is not None and self.clock() >= self.deadline:
                raise _Stop
            if self.should_stop is not None and self.should_stop():
                raise _Stop

    def _ordered(self, moves, first=None):
        board = self.board
        moves = sorted(moves, key=lambda m: _order_score(board, m), reverse=True)
        if first in moves:
            moves.remove(first)
            moves.insert(0, first)
        return moves

    def negamax(self, depth, alpha, beta, ply):
        self._tick()
        board = self.board
        if board.halfmove >= 100 or board.repetitions() >= 2:
            return 0
        if depth <= 0:
            return self.quiesce(alpha, beta)
        us = board.turn
        them = "b" if us == "w" else "w"
        any_legal = False
        for move in self._ordered(board.pseudo_legal_moves()):
            board.push(move)
            if board.attacked(board.kings[us], them):
                board.pop()
                continue
            any_legal = True
            score = -self.negamax(depth - 1, -beta, -alpha, ply + 1)
            board.pop()
            if score >= beta:
                return score
            if score > alpha:
                alpha = score
        if not any_legal:
            return -(MATE - ply) if board.in_check() else 0
        return alpha

    def quiesce(self, alpha, beta):
        self._tick()
        board = self.board
        stand = evaluate(board)
        if stand >= beta:
            return stand
        if stand > alpha:
            alpha = stand
        us = board.turn
        them = "b" if us == "w" else "w"
        noisy = [m for m in board.pseudo_legal_moves() if board.is_capture(m) or m[2] == "q"]
        for move in self._ordered(noisy):
            board.push(move)
            if board.attacked(board.kings[us], them):
                board.pop()
                continue
            score = -self.quiesce(-beta, -alpha)
            board.pop()
            if score >= beta:
                return score
            if score > alpha:
                alpha = score
        return alpha

    def root(self, moves, depth, first):
        alpha = -_INF
        best = None
        for move in self._ordered(moves, first):
            self.board.push(move)
            score = -self.negamax(depth - 1, -_INF, -alpha, 1)
            self.board.pop()
            if best is None or score > alpha:
                alpha, best = score, move
        return alpha, best


def best_move(board: Board, time_budget: float = None, max_depth: int = None,
              clock=time.monotonic, should_stop=None, rng: random.Random = None):
    """
    The move to play in `board`, or None when the side to move has none.

    Stops at `max_depth` plies, when `time_budget` seconds have passed, or when
    `should_stop()` returns True, whichever comes first, and always returns a
    legal move from the deepest search it finished (the first candidate if it
    finished none). The board is left exactly as it was given.
    """
    moves = board.legal_moves()
    if not moves:
        return None
    if len(moves) == 1:
        return moves[0]
    (rng or random.Random()).shuffle(moves)

    deadline = clock() + time_budget if time_budget is not None else None
    searcher = _Searcher(board, deadline, clock, should_stop)
    depth_limit = max_depth or 64
    undo_depth = board.move_count
    best = searcher._ordered(moves)[0]
    try:
        for depth in range(1, depth_limit + 1):
            score, move = searcher.root(moves, depth, best)
            best = move
            if abs(score) >= MATE - 100:
                break
    except _Stop:
        while board.move_count > undo_depth:
            board.pop()
    return best
