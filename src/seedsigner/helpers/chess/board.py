"""
Chess rules: board state, legal moves, and how a game ends.

The board is a 10x12 "mailbox": 120 cells with a two-cell border of off-board
markers, so a knight or slider stepping off the edge lands on a marker instead
of wrapping around. a8 is index 21 and h1 is index 98.

Pieces are FEN letters, upper case for White: "PNBRQK" / "pnbrqk". An empty
square is "." and an off-board cell is " ".

A move is a tuple (from_index, to_index, promotion), promotion being "" or one
of "q", "r", "b", "n".
"""

START_FEN = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"

EMPTY = "."
OFF = " "

KNIGHT_STEPS = (-21, -19, -12, -8, 8, 12, 19, 21)
DIAGONALS = (-11, -9, 9, 11)
ORTHOGONALS = (-10, -1, 1, 10)
KING_STEPS = DIAGONALS + ORTHOGONALS
PROMOTIONS = ("q", "r", "b", "n")

# Castling rights lost when anything moves from or to these squares.
_RIGHTS_TOUCHED = {95: "KQ", 91: "Q", 98: "K", 25: "kq", 21: "q", 28: "k"}
# King destination -> (rook from, rook to).
_CASTLE_ROOK = {97: (98, 96), 93: (91, 94), 27: (28, 26), 23: (21, 24)}


def square_index(name: str) -> int:
    """"e4" -> mailbox index. Raises ValueError for anything else."""
    if len(name) != 2 or name[0] not in "abcdefgh" or name[1] not in "12345678":
        raise ValueError(f"not a square: {name!r}")
    return 21 + "abcdefgh".index(name[0]) + (8 - int(name[1])) * 10


def square_name(index: int) -> str:
    return "abcdefgh"[index % 10 - 1] + str(8 - (index // 10 - 2))


def is_white(piece: str) -> bool:
    return piece.isupper()


class Board:
    def __init__(self, fen: str = START_FEN):
        self._set_fen(fen)

    @classmethod
    def from_fen(cls, fen: str) -> "Board":
        return cls(fen)

    # ------------------------------------------------------------------ FEN

    def _set_fen(self, fen: str):
        fields = fen.split()
        if len(fields) not in (4, 6):
            raise ValueError("a FEN has 4 or 6 fields")
        placement, turn, castling, ep = fields[:4]
        halfmove, fullmove = fields[4:6] if len(fields) == 6 else ("0", "1")

        rows = placement.split("/")
        if len(rows) != 8:
            raise ValueError("a FEN board has 8 ranks")
        board = [OFF] * 120
        for r, row in enumerate(rows):
            f = 0
            for ch in row:
                if ch in "12345678":
                    for _ in range(int(ch)):
                        if f > 7:
                            raise ValueError("a rank has 8 files")
                        board[21 + r * 10 + f] = EMPTY
                        f += 1
                elif ch in "PNBRQKpnbrqk":
                    if f > 7:
                        raise ValueError("a rank has 8 files")
                    board[21 + r * 10 + f] = ch
                    f += 1
                else:
                    raise ValueError(f"not a piece: {ch!r}")
            if f != 8:
                raise ValueError("a rank has 8 files")

        if board.count("K") != 1 or board.count("k") != 1:
            raise ValueError("each side needs exactly one king")
        if turn not in ("w", "b"):
            raise ValueError("side to move is w or b")
        if castling != "-" and (not set(castling) <= set("KQkq") or len(set(castling)) != len(castling)):
            raise ValueError("castling rights are - or a subset of KQkq")
        if ep == "-":
            ep_index = None
        else:
            ep_index = square_index(ep)
            if ep[1] not in "36":
                raise ValueError("an en passant square is on rank 3 or 6")
        try:
            halfmove, fullmove = int(halfmove), int(fullmove)
        except ValueError:
            raise ValueError("move counters are numbers")
        if halfmove < 0 or fullmove < 1:
            raise ValueError("move counters are out of range")

        self.board = board
        self.turn = turn
        self.castling = "".join(c for c in "KQkq" if c in castling)
        self.ep = ep_index
        self.halfmove = halfmove
        self.fullmove = fullmove
        self.kings = {"w": board.index("K"), "b": board.index("k")}
        self._undo = []
        self._keys = [self._key()]

    def fen(self) -> str:
        rows = []
        for r in range(8):
            row, empty = "", 0
            for f in range(8):
                p = self.board[21 + r * 10 + f]
                if p == EMPTY:
                    empty += 1
                else:
                    if empty:
                        row += str(empty)
                        empty = 0
                    row += p
            if empty:
                row += str(empty)
            rows.append(row)
        ep = square_name(self.ep) if self.ep is not None else "-"
        return f"{'/'.join(rows)} {self.turn} {self.castling or '-'} {ep} {self.halfmove} {self.fullmove}"

    # -------------------------------------------------------------- queries

    def piece_at(self, square: str) -> str:
        return self.board[square_index(square)]

    def king_square(self, color: str) -> str:
        return square_name(self.kings[color])

    def attacked(self, index: int, by: str) -> bool:
        """Whether side `by` ("w"/"b") attacks the square at `index`."""
        b = self.board
        white = by == "w"
        if white:
            if b[index + 9] == "P" or b[index + 11] == "P":
                return True
        elif b[index - 9] == "p" or b[index - 11] == "p":
            return True
        knight, king = ("N", "K") if white else ("n", "k")
        for step in KNIGHT_STEPS:
            if b[index + step] == knight:
                return True
        for step in KING_STEPS:
            if b[index + step] == king:
                return True
        diag = ("B", "Q") if white else ("b", "q")
        for step in DIAGONALS:
            s = index + step
            while b[s] == EMPTY:
                s += step
            if b[s] in diag:
                return True
        line = ("R", "Q") if white else ("r", "q")
        for step in ORTHOGONALS:
            s = index + step
            while b[s] == EMPTY:
                s += step
            if b[s] in line:
                return True
        return False

    def in_check(self, color: str = None) -> bool:
        color = color or self.turn
        return self.attacked(self.kings[color], "b" if color == "w" else "w")

    # ------------------------------------------------------ move generation

    def pseudo_legal_moves(self):
        """Every move by the side to move, ignoring whether it leaves its own king in check."""
        b = self.board
        white = self.turn == "w"
        moves = []
        for s in range(21, 99):
            p = b[s]
            if p == EMPTY or p == OFF or p.isupper() != white:
                continue
            kind = p.upper()
            if kind == "P":
                self._pawn_moves(s, white, moves)
            elif kind == "N" or kind == "K":
                for step in (KNIGHT_STEPS if kind == "N" else KING_STEPS):
                    t = s + step
                    q = b[t]
                    if q == EMPTY or (q != OFF and q.isupper() != white):
                        moves.append((s, t, ""))
                if kind == "K":
                    self._castling_moves(white, moves)
            else:
                steps = DIAGONALS if kind == "B" else ORTHOGONALS if kind == "R" else KING_STEPS
                for step in steps:
                    t = s + step
                    while True:
                        q = b[t]
                        if q == EMPTY:
                            moves.append((s, t, ""))
                        else:
                            if q != OFF and q.isupper() != white:
                                moves.append((s, t, ""))
                            break
                        t += step
        return moves

    def _pawn_moves(self, s, white, moves):
        b = self.board
        forward = -10 if white else 10
        start_row = 8 if white else 3
        last_row = 2 if white else 9

        def add(t):
            if t // 10 == last_row:
                for promo in PROMOTIONS:
                    moves.append((s, t, promo))
            else:
                moves.append((s, t, ""))

        one = s + forward
        if b[one] == EMPTY:
            add(one)
            if s // 10 == start_row and b[one + forward] == EMPTY:
                moves.append((s, one + forward, ""))
        for t in (one - 1, one + 1):
            q = b[t]
            if q != EMPTY and q != OFF and q.isupper() != white:
                add(t)
            elif t == self.ep:
                add(t)

    def _castling_moves(self, white, moves):
        b = self.board
        if white:
            if self.kings["w"] != 95 or self.attacked(95, "b"):
                return
            if "K" in self.castling and b[98] == "R" and b[96] == EMPTY and b[97] == EMPTY \
                    and not self.attacked(96, "b") and not self.attacked(97, "b"):
                moves.append((95, 97, ""))
            if "Q" in self.castling and b[91] == "R" and b[94] == EMPTY and b[93] == EMPTY \
                    and b[92] == EMPTY and not self.attacked(94, "b") and not self.attacked(93, "b"):
                moves.append((95, 93, ""))
        else:
            if self.kings["b"] != 25 or self.attacked(25, "w"):
                return
            if "k" in self.castling and b[28] == "r" and b[26] == EMPTY and b[27] == EMPTY \
                    and not self.attacked(26, "w") and not self.attacked(27, "w"):
                moves.append((25, 27, ""))
            if "q" in self.castling and b[21] == "r" and b[24] == EMPTY and b[23] == EMPTY \
                    and b[22] == EMPTY and not self.attacked(24, "w") and not self.attacked(23, "w"):
                moves.append((25, 23, ""))

    def legal_moves(self):
        us = self.turn
        them = "b" if us == "w" else "w"
        legal = []
        for move in self.pseudo_legal_moves():
            self._make(move)
            if not self.attacked(self.kings[us], them):
                legal.append(move)
            self._unmake()
        return legal

    def is_capture(self, move) -> bool:
        return self.board[move[1]] != EMPTY or (move[1] == self.ep and self.board[move[0]] in "Pp")

    # --------------------------------------------------------- make/unmake

    def _make(self, move):
        b = self.board
        s, t, promo = move
        piece = b[s]
        captured = b[t]
        white = piece.isupper()
        ep_victim = None
        if piece in "Pp" and t == self.ep and captured == EMPTY:
            ep_victim = t + 10 if white else t - 10
            captured = b[ep_victim]
            b[ep_victim] = EMPTY

        self._undo.append((move, piece, captured, ep_victim, self.castling, self.ep,
                           self.halfmove, self.fullmove, self.kings["w"], self.kings["b"]))

        b[t] = (promo.upper() if white else promo) if promo else piece
        b[s] = EMPTY
        if piece in "Kk":
            self.kings["w" if white else "b"] = t
            if abs(t - s) == 2:
                rook_from, rook_to = _CASTLE_ROOK[t]
                b[rook_to] = b[rook_from]
                b[rook_from] = EMPTY
        if self.castling:
            for sq in (s, t):
                lost = _RIGHTS_TOUCHED.get(sq)
                if lost:
                    self.castling = "".join(c for c in self.castling if c not in lost)
        self.ep = (s + t) // 2 if piece in "Pp" and abs(t - s) == 20 else None
        self.halfmove = 0 if piece in "Pp" or captured != EMPTY else self.halfmove + 1
        if not white:
            self.fullmove += 1
        self.turn = "b" if white else "w"

    def _unmake(self):
        (move, piece, captured, ep_victim, self.castling, self.ep,
         self.halfmove, self.fullmove, wk, bk) = self._undo.pop()
        b = self.board
        s, t, _ = move
        b[s] = piece
        if ep_victim is not None:
            b[t] = EMPTY
            b[ep_victim] = captured
        else:
            b[t] = captured
        if piece in "Kk" and abs(t - s) == 2:
            rook_from, rook_to = _CASTLE_ROOK[t]
            b[rook_from] = b[rook_to]
            b[rook_to] = EMPTY
        self.kings["w"], self.kings["b"] = wk, bk
        self.turn = "w" if piece.isupper() else "b"

    def push(self, move):
        """Play a move and record the position for repetition."""
        self._make(move)
        self._keys.append(self._key())

    def pop(self):
        """Take back the last move played with push()."""
        self._keys.pop()
        self._unmake()

    @property
    def move_count(self) -> int:
        return len(self._keys) - 1

    def _key(self) -> str:
        return "".join(self.board[21:99]) + self.turn + self.castling + str(self.ep)

    def repetitions(self) -> int:
        return self._keys.count(self._keys[-1])

    # ------------------------------------------------------------ outcome

    def outcome(self):
        """
        None while the game goes on, else (reason, winner): winner is "w" or "b"
        for checkmate and None for every draw.
        """
        if not self.legal_moves():
            if self.in_check():
                return ("checkmate", "b" if self.turn == "w" else "w")
            return ("stalemate", None)
        if self.halfmove >= 100:
            return ("fifty-move", None)
        if self.repetitions() >= 3:
            return ("repetition", None)
        if self.insufficient_material():
            return ("insufficient material", None)
        return None

    def insufficient_material(self) -> bool:
        others = [p for p in self.board[21:99] if p not in (EMPTY, OFF, "K", "k")]
        return not others or (len(others) == 1 and others[0] in "NBnb")

    # ------------------------------------------------------------- UCI text

    def to_uci(self, move) -> str:
        return square_name(move[0]) + square_name(move[1]) + move[2]

    def parse_uci(self, text: str):
        """The legal move `text` names ("e2e4", "a7a8q"), or None."""
        try:
            s, t = square_index(text[0:2]), square_index(text[2:4])
        except ValueError:
            return None
        promo = text[4:]
        for move in self.legal_moves():
            if move[0] == s and move[1] == t and move[2] == promo:
                return move
        return None
