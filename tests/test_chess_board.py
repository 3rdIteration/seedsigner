"""
Rules of the chess game under Tools.

Move generation is checked by perft: the number of leaf positions reachable in
exactly N moves from a position. The counts below are the published reference
values (chessprogramming.org "Perft Results"), and every rule -- castling out of
or through check, en passant exposing the king, promotion, pins -- changes them
if it is wrong. Depths are kept to what runs in a few seconds in CI.
"""
import pytest

from seedsigner.helpers.chess.board import Board, START_FEN


def perft(board: Board, depth: int) -> int:
    if depth == 0:
        return 1
    total = 0
    for move in board.legal_moves():
        board.push(move)
        total += perft(board, depth - 1)
        board.pop()
    return total


KIWIPETE = "r3k2r/p1ppqpb1/bn2pnp1/3PN3/1p2P3/2N2Q1p/PPPBBPPP/R3K2R w KQkq - 0 1"
POSITION_3 = "8/2p5/3p4/KP5r/1R3p1k/8/4P1P1/8 w - - 0 1"
POSITION_4 = "r3k2r/Pppp1ppp/1b3nbN/nP6/BBP1P3/q4N2/Pp1P2PP/R2Q1RK1 w kq - 0 1"
POSITION_5 = "rnbq1k1r/pp1Pbppp/2p5/8/2B5/8/PPP1NnPP/RNBQK2R w KQ - 1 8"
POSITION_6 = "r4rk1/1pp1qppp/p1np1n2/2b1p1B1/2B1P1b1/P1NP1N2/1PP1QPPP/R4RK1 w - - 0 10"


@pytest.mark.parametrize("fen, counts", [
    (START_FEN, [20, 400, 8902, 197281]),
    (KIWIPETE, [48, 2039, 97862]),
    (POSITION_3, [14, 191, 2812, 43238]),
    (POSITION_4, [6, 264, 9467]),
    (POSITION_5, [44, 1486, 62379]),
    (POSITION_6, [46, 2079, 89890]),
])
def test_perft_matches_the_reference_counts(fen, counts):
    board = Board.from_fen(fen)
    for depth, expected in enumerate(counts, start=1):
        assert perft(board, depth) == expected, f"depth {depth}"
    # push/pop left the position exactly as it was
    assert board.fen() == Board.from_fen(fen).fen()


@pytest.mark.parametrize("fen", [START_FEN, KIWIPETE, POSITION_4, POSITION_5])
def test_fen_round_trips(fen):
    assert Board.from_fen(fen).fen() == fen


def test_uci_round_trip_and_promotion():
    board = Board.from_fen("8/P6k/8/8/8/8/8/K7 w - - 0 1")
    moves = {board.to_uci(m) for m in board.legal_moves()}
    assert {"a7a8q", "a7a8r", "a7a8b", "a7a8n"} <= moves
    board.push(board.parse_uci("a7a8n"))
    assert board.piece_at("a8") == "N"


def test_parse_uci_refuses_an_illegal_move():
    board = Board()
    assert board.parse_uci("e2e5") is None
    assert board.parse_uci("e1e2") is None
    assert board.parse_uci("zz") is None


def test_en_passant_capture_removes_the_pawn():
    board = Board.from_fen("4k3/8/8/3pP3/8/8/8/4K3 w - d6 0 1")
    board.push(board.parse_uci("e5d6"))
    assert board.piece_at("d5") == "."
    assert board.piece_at("d6") == "P"


def test_castling_moves_the_rook_and_loses_rights():
    board = Board.from_fen("r3k2r/8/8/8/8/8/8/R3K2R w KQkq - 0 1")
    board.push(board.parse_uci("e1g1"))
    assert board.piece_at("f1") == "R" and board.piece_at("h1") == "."
    assert "K" not in board.fen().split()[2] and "Q" not in board.fen().split()[2]


def test_cannot_castle_through_check():
    board = Board.from_fen("4k3/8/8/8/8/8/5r2/4K2R w K - 0 1")
    assert board.parse_uci("e1g1") is None


def test_checkmate():
    board = Board.from_fen("rnb1kbnr/pppp1ppp/8/4p3/6Pq/5P2/PPPPP2P/RNBQKBNR w KQkq - 1 3")
    assert board.outcome() == ("checkmate", "b")


def test_stalemate():
    board = Board.from_fen("7k/5Q2/6K1/8/8/8/8/8 b - - 0 1")
    assert board.outcome() == ("stalemate", None)


def test_fifty_move_rule():
    board = Board.from_fen("4k3/8/8/8/8/8/8/4K2R w - - 100 80")
    assert board.outcome() == ("fifty-move", None)


def test_threefold_repetition():
    board = Board.from_fen("4k3/8/8/8/8/8/8/4K2R w - - 0 1")
    for uci in ["h1h2", "e8e7", "h2h1", "e7e8"] * 2:
        assert board.outcome() is None
        board.push(board.parse_uci(uci))
    assert board.outcome() == ("repetition", None)


@pytest.mark.parametrize("fen", [
    "4k3/8/8/8/8/8/8/4K3 w - - 0 1",
    "4k3/8/8/8/8/8/8/4KB2 w - - 0 1",
    "4k3/8/8/8/8/8/8/4KN2 w - - 0 1",
])
def test_insufficient_material(fen):
    assert Board.from_fen(fen).outcome() == ("insufficient material", None)


def test_rook_is_enough_material():
    assert Board.from_fen("4k3/8/8/8/8/8/8/4K2R w - - 0 1").outcome() is None


def test_in_check_and_king_square():
    board = Board.from_fen("4k3/8/8/8/8/8/4r3/4K3 w - - 0 1")
    assert board.in_check()
    assert board.king_square("w") == "e1"


@pytest.mark.parametrize("fen", [
    "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR x KQkq - 0 1",  # bad side to move
    "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP w KQkq - 0 1",  # 7 ranks
    "rnbqkbnr/pppppppp/9/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1",  # 9 files
    "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQXBNR w KQkq - 0 1",  # bad piece
    "8/8/8/8/8/8/8/8 w - - 0 1",  # no kings
])
def test_bad_fen_is_refused(fen):
    with pytest.raises(ValueError):
        Board.from_fen(fen)
