"""The device's chess opponent: plays legal moves, sees short mates, keeps to its time."""
import random

import pytest

from seedsigner.helpers.chess.board import Board, START_FEN
from seedsigner.helpers.chess.search import best_move


def uci(board, move):
    return board.to_uci(move) if move else None


@pytest.mark.parametrize("fen, mate", [
    ("6k1/5ppp/8/8/8/8/5PPP/3R2K1 w - - 0 1", "d1d8"),  # back rank
    ("k7/8/1K6/8/8/8/8/7Q w - - 0 1", "h1h8"),  # queen along the back rank
    ("r1bqkbnr/pppp1ppp/2n5/4p3/2B1P3/5Q2/PPPP1PPP/RNB1K1NR w KQkq - 4 4", "f3f7"),  # scholar's mate
])
def test_finds_mate_in_one(fen, mate):
    board = Board(fen)
    move = best_move(board, max_depth=2)
    board.push(move)
    assert board.outcome() == ("checkmate", "w"), f"played {board.to_uci(move)}"


def test_finds_mate_in_two():
    # Two rooks: one cuts off the seventh rank, the other mates on the eighth.
    board = Board("7k/8/8/8/8/8/R7/1R4K1 w - - 0 1")
    move = best_move(board, max_depth=4)
    board.push(move)
    reply = best_move(board, max_depth=3)
    board.push(reply)
    board.push(best_move(board, max_depth=2))
    assert board.outcome() == ("checkmate", "w")


def test_takes_a_hanging_queen():
    board = Board("4k3/8/8/3q4/8/8/3R4/4K3 w - - 0 1")
    assert uci(board, best_move(board, max_depth=2)) == "d2d5"


def test_no_move_when_the_game_is_over():
    assert best_move(Board("7k/5Q2/6K1/8/8/8/8/8 b - - 0 1"), max_depth=2) is None


def test_board_is_left_as_it_was():
    board = Board("r3k2r/p1ppqpb1/bn2pnp1/3PN3/1p2P3/2N2Q1p/PPPBBPPP/R3K2R w KQkq - 0 1")
    before = board.fen()
    best_move(board, max_depth=3)
    assert board.fen() == before and board.move_count == 0


class FakeClock:
    """Advances a fixed step every time it is read, like a slow CPU would."""
    def __init__(self, step):
        self.now, self.step = 0.0, step

    def __call__(self):
        self.now += self.step
        return self.now


def test_keeps_to_its_time_budget():
    clock = FakeClock(0.001)
    board = Board(START_FEN)
    before = board.fen()
    move = best_move(board, time_budget=0.5, clock=clock)
    assert move in board.legal_moves()
    # a little slack for the reads that land after the deadline is noticed
    assert clock.now < 0.6
    assert board.fen() == before


def test_stop_request_returns_a_legal_move_quickly():
    board = Board(START_FEN)
    calls = {"n": 0}

    def stop():
        calls["n"] += 1
        return calls["n"] > 50

    move = best_move(board, time_budget=60, should_stop=stop)
    assert move in board.legal_moves()


def test_always_plays_a_legal_move():
    rng = random.Random(1)
    for game in range(6):
        board = Board()
        for ply in range(40):
            if board.outcome():
                break
            if ply % 2:
                move = rng.choice(board.legal_moves())
            else:
                move = best_move(board, max_depth=2, rng=random.Random(game))
                assert move in board.legal_moves()
            board.push(move)
