from seedsigner.helpers import password_generation


def test_dice_rolls_from_seed_is_deterministic():
    seed = bytes(range(64))
    rolls1 = password_generation.dice_rolls_from_seed(seed, sides=6, roll_count=50, base=1)
    rolls2 = password_generation.dice_rolls_from_seed(seed, sides=6, roll_count=50, base=1)
    assert rolls1 == rolls2
    assert len(rolls1) == 50
    assert set(rolls1).issubset(set("123456"))


def test_dice_rolls_from_seed_supports_zero_indexed_rolls():
    seed = bytes([7] * 64)
    rolls = password_generation.dice_rolls_from_seed(seed, sides=6, roll_count=50, base=0)
    assert len(rolls) == 50
    assert set(rolls).issubset(set("012345"))


def test_dice_roll_values_from_seed_supports_multi_digit_rolls():
    seed = bytes([3] * 64)
    rolls = password_generation.dice_roll_values_from_seed(seed, sides=20, roll_count=8, base=0)
    assert len(rolls) == 8
    assert all(0 <= roll <= 19 for roll in rolls)
