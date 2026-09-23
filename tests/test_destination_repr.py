from seedsigner.views.view import Destination, MainMenuView


def test_destination_repr_redacts_password_fields():
    dest = Destination(
        MainMenuView,
        view_args={"password": "super-secret", "label": "demo", "nested": {"passphrase": "abc"}},
    )

    rep = repr(dest)

    assert "super-secret" not in rep
    assert "abc" not in rep
    assert "***redacted***" in rep
    assert "demo" in rep


def test_destination_repr_keeps_non_sensitive_fields():
    dest = Destination(MainMenuView, view_args={"title": "Password", "index": 7})
    rep = repr(dest)

    assert "Password" in rep
    assert "7" in rep


def test_destination_repr_redacts_entropy_fields():
    """Raw entropy sources (dice rolls, coin flips, BIP85 entropy bytes) must
    never leak into logs via Destination.__repr__."""
    dest = Destination(
        MainMenuView,
        view_args={
            "roll_data": "123451234512345",
            "entropy": b"\xde\xad\xbe\xef",
            "entropy_bytes": b"\xca\xfe\xba\xbe",
            "entropy_bytes_override": b"\x01\x02\x03\x04",
            "coin_flips": "10110010101",
            "nested": {"roll_data": "11112222"},
            "in_list": [{"entropy_bytes": b"\x99"}],
        },
    )

    rep = repr(dest)

    for leaked in ("123451234512345", "deadbeef", "cafebabe", "10110010101", "11112222"):
        assert leaked not in rep
    assert rep.count("***redacted***") == 7


def test_destination_repr_redacts_entropy_entropy_source_still_shown():
    """entropy_source is a mode name (e.g. 'dice'), not entropy itself."""
    dest = Destination(
        MainMenuView,
        view_args={"entropy_source": "dice_rolls", "roll_data": "1111"},
    )
    rep = repr(dest)

    assert "dice_rolls" in rep
    assert "1111" not in rep
