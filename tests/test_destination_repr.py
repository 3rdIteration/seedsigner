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
