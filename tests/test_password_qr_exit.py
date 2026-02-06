from seedsigner.views import tools_views


def test_text_qr_done_destination_can_return_home():
    dest = tools_views._text_qr_done_destination(return_to_home=True)
    assert dest.View_cls is tools_views.ToolsMenuView
    assert dest.clear_history is True


def test_password_review_show_qr_small_routes_home_flow(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordReviewView)
    view.password = "abc123"

    monkeypatch.setattr(
        tools_views.ToolsPasswordReviewView,
        "run_screen",
        lambda self, *_args, **_kwargs: 0,
    )

    from seedsigner.helpers import qr as qr_mod
    monkeypatch.setattr(qr_mod.QR, "qrsize", lambda self, data: 21)

    dest = tools_views.ToolsPasswordReviewView.run(view)

    assert dest.View_cls is tools_views.ToolsTextQRTranscribeModePromptView
    assert dest.view_args["return_to_home"] is True


def test_password_review_show_qr_large_routes_home_flow(monkeypatch):
    view = object.__new__(tools_views.ToolsPasswordReviewView)
    view.password = "x" * 300

    monkeypatch.setattr(
        tools_views.ToolsPasswordReviewView,
        "run_screen",
        lambda self, *_args, **_kwargs: 0,
    )

    from seedsigner.helpers import qr as qr_mod
    monkeypatch.setattr(qr_mod.QR, "qrsize", lambda self, data: 80)

    dest = tools_views.ToolsPasswordReviewView.run(view)

    assert dest.View_cls is tools_views.ToolsTextQRFullScreenModeView
    assert dest.view_args["return_to_home"] is True
