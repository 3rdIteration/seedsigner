import pytest
from seedsigner.gui.components import reflow_text_for_width, GUIConstants, Fonts


def _half_text_width(text, font_name, font_size):
    font = Fonts.get_font(font_name=font_name, size=font_size)
    left, top, right, bottom = font.getbbox(text, anchor="ls")
    return (right - left) // 2


def test_reflow_text_wraps_long_password_with_leading_space():
    font_name = GUIConstants.get_body_font_name()
    font_size = GUIConstants.get_body_font_size()
    text = ' Password:"mmmmmmmmmdddddde"'
    width = _half_text_width(text, font_name, font_size)
    lines = reflow_text_for_width(text=text, width=width, font_name=font_name, font_size=font_size)
    assert len(lines) > 1


def test_reflow_text_wraps_overlong_word_after_space():
    font_name = GUIConstants.get_body_font_name()
    font_size = GUIConstants.get_body_font_size()
    long_word = "mmmmmmmmmdddddde"
    text = f'Label {long_word}'
    width = _half_text_width(text, font_name, font_size)
    lines = reflow_text_for_width(text=text, width=width, font_name=font_name, font_size=font_size)
    assert len(lines) > 1
    assert lines[0]["text"].startswith("Label")
