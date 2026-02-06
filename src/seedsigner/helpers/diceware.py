from __future__ import annotations

from pathlib import Path
from typing import Dict, List

_EFF_LARGE_PATH = (
    Path(__file__).resolve().parents[1] / "resources" / "diceware" / "eff_large_wordlist.txt"
)
_EFF_SHORT_PATH = (
    Path(__file__).resolve().parents[1] / "resources" / "diceware" / "eff_short_wordlist_1.txt"
)

_eff_large_words: List[str] | None = None
_eff_large_map: Dict[str, str] | None = None
_eff_short_map: Dict[str, str] | None = None


def _load_eff_large() -> None:
    global _eff_large_words, _eff_large_map
    if _eff_large_words is not None and _eff_large_map is not None:
        return
    words: List[str] = []
    word_map: Dict[str, str] = {}
    with _EFF_LARGE_PATH.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            key, word = line.split("\t", 1)
            words.append(word)
            word_map[key] = word
    _eff_large_words = words
    _eff_large_map = word_map


def eff_large_map() -> Dict[str, str]:
    _load_eff_large()
    return dict(_eff_large_map)


def eff_short_map() -> Dict[str, str]:
    global _eff_short_map
    if _eff_short_map is None:
        word_map: Dict[str, str] = {}
        with _EFF_SHORT_PATH.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                key, word = line.split("\t", 1)
                word_map[key] = word
        _eff_short_map = word_map
    return dict(_eff_short_map)


def diceware_words_from_rolls(rolls: str, word_map: Dict[str, str], rolls_per_word: int) -> List[str]:
    if len(rolls) % rolls_per_word != 0:
        raise ValueError("Roll count must be divisible by rolls per word")
    words = []
    for idx in range(0, len(rolls), rolls_per_word):
        key = rolls[idx : idx + rolls_per_word]
        word = word_map.get(key)
        if not word:
            raise ValueError("Invalid dice roll sequence")
        words.append(word)
    return words
