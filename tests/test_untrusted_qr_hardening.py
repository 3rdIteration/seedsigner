"""
Scanned QR payloads are untrusted input. Each of these used to escape as an
uncaught exception -- the System Error screen, or in the UR2 case a device that
appears frozen -- instead of being turned away as an invalid QR. Mirrors fixes
proposed upstream (SeedSigner #967, #968, #970, #971).
"""
import time

import pytest

from seedsigner.helpers import embit_utils
from seedsigner.models.decode_qr import DecodeQR, DecodeQRStatus
from seedsigner.models.qr_type import QRType
from seedsigner.models.settings_definition import SettingsConstants


def decode(data: str):
    decoder = DecodeQR(wordlist_language_code=SettingsConstants.WORDLIST_LANGUAGE__ENGLISH)
    return decoder, decoder.add_data(data)


class TestSignMessageQr:

    @pytest.mark.parametrize("payload", [
        "signmessage",
        "signmessage m/84h/0h/0h/0/0",
        "signmessage m/84h/0h/0h/0/0 nocolon",
    ])
    def test_malformed_payload_is_invalid_not_a_crash(self, payload):
        _decoder, status = decode(payload)
        assert status == DecodeQRStatus.INVALID

    def test_message_keeps_spaces_and_a_second_format_marker(self):
        decoder, status = decode("signmessage m/84h/0h/0h/0/0 ascii:hello world ascii:again")
        assert status == DecodeQRStatus.COMPLETE
        assert decoder.get_qr_data()["message"] == "hello world ascii:again"


class TestStandardSeedQr:

    def test_bad_checksum_is_invalid(self):
        """'abandon' x12 is twelve valid words with an invalid checksum."""
        _decoder, status = decode("0000" * 12)
        assert status == DecodeQRStatus.INVALID

    def test_valid_seedqr_still_decodes(self):
        """'abandon' x11 + 'about' (word 3) is the canonical valid 12-word mnemonic."""
        decoder, status = decode("0000" * 11 + "0003")
        assert status == DecodeQRStatus.COMPLETE
        assert decoder.get_seed_phrase()[-1] == "about"

    def test_a_digit_run_inside_other_data_is_not_a_seedqr(self):
        assert DecodeQR.detect_segment_type("settings::v1 " + "1" * 48) != QRType.SEED__SEEDQR

    def test_whole_payload_seedqr_is_detected(self):
        assert DecodeQR.detect_segment_type("0000" * 11 + "0003") == QRType.SEED__SEEDQR


class TestParseDerivationPath:

    @pytest.mark.parametrize("path", ["", "m", "x", "m/", "m/84h", "m/48h/0h/0h/2h/0/0"])
    def test_unparseable_path_is_an_unclean_match(self, path):
        assert embit_utils.parse_derivation_path(path)["clean_match"] is False

    def test_standard_path_still_parses(self):
        details = embit_utils.parse_derivation_path("m/84h/0h/0h/0/5")
        assert details["clean_match"] is True
        assert details["index"] == 5


class TestUR2SeqLenBound:

    @staticmethod
    def _part(seq_num, seq_len):
        from seedsigner.helpers.ur2.fountain_encoder import Part
        return Part(seq_num=seq_num, seq_len=seq_len, message_len=32, checksum=0, data=b"\x00" * 32)

    def test_implausible_part_count_is_rejected_quickly(self):
        from seedsigner.helpers.ur2.fountain_decoder import FountainDecoder, MAX_SEQ_LEN

        decoder = FountainDecoder()
        started = time.monotonic()
        assert decoder.receive_part(self._part(seq_num=MAX_SEQ_LEN * 10, seq_len=MAX_SEQ_LEN * 10)) is False
        assert time.monotonic() - started < 1
        assert decoder.expected_part_indexes is None

    def test_plausible_part_count_is_accepted(self):
        from seedsigner.helpers.ur2.fountain_decoder import FountainDecoder

        decoder = FountainDecoder()
        assert decoder.validate_part(self._part(seq_num=1, seq_len=10)) is True
