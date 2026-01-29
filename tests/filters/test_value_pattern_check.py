import unittest
from unittest.mock import MagicMock

import pytest

from credsweeper.common.constants import DEFAULT_PATTERN_LEN
from credsweeper.config.config import Config
from credsweeper.filters import ValuePatternCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValuePatternCheck(unittest.TestCase):

    def setUp(self) -> None:
        self.config = MagicMock(spec=Config)

    def test_min_patter_len_n(self) -> None:
        with self.assertRaises(ValueError):
            ValuePatternCheck(self.config, DEFAULT_PATTERN_LEN - 1)

    def test_init_n(self) -> None:
        test_filter = ValuePatternCheck(self.config)
        self.assertEqual(-1, test_filter.pattern_len)
        self.assertListEqual([4, 4, 4, 4, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13], test_filter.pattern_lengths)

    def test_init_p(self) -> None:
        test_filter = ValuePatternCheck(self.config, DEFAULT_PATTERN_LEN)
        self.assertEqual(DEFAULT_PATTERN_LEN, test_filter.pattern_len)
        self.assertListEqual([4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4], test_filter.pattern_lengths)

    def test_duple_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).duple_pattern_check("20201030", DEFAULT_PATTERN_LEN))
        self.assertFalse(ValuePatternCheck(self.config).duple_pattern_check("01000101", DEFAULT_PATTERN_LEN))
        self.assertFalse(ValuePatternCheck(self.config).duple_pattern_check("10305070", DEFAULT_PATTERN_LEN))
        self.assertFalse(ValuePatternCheck(self.config).duple_pattern_check("11224433", DEFAULT_PATTERN_LEN))
        self.assertFalse(ValuePatternCheck(self.config).duple_pattern_check("11000000", DEFAULT_PATTERN_LEN))

    def test_duple_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).duple_pattern_check("11223344", DEFAULT_PATTERN_LEN))
        self.assertTrue(ValuePatternCheck(self.config).duple_pattern_check("010101010", DEFAULT_PATTERN_LEN))
        self.assertTrue(ValuePatternCheck(self.config).duple_pattern_check("40302010", DEFAULT_PATTERN_LEN))

    def test_equal_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).equal_pattern_check("Crackle123", DEFAULT_PATTERN_LEN))
        self.assertFalse(ValuePatternCheck(self.config).equal_pattern_check("IEEE32441", DEFAULT_PATTERN_LEN))
        self.assertFalse(ValuePatternCheck(self.config).equal_pattern_check("Pass...", DEFAULT_PATTERN_LEN))
        self.assertFalse(ValuePatternCheck(pattern_len=4).equal_pattern_check("Pass:\\n        Crackle123", 5))

    def test_equal_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).equal_pattern_check("AAAABCD", DEFAULT_PATTERN_LEN))
        self.assertTrue(ValuePatternCheck(pattern_len=4).equal_pattern_check("-------BEGIN", DEFAULT_PATTERN_LEN))
        self.assertFalse(ValuePatternCheck(pattern_len=8).equal_pattern_check("-------BEGIN", DEFAULT_PATTERN_LEN))

    def test_ascending_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).ascending_pattern_check("Crackle123", DEFAULT_PATTERN_LEN))
        self.assertFalse(
            ValuePatternCheck(pattern_len=4).ascending_pattern_check("Crackle987654321", DEFAULT_PATTERN_LEN))

    def test_ascending_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).ascending_pattern_check("Crackle1234", DEFAULT_PATTERN_LEN))
        self.assertTrue(ValuePatternCheck(pattern_len=4).ascending_pattern_check("Cracklefgh", DEFAULT_PATTERN_LEN))

    def test_descending_pattern_check_n(self) -> None:
        self.assertFalse(ValuePatternCheck(self.config).descending_pattern_check("Crackle321", DEFAULT_PATTERN_LEN))
        self.assertFalse(ValuePatternCheck(pattern_len=4).descending_pattern_check("Crackle123456789", 5))

    def test_descending_pattern_check_p(self) -> None:
        self.assertTrue(ValuePatternCheck(self.config).descending_pattern_check("Crackle4321", DEFAULT_PATTERN_LEN))
        self.assertTrue(ValuePatternCheck(pattern_len=4).descending_pattern_check("Crackledcba", DEFAULT_PATTERN_LEN))


class TestValuePatternCheckFixture:

    def test_value_similarity_check_p(self, file_path: pytest.fixture, config: Config,
                                      success_line: pytest.fixture) -> None:
        line_data = get_line_data(file_path, line=success_line, pattern=LINE_VALUE_PATTERN)
        assert ValuePatternCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", [
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526",
        "c0ffeecc-dead-beef-cafe-1a2b3c4d5e6f", "123456ff-dead-beef-cafe-7a24ca6a903c",
        "ffffff00-dead-beef-cafe-4a25c06a902d", "Crackle4444", "Crackle1234", "Crackle4321", "@$%", "a5", "_"
    ])
    def test_value_similarity_check_n(self, file_path: pytest.fixture, config: Config, line: str) -> None:
        line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValuePatternCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
