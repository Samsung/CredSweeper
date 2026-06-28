import random
import unittest
from argparse import ArgumentTypeError

import pytest

from credsweeper import ThresholdPreset, Severity
from credsweeper.cli import positive_int, threshold_or_float_or_zero, logger_levels, severity_levels
from credsweeper.logger.logger import Logger


class TestCli(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def tearDown(self):
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_positive_int_n(self):
        i = random.randint(-100, 0)
        with self.assertRaises(ArgumentTypeError):
            positive_int(i)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_positive_int_p(self):
        i = random.randint(1, 100)
        self.assertEqual(positive_int(i), i)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_threshold_or_float_or_zero_n(self):
        with pytest.raises(ArgumentTypeError):
            threshold_or_float_or_zero("DUMMY STRING")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_threshold_or_float_or_zero_p(self):
        f = random.random()
        self.assertEqual(f, threshold_or_float_or_zero(str(f)))
        self.assertEqual(42.0, threshold_or_float_or_zero("42"))
        self.assertIsInstance(threshold_or_float_or_zero('0'), int)
        t = random.choice(list(ThresholdPreset))
        self.assertEqual(t, threshold_or_float_or_zero(t.value))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_logger_levels_n(self):
        with pytest.raises(ArgumentTypeError):
            logger_levels("NotALogLevel")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_logger_levels_p(self):
        self.assertEqual("DEBUG", logger_levels("DeBuG"))
        t = random.choice(list(Logger.LEVELS.keys()))
        self.assertEqual(t, logger_levels(t))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_severity_levels_n(self):
        with pytest.raises(ArgumentTypeError):
            severity_levels("NotASeverityLevel")

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_severity_levels_p(self):
        self.assertEqual(Severity.LOW, severity_levels("LoW"))
        t = random.choice(list(Severity))
        self.assertEqual(t, severity_levels(t))
