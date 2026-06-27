import random
import unittest
from argparse import ArgumentTypeError

import pytest

from credsweeper.cli import positive_int, threshold_or_float_or_zero


class TestCli(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def tearDown(self):
        pass

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_positive_int_p(self):
        i = random.randint(1, 100)
        self.assertEqual(positive_int(i), i)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_positive_int_n(self):
        i = random.randint(-100, 0)
        with self.assertRaises(ArgumentTypeError):
            positive_int(i)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_threshold_or_float_or_zero_p(self):
        f = random.random()
        self.assertEqual(f, threshold_or_float_or_zero(str(f)))
        self.assertEqual(42.0, threshold_or_float_or_zero("42"))
        self.assertIsInstance(threshold_or_float_or_zero('0'), int)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_threshold_or_float_or_zero_n(self):
        with pytest.raises(ArgumentTypeError):
            threshold_or_float_or_zero("DUMMY STRING")
