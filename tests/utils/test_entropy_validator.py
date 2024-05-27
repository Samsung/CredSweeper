import sys
import unittest

import numpy as np

from credsweeper.common.constants import Chars
from credsweeper.utils import Util
from credsweeper.utils.entropy_validator import EntropyValidator


class TestUtils(unittest.TestCase):

    def test_validator_n(self):
        self.assertEqual("None None None", str(EntropyValidator(None)))
        self.assertEqual("HEX_CHARS 0 False", str(EntropyValidator("")))
        self.assertEqual("BASE64_CHARS 2.321928 False", str(EntropyValidator("12345")))
        self.assertEqual("BASE64_CHARS 2.321928 False", str(EntropyValidator("/home")))

    def test_validator_p(self):
        self.assertEqual("HEX_CHARS 3.584963 True", str(EntropyValidator("abcdefABCDEF")))
        self.assertEqual("BASE36_CHARS 3.169925 True", str(EntropyValidator("123456789")))
        self.assertEqual("BASE64_CHARS 4.681881 True", str(EntropyValidator("dNJKHBD34534928DRFCsnkjBUygtrd+32sd/uy")))

