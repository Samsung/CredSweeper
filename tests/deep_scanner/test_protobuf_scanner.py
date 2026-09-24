import random
import unittest

from credsweeper.common.constants import MIN_DATA_LEN, MAX_LINE_LENGTH
from credsweeper.deep_scanner.protobuf_scanner import ProtobufScanner
from tests import AZ_DATA


class TestProtobufScanner(unittest.TestCase):

    def test_match_n(self):
        self.assertFalse(ProtobufScanner.match(b"\x08\x96\x01\x12\x0BCredLeak"))
        self.assertFalse(ProtobufScanner.match(AZ_DATA))
        self.assertFalse(ProtobufScanner.match(b''))
        self.assertFalse(ProtobufScanner.match(None))
        # may fail in some percent cases
        fp = 0
        for n in range(100):
            dl = random.randint(MIN_DATA_LEN, MAX_LINE_LENGTH)
            rd = random.randbytes(dl)
            if ProtobufScanner.match(rd):
                fp += 1
        # less than 5%
        self.assertGreater(5, fp, "Restart test in fail case")

    def test_match_p(self):
        self.assertTrue(ProtobufScanner.match(b"\x08\x96\x01\x12\x0BCredSweeper"))
        self.assertTrue(ProtobufScanner.match(b"\x08\x96\x01\x12\x04Cred"))
