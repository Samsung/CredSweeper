import random
import unittest

from credsweeper.common.constants import MIN_DATA_LEN
from credsweeper.deep_scanner.protobuf_scanner import ProtobufScanner
from tests import AZ_DATA


class TestProtobufScanner(unittest.TestCase):

    def test_match_n(self):
        self.assertFalse(ProtobufScanner.match(b"\x08\x96\x01\x12\x0BCredLeak"))
        self.assertFalse(ProtobufScanner.match(AZ_DATA))
        self.assertFalse(ProtobufScanner.match(b''))
        self.assertFalse(ProtobufScanner.match(None))
        # may fail in some percent cases
        self.assertFalse(ProtobufScanner.match(random.randbytes(MIN_DATA_LEN)))

    def test_match_p(self):
        self.assertTrue(ProtobufScanner.match(b"\x08\x96\x01\x12\x0BCredSweeper"))
        self.assertTrue(ProtobufScanner.match(b"\x08\x96\x01\x12\x04Cred"))
