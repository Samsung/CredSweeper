import random
import unittest

from credsweeper.deep_scanner.protobuf_scanner import ProtobufScanner
from tests import AZ_DATA


class TestProtobufScanner(unittest.TestCase):

    def test_read_varint_n(self):
        self.assertGreater((0, 0), ProtobufScanner.read_varint(b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 0))
        self.assertGreater((0, 0), ProtobufScanner.read_varint(b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 5))

    def test_read_varint_p(self):
        self.assertEqual((1, 16), ProtobufScanner.read_varint(b"\x10", 0))
        self.assertEqual((1, 0), ProtobufScanner.read_varint(b"\x00", 0))
        self.assertEqual((1, 1), ProtobufScanner.read_varint(b"\x01", 0))
        self.assertEqual((1, 127), ProtobufScanner.read_varint(b"\x7F", 0))
        self.assertEqual((2, 128), ProtobufScanner.read_varint(b"\x80\x01", 0))
        self.assertEqual((2, 150), ProtobufScanner.read_varint(b"\xFF\x96\x01\xABc\xDE\xFF", 1))
        self.assertEqual((5, 31726677630), ProtobufScanner.read_varint(b"\xFE\xDC\xBA\x98\x76\xFF", 0))
        self.assertEqual((2, 16383), ProtobufScanner.read_varint(b"\xFF\xFF\xFF\xFF\xFF\x7F", 4))
        self.assertEqual((3, 2097151), ProtobufScanner.read_varint(b"\xFF\xFF\xFF\xFF\xFF\x7F", 3))
        self.assertEqual((4, 268435455), ProtobufScanner.read_varint(b"\xFF\xFF\xFF\xFF\xFF\x7F", 2))
        self.assertEqual((5, 34359738367), ProtobufScanner.read_varint(b"\xFF\xFF\xFF\xFF\xFF\x7F", 1))

    def test_match_n(self):
        self.assertFalse(ProtobufScanner.match(AZ_DATA))
        self.assertFalse(ProtobufScanner.match(random.randbytes(16)))

    def test_match_p(self):
        self.assertFalse(ProtobufScanner.match(AZ_DATA))
        self.assertFalse(ProtobufScanner.match(random.randbytes(16)))