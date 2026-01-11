import string
import unittest

from credsweeper.common.constants import MAX_LINE_LENGTH
from credsweeper.deep_scanner.encoder_scanner import EncoderScanner
from tests import AZ_DATA


class TestEncoderScanner(unittest.TestCase):

    def test_match_n(self):
        with self.assertRaises(TypeError):
            EncoderScanner.match(None)
        self.assertFalse(EncoderScanner.match(b""))
        self.assertFalse(EncoderScanner.match(AZ_DATA))
        self.assertFalse(EncoderScanner.match(b"ba4e4d89-dead-beef-c0fe-913bc57ff132"))
        self.assertFalse(EncoderScanner.match(b"/Some/Path.extension"))
        self.assertFalse(EncoderScanner.match(b"1-various+SYMBOLS"))
        self.assertFalse(EncoderScanner.match(string.digits.encode()))
        self.assertFalse(EncoderScanner.match(string.ascii_letters.encode()))
        self.assertFalse(EncoderScanner.match(string.ascii_lowercase.encode()))
        self.assertFalse(EncoderScanner.match(string.ascii_uppercase.encode()))
        self.assertFalse(EncoderScanner.match(string.printable.encode()))
        self.assertFalse(EncoderScanner.match(b'A' * MAX_LINE_LENGTH + b"E2e4"))
        self.assertFalse(EncoderScanner.match(b'a' * MAX_LINE_LENGTH + b"E2e4"))
        self.assertFalse(EncoderScanner.match(b'0' * MAX_LINE_LENGTH + b"E2e4"))
        self.assertFalse(EncoderScanner.match(b"TooSh0rt"))

    def test_match_p(self):
        self.assertTrue(
            EncoderScanner.match(
                b'\xFF\xFE\x00X\x00G\x005\x00n\x00a\x00X\x00R\x00f\x00d\x00G\x009\x00r\x00Z\x00W\x004\x00g\x00P'
                b'\x00S\x00A\x00i\x00Z\x002\x00l\x00y\x00Z\x00W\x009\x00n\x00a\x00W\x00N\x00y\x00Y\x00W\x00N'
                b'\x00r\x00b\x00G\x00V\x00j\x00c\x00m\x00\r\x00\n\x00F\x00j\x00a\x002\x00x\x00l\x00M\x00T\x00I'
                b'\x00z\x00M\x00T\x00U\x002\x00N\x00z\x00E\x005\x00M\x00D\x00E\x00x\x00M\x00z\x00Q\x00x\x00M\x00z'
                b'\x00k\x004\x00M\x00S\x00J\x00c\x00b\x00l\x00x\x00u\x00C\x00g\x00=\x00=\x00\r\x00\n\x00\r\x00\n'))
        self.assertTrue(EncoderScanner.match(b"E2e4\n\tnext line"))
        self.assertTrue(EncoderScanner.match(b"E2e4a1++//=="))
