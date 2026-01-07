import unittest

from credsweeper.deep_scanner.bzip2_scanner import Bzip2Scanner


class TestBzip2Scanner(unittest.TestCase):

    def test_match_p(self):
        # Valid bzip2 signature with correct version and block size
        self.assertTrue(Bzip2Scanner.match(b"\x42\x5A\x68\x31\x31\x41\x59\x26\x53\x59"))
        self.assertTrue(Bzip2Scanner.match(b"\x42\x5A\x68\x39\x31\x41\x59\x26\x53\x59"))

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(AttributeError):
            Bzip2Scanner.match(None)
        with self.assertRaises(AttributeError):
            Bzip2Scanner.match(1)
        # Too short
        self.assertFalse(Bzip2Scanner.match(b""))
        self.assertFalse(Bzip2Scanner.match(b"\x42\x5A\x68"))
        # Wrong signature
        self.assertFalse(Bzip2Scanner.match(b"\x42\x5A\x69"))
        # Wrong version
        self.assertFalse(Bzip2Scanner.match(b"\x42\x5A\x68\x30\x31\x41\x59\x26\x53\x59"))
        # Wrong block size
        self.assertFalse(Bzip2Scanner.match(b"\x42\x5A\x68\x31\x30\x41\x59\x26\x53\x59"))
