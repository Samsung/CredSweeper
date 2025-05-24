import unittest

from credsweeper.deep_scanner.deb_scanner import DebScanner
from tests import SAMPLE_DEB


class TestDebScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_walk_n(self):
        with self.assertRaises(Exception):
            list(DebScanner.walk(b"!<arch>\ndummy/          0           0     0     777     x         `\nX"))
        self.assertListEqual([], list(DebScanner.walk(b'')))
        self.assertListEqual(
            [], list(DebScanner.walk(b"!<arch>\ndummy/          0           0     0     777     1234567890`\nX")))

    def test_walk_p(self):
        self.assertListEqual(
            [], list(DebScanner.walk(b"!<arch>\ndummy/          0           0     0     777     0         `\n")))
        data = (b"!<arch>\n"
                b"uuid1/          0           0     0     644     36        `\n"
                b"cafebabe-beda-beda-cafe-9129474bcd81"
                b"uuid2/          0           0     0     644     36        `\n"
                b"bace1d29-fa7e-dead-beef-9123474bcd87")
        self.assertListEqual([(68, "uuid1", b"cafebabe-beda-beda-cafe-9129474bcd81"),
                              (164, "uuid2", b"bace1d29-fa7e-dead-beef-9123474bcd87")], list(DebScanner.walk(data)))
        sample_list = list(DebScanner.walk(SAMPLE_DEB.read_bytes()))
        self.assertEqual(5, len(sample_list))
