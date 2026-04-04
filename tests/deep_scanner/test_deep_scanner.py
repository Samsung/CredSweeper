import unittest

from hypothesis import given, strategies

from credsweeper.deep_scanner.deep_scanner import DeepScanner
from credsweeper.file_handler.descriptor import Descriptor
from tests import AZ_DATA, AZ_STRING


class TestDeepScanner(unittest.TestCase):

    def test_get_deep_scanners_n(self):
        self.assertEqual(([], []), DeepScanner.get_deep_scanners(None, Descriptor('', '', ''), 0))
        self.assertEqual(([], []), DeepScanner.get_deep_scanners(b'', Descriptor('', '', ''), 0))
        self.assertEqual(([], []), DeepScanner.get_deep_scanners(b'0xFF', Descriptor('', '', ''), 0))

    @given(strategies.binary())
    def test_get_deep_scanners_n(self, data):
        # no exception should be raised
        x, y = DeepScanner.get_deep_scanners(data, Descriptor('', '', ''), 0)
        # no fallback scanners for depth=0
        self.assertListEqual([], y)

    def test_is_media_n(self):
        with self.assertRaises(TypeError):
            self.assertFalse(DeepScanner.is_media(None))
        with self.assertRaises(IndexError):
            self.assertFalse(DeepScanner.is_media(b''))
        self.assertFalse(DeepScanner.is_media(AZ_STRING))
        self.assertFalse(DeepScanner.is_media(AZ_DATA))
        self.assertFalse(DeepScanner.is_media(b"\0\0\0\0"))
        self.assertFalse(DeepScanner.is_media(b"III. Password is Gehe1mnis!"))
        self.assertFalse(DeepScanner.is_media(b"\xFF\xFEu\x00t\x00f\x001\x006\x00"))
        self.assertFalse(DeepScanner.is_media(b"GIF89a format cannot store data inside\n\tHowever a picture can\r\n"))
        self.assertFalse(DeepScanner.is_media(b"BMP is a picture"))

    def test_is_media_p(self):
        self.assertTrue(DeepScanner.is_media(b"\x89PNG\x0D\x0A\x1A\x0A...can store text chunks"))
        self.assertTrue(DeepScanner.is_media(b"\xFF\xD8\xFF\xE1+\x84Exif\0\0*\0"))
        self.assertTrue(DeepScanner.is_media(b"GIF89a null terminated string\0"))
        self.assertTrue(DeepScanner.is_media(b"BMP!\0\0\0\0"))
