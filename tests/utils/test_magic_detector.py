import unittest

from credsweeper.utils.magic_detector import MagicDetector
from tests import AZ_STRING, AZ_DATA


class TestMagicDetector(unittest.TestCase):

    def test_detect_n(self):
        with self.assertRaises(TypeError):
            self.assertFalse(MagicDetector.detect(None))
        with self.assertRaises(IndexError):
            self.assertFalse(MagicDetector.detect(b''))
        self.assertFalse(MagicDetector.detect(AZ_STRING))
        self.assertFalse(MagicDetector.detect(AZ_DATA))
        self.assertFalse(MagicDetector.detect(b"\0\0\0\0"))
        self.assertFalse(MagicDetector.detect(b"III. Password is Gehe1mnis!"))
        self.assertFalse(MagicDetector.detect(b"\xFF\xFEu\x00t\x00f\x001\x006\x00"))
        self.assertFalse(MagicDetector.detect(b"GIF89a format cannot store data inside\n\tHowever a picture can\r\n"))
        self.assertFalse(MagicDetector.detect(b"BMP is a picture"))

    def test_detect_p(self):
        self.assertTrue(MagicDetector.detect(b"FWS\x08\xd3<\x00\x00x\x00\x05_\x00\x00\x0f\xa0\x00\x00\x0c\x01\x00X"))
        self.assertTrue(MagicDetector.detect(b"\xabKTX 33\xbb\r\n\x1a\n\x01\x02\x03\x04\x0b\x14\x00\x00\x02\x00\x00"))
        self.assertTrue(MagicDetector.detect(b"glTF\x02\x00\x00\x00\xa8\xe3[\x00p\x1d\x00\x00JSON"))
        self.assertTrue(MagicDetector.detect(b"BMV\xae\x04\x00\x00\x00\x00\x007\x00\x00\x00}\x00\x00\x00\x1c\x01"))
        self.assertTrue(MagicDetector.detect(b"RIVE\x07\x00\x8f\x84\x0c\xc4\x01\x00\x00\x00\x00\x00\x17\x00\x01\x02"))
        self.assertTrue(MagicDetector.detect(b"\x7fELF\x02\x01\x01{\x03\x00\x00\x00\x00\x00\x00\x00\x07\x00>"))
        self.assertTrue(MagicDetector.detect(b"\x00\x00\x00\x18ftypqt   \x07\t\x00qt  niko\x99@{\xeamdat"))
        self.assertTrue(MagicDetector.detect(b"RIFF\xf8&\n\x00WAVEfmt \x10\x00\x01\x00\x00\x01\x00\x02\x00D\t\x00"))
        self.assertTrue(MagicDetector.detect(b"\x89PNG\x0D\x0A\x1A\x0A...can store text chunks"))
        self.assertTrue(MagicDetector.detect(b"\xFF\xD8\xFF\xE1+\x84Exif\0\0*\0"))
        self.assertTrue(MagicDetector.detect(b"GIF89a null terminated string\0"))
        self.assertTrue(MagicDetector.detect(b"BMP!\0\0\0\0"))
        self.assertTrue(
            MagicDetector.detect(b"ttcf\x00\x01\x00\x00\x00\x00\x00\n\x00\x00\x004\x00\x03X\x00\x00\x04d"))
        self.assertTrue(
            MagicDetector.detect(b"MThd\x00\x00\x00\x06\x00\x01\x00\x03\xe0MTrk\x00\x00\x00\x05Seq-1\x00"))
        self.assertTrue(MagicDetector.detect(b"VCLMTF\x01\x001\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
        self.assertTrue(MagicDetector.detect(b"wvpk\x81\xff\x00\x00\x10\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
