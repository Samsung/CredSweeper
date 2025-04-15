import base64
import binascii
import os
import random
import string
import sys
import tempfile
import unittest
from pathlib import Path
from xmlrpc.client import MAXINT

from lxml.etree import XMLSyntaxError

from credsweeper.common.constants import Chars, DEFAULT_ENCODING, UTF_8, MAX_LINE_LENGTH, CHUNK_STEP_SIZE, CHUNK_SIZE, \
    OVERLAP_SIZE, LATIN_1, UTF_16, BASE64COMMON, MIN_DATA_LEN
from credsweeper.utils import Util
from tests import AZ_DATA, AZ_STRING, SAMPLES_PATH


class TestUtils(unittest.TestCase):
    KOREAN_PANGRAM = "키스의 고유조건은 입술끼리 만나야 하고 특별한 기술은 필요치 않다."
    DEUTSCH_PANGRAM = "Üben von Xylophon und Querflöte ist ja zweckmäßig"

    def test_asn1_p(self):
        based_data = """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
C5z6Z1bgIfi2awICAicQ"""
        data = base64.b64decode(based_data)
        self.assertTrue(Util.is_asn1(data))

    def test_asn1_n(self):
        based_data = """MIIG8gIBAzCCBpwGCSqGSIb3DQEHAaCCBo0EggaJMIIGhTCCBoEGCSqGSIb3DQEHBqCCBnIwggZu
AgEAMIIGZwYJKoZIhvcNAQcBMGYGCSqGSIb3DQEFDTBZMDgGCSqGSIb3DQEFDDArBBSQgogxffCn
2ow1ucAT4NGvWzziNMWKbhk+C8M6JXiYzzQ1xjz0RrGmIujjJn+iO6+Y+CiaD3SGtvyRxNUJIQP9
C5z6Z1bgIfi2awICAicQ"""
        data = base64.b64decode(based_data)
        self.assertFalse(Util.is_asn1(data))

    def test_get_extension_n(self):
        self.assertEqual("", Util.get_extension(None))
        self.assertEqual("", Util.get_extension("/"))
        self.assertEqual("", Util.get_extension("/tmp"))
        self.assertEqual("", Util.get_extension("tmp"))
        self.assertEqual("", Util.get_extension("tmp/"))
        self.assertEqual("", Util.get_extension(".gitignore"))
        self.assertEqual("", Util.get_extension("/tmp/.hidden"))
        self.assertEqual("", Util.get_extension("/tmp.ext/"))
        self.assertEqual("", Util.get_extension("http://127.0.0.1/index"))

    def test_get_extension_p(self):
        self.assertEqual(".ext", Util.get_extension("tmp.ext"))
        self.assertEqual(".jpg", Util.get_extension("tmp.JPG"))
        self.assertEqual(".ї", Util.get_extension("tmp.Ї", lower=True))
        self.assertEqual(".Ї", Util.get_extension("tmp.Ї", lower=False))
        self.assertEqual(".♡", Util.get_extension("tmp.♡"))
        self.assertEqual(".ㅋㅅ", Util.get_extension("tmp.ㅋㅅ"))
        self.assertEqual(".ß", Util.get_extension("tmp.ß"))
        self.assertEqual(".txt", Util.get_extension("/.hidden.tmp.txt"))

    def test_colon_os_n(self):
        self.assertEqual("", Util.get_extension(":memory:"))
        self.assertEqual(".ext", Util.get_extension("c:\\tmp.ext"))
        self.assertEqual(".json", Util.get_extension("c:\\tmp.ext:zip:text.json"))
        self.assertEqual(".json", Util.get_extension("/tmp.ext:zip:text.json"))
        self.assertEqual(".json:encoded", Util.get_extension("c:\\tmp.ext:zip:text.json:ENCODED"))
        self.assertEqual(".json:raw", Util.get_extension("/tmp.ext:zip:text.json:raw"))
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_name = os.path.join(tmp_dir, "test_file.zip")
            Path(file_name).touch()
            assert os.path.exists(file_name)
            new_name = f"{file_name}:ZIP:dummy.txt"
            assert not os.path.exists(new_name)

    def test_get_shannon_entropy_n(self):
        self.assertEqual(0, Util.get_shannon_entropy(None))
        self.assertEqual(0, Util.get_shannon_entropy(''))
        self.assertEqual(0, Util.get_shannon_entropy('x'))
        self.assertEqual(0, Util.get_shannon_entropy('♡'))
        self.assertEqual(0, Util.get_shannon_entropy(b'\0'))

    def test_get_shannon_entropy_p(self):
        self.assertEqual(1.0, Util.get_shannon_entropy("01"))
        self.assertEqual(1.0, Util.get_shannon_entropy("ÖЇ"))
        self.assertEqual(1.0, Util.get_shannon_entropy("ㅋㅅ"))
        self.assertEqual(4.431965045349459, Util.get_shannon_entropy(AZ_STRING))
        self.assertEqual(4.385453417442482, Util.get_shannon_entropy(AZ_STRING.lower()))
        self.assertEqual(4.385453417442482, Util.get_shannon_entropy(AZ_STRING.upper()))
        self.assertEqual(3.321928094887362, Util.get_shannon_entropy(string.digits))
        self.assertEqual(3.321928094887362, Util.get_shannon_entropy(string.ascii_uppercase[:10]))
        self.assertEqual(6.0, Util.get_shannon_entropy(Chars.BASE64STD_CHARS.value))
        self.assertEqual(6.0, Util.get_shannon_entropy(Chars.BASE64URL_CHARS.value))
        self.assertEqual(6.0223678130284535, Util.get_shannon_entropy(Chars.BASE64URLPAD_CHARS.value))
        self.assertEqual(6.643856189774724, Util.get_shannon_entropy(string.printable))
        self.assertEqual(6.62935662007961, Util.get_shannon_entropy(string.printable[:-1]))
        self.assertEqual(6.62935662007961, Util.get_shannon_entropy(string.printable[1:]))

    def test_util_read_file_n(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_file_p.tmp')
            # required binary write mode
            with open(file_path, "wb") as tmp_file:
                tmp_file.write(AZ_DATA)
            assert os.path.isfile(file_path)
            # CP1026 incompatible with ASCII but encodes something
            test_result = Util.read_file(file_path, [1, 'fake', 'undefined', 'utf_16', 'utf_32', 'CP1026'])
            assert 1 == len(test_result)
            assert len(AZ_STRING) == len(test_result[0])
            assert AZ_STRING != test_result[0]

    def test_util_read_file_p(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_file_p.tmp')
            # required binary write mode
            with open(file_path, "wb") as tmp_file:
                tmp_file.write(AZ_DATA)
            assert os.path.isfile(file_path)
            # windows might accept oem
            test_result = Util.read_file(file_path, ['oem', 'utf_8'])
            assert 1 == len(test_result)
            assert AZ_STRING == test_result[0]

    def test_util_read_utf8_bin_p(self):
        IOOOOOOO = int('10000000', 2)
        IOIIIIII = int('10111111', 2)
        IIOOOOOO = int('11000000', 2)
        IIIOOOOO = int('11100000', 2)
        IIIIOOOO = int('11110000', 2)
        IIIIIOOO = int('11111000', 2)
        bin_text = bytearray()
        n = 65536
        while 0 < n:
            bin_char = bytearray()
            r = random.randint(1, 255)
            if 128 > r:
                bin_char.append(r)
            elif IIOOOOOO == (IIIOOOOO & r):
                bin_char.append(r)
                bin_char.append(random.randint(IOOOOOOO, IOIIIIII))
            elif IIIOOOOO == (IIIIOOOO & r):
                bin_char.append(r)
                bin_char.append(random.randint(IOOOOOOO, IOIIIIII))
                bin_char.append(random.randint(IOOOOOOO, IOIIIIII))
            elif IIIIOOOO == (IIIIIOOO & r):
                bin_char.append(r)
                bin_char.append(random.randint(IOOOOOOO, IOIIIIII))
                bin_char.append(random.randint(IOOOOOOO, IOIIIIII))
                bin_char.append(random.randint(IOOOOOOO, IOIIIIII))
            else:
                continue
            try:
                utf8_char = bin_char.decode('utf-8')
                encoded_bin = utf8_char.encode('utf-8')
                if bin_char != encoded_bin:
                    # print (f"Wrong refurbish:{utf8_char} {bin_char} {encoded_bin}")
                    continue
            except UnicodeError:
                continue
            # the byte sequence is correct for UTF-8 and is added to data
            bin_text += bin_char
            n -= 1

        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_utf8_bin_p.tmp')
            with open(file_path, "wb") as tmp_file:
                tmp_file.write(bin_text)
            assert os.path.isfile(file_path)
            read_lines = Util.read_file(file_path)
            decoded_lines = Util.decode_bytes(bin_text)
            assert 0 < len(read_lines)
            assert decoded_lines == read_lines

    def test_util_read_utf16le_bin_p(self):
        bin_text = bytearray()
        bin_text += bytes([0xff, 0xfe])  # BOM LE
        n = 65536
        while 0 < n:
            bin_char = bytearray()
            try:
                bin_char.append(random.randint(0, 255))
                bin_char.append(random.randint(0, 255))
                utf16_char = bin_char.decode('utf-16-le')
                encoded_bin = utf16_char.encode('utf-16-le')
                if bin_char != encoded_bin:
                    # print (f"Wrong refurbish:{utf16_char} {bin_char} {encoded_bin}")
                    continue
            except UnicodeError:
                continue
            # the byte sequence is correct for UTF-16-LE and is added to data
            bin_text += bin_char
            n -= 1
            if 0 == n % 32:
                bin_char.append(0x0a)
                bin_char.append(0x00)

        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_utf16le_bin_p.tmp')
            with open(file_path, "wb") as tmp_file:
                tmp_file.write(bin_text)
            assert os.path.isfile(file_path)
            read_lines = Util.read_file(file_path)
            test_lines = Util.decode_bytes(bin_text)
            assert 0 < len(read_lines)
            assert read_lines == test_lines

    def test_util_read_utf16le_txt_p(self):
        unicode_text = ""
        n = 65536
        while 0 < n:
            try:
                unicode_char = chr(random.randint(0, 0x10FFFF))
                encoded_bin = unicode_char.encode('utf-16-le')
                utf16_char = encoded_bin.decode('utf-16-le')
                if unicode_char != utf16_char:
                    # print(f"Wrong refurbish:{unicode_char} {encoded_bin} {utf16_char}")
                    continue
            except UnicodeError:
                continue
            # the byte sequence is correct for UTF-16-LE and is added to data
            unicode_text += unicode_char
            n -= 1
            if 0 == n % 32:
                unicode_text += '\n'

        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_utf16le_bin_p.tmp')
            with open(file_path, "wb") as tmp_file:
                tmp_file.write(bytes([0xff, 0xfe]))  # BOM LE
                tmp_file.write(unicode_text.encode('utf-16-le'))
            assert os.path.isfile(file_path)
            read_lines = Util.read_file(file_path)
            test_lines = Util.decode_bytes(bytes([0xff, 0xfe]) + unicode_text.encode('utf-16-le'))
            assert 0 < len(read_lines)
            assert read_lines == test_lines

    def test_util_read_utf16be_txt_p(self):
        unicode_text = ""
        n = 65536
        while 0 < n:
            try:
                unicode_char = chr(random.randint(0, 0x10FFFF))
                encoded_bin = unicode_char.encode('utf-16-be')
                utf16_char = encoded_bin.decode('utf-16-be')
                if unicode_char != utf16_char:
                    # print (f"Wrong refurbish:{unicode_char} {encoded_bin} {utf16_char}")
                    continue
            except UnicodeError:
                continue
            # the byte sequence is correct for UTF-16-BE and is added to data
            unicode_text += unicode_char
            n -= 1
            if 0 == n % 32:
                unicode_text += '\n'

        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_utf16le_bin_p.tmp')
            with open(file_path, "wb") as tmp_file:
                tmp_file.write(bytes([0xfe, 0xff]))  # BOM BE
                tmp_file.write(unicode_text.encode('utf-16-be'))
            assert os.path.isfile(file_path)
            read_lines = Util.read_file(file_path, ['utf-16-be', 'undefined'])
            test_bytes = bytes([0xfe, 0xff]) + unicode_text.encode('utf-16-be')
            test_lines = Util.decode_bytes(test_bytes, ['utf-16-be', 'undefined'])
            assert 0 < len(read_lines)
            assert read_lines == test_lines

    def test_is_known_p(self):
        # 00000000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  |.ELF............|
        data = bytearray(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
        data.extend(b'\0' * 128)
        self.assertTrue(Util.is_known(data))
        data[4] = 0x01
        self.assertTrue(Util.is_known(data))

    def test_is_known_n(self):
        data = bytearray(b"\x7fELF\xFF")
        # too short
        self.assertFalse(Util.is_known(data))
        # signature wrong
        data.extend(b"\x7fTEN")
        self.assertFalse(Util.is_known(data))

    def test_is_binary_n(self):
        with self.assertRaises(AttributeError):
            Util.is_binary(None)
        self.assertFalse(Util.is_binary(b''))
        self.assertFalse(Util.is_binary(self.DEUTSCH_PANGRAM.encode(UTF_8)))
        self.assertFalse(Util.is_binary(b"\x7Ffew unprintable letters\x00"))
        self.assertFalse(Util.is_binary(self.KOREAN_PANGRAM.encode(UTF_8)))
        # some binaries may be false negatives
        self.assertFalse(Util.is_binary(b'!' * MAX_LINE_LENGTH + b"\0\0\0\0"))

    def test_is_binary_p(self):
        # two zeroes sequence is a marker of a binary
        self.assertTrue(Util.is_binary(b"\0\0"))
        self.assertTrue(Util.is_binary(b"X3\0\0"))
        # unsupported encoding has 3 zeroes
        self.assertTrue(Util.is_binary(AZ_STRING.encode("utf_32")))
        self.assertTrue(Util.is_binary(AZ_STRING.encode("utf_32_le")))
        self.assertTrue(Util.is_binary(AZ_STRING.encode("utf_32_be")))

    def test_is_latin1_n(self):
        # standard UTF-16 encoding is not recognized as Latin1
        self.assertFalse(Util.is_latin1(self.DEUTSCH_PANGRAM.encode(UTF_16)))
        # standard UTF-8 encoding is not recognized as Latin1 for Hangul
        self.assertFalse(Util.is_latin1(self.KOREAN_PANGRAM.encode(UTF_8)))
        # random data should be not recognized as Latin1
        self.assertFalse(Util.is_latin1(random.randbytes(MAX_LINE_LENGTH)))

    def test_is_latin1_p(self):
        # standard UTF-8 encoding is recognized as Latin1 even with null-terminator
        self.assertTrue(Util.is_latin1((self.DEUTSCH_PANGRAM + '\0').encode(UTF_8)))
        # obsolete encoding may be recognized as Latin1
        self.assertTrue(Util.is_latin1(self.KOREAN_PANGRAM.encode("euc_kr")))

    def test_is_ascii_entropy_validate_p(self):
        self.assertTrue(Util.is_ascii_entropy_validate(b''))
        self.assertTrue(Util.is_ascii_entropy_validate(AZ_DATA))
        # remove all spaces to make a variable name
        az_data = AZ_DATA.replace(b' ', b'')  # 35 bytes
        self.assertTrue(Util.is_ascii_entropy_validate(az_data))
        hangul_pangram_data = self.KOREAN_PANGRAM.encode(UTF_8)
        self.assertTrue(Util.is_ascii_entropy_validate(hangul_pangram_data))
        hanja_data = "漢字能力檢定試驗".encode(UTF_8)
        self.assertEqual(24, len(hanja_data))
        self.assertTrue(Util.is_ascii_entropy_validate(hanja_data))

    def test_is_ascii_entropy_validate_n(self):
        various_lang_data = "수도 首都 Hauptstadt".encode(UTF_8)
        self.assertEqual(24, len(various_lang_data))
        self.assertFalse(Util.is_ascii_entropy_validate(various_lang_data))
        decoded_like_base64 = base64.b64decode(f"{AZ_STRING}=")
        self.assertFalse(Util.is_ascii_entropy_validate(decoded_like_base64))
        for random_data_len in range(16, 40):
            data = random.randbytes(random_data_len)
            # VERY RARELY IT MIGHT FAIL
            self.assertFalse(Util.is_ascii_entropy_validate(data), data)

    def test_read_bin_file_n(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            self.assertTrue(os.path.isdir(tmp_dir))
            file_path = os.path.join(tmp_dir, 'test_read_data_p')
            with open(file_path, "wb") as f:
                f.write(AZ_DATA)
            data = Util.read_data(file_path)
            self.assertEqual(AZ_DATA, data)

    def test_read_data_n(self):
        self.assertIsNone(Util.read_data(os.path.join("not", "existed", "path")))

    def test_is_zip_p(self):
        self.assertTrue(Util.is_zip(b'PK\003\004'))
        # empty archive - no files
        self.assertTrue(Util.is_zip(b'PK\x05\x06\x00\x00'))
        # not supported spanned archive (multi volume)
        self.assertFalse(Util.is_zip(b'PK\x07\x08'))

    def test_is_zip_n(self):
        # wrong data type
        self.assertFalse(Util.is_zip(None))
        self.assertFalse(Util.is_zip(1))
        # few bytes than required
        self.assertFalse(Util.is_zip(b''))
        self.assertFalse(Util.is_zip(b'P'))
        self.assertFalse(Util.is_zip(b'PK'))
        self.assertFalse(Util.is_zip(b'PK\003'))
        # wrong signature
        self.assertFalse(Util.is_zip(b'PK\003\003'))
        # plain text data
        self.assertFalse(Util.is_zip(AZ_DATA))

    def test_is_gzip_p(self):
        self.assertTrue(Util.is_gzip(b'\x1f\x8b\x08'))
        self.assertTrue(Util.is_gzip(b'\x1f\x8b\x08xxx'))

    def test_is_gzip_n(self):
        self.assertFalse(Util.is_gzip(None))
        self.assertFalse(Util.is_gzip(b'\x1f'))
        self.assertFalse(Util.is_gzip(b'\x1f\x8bxxx'))
        self.assertFalse(Util.is_gzip(b'\x1f\x8b\x02'))

    def test_is_pdf_p(self):
        self.assertTrue(Util.is_pdf(b'\x25\x50\x44\x46\x2D'))
        self.assertTrue(Util.is_pdf(b'%PDF-!'))

    def test_is_pdf_n(self):
        self.assertFalse(Util.is_pdf(None))
        self.assertFalse(Util.is_pdf(b''))
        self.assertFalse(Util.is_pdf(b'%PDF+'))

    def test_get_xml_data_p(self):
        target_path = str(SAMPLES_PATH / "xml_password.xml")
        xml_lines = Util.read_data(target_path).decode().splitlines(True)
        result = Util.get_xml_from_lines(xml_lines)
        self.assertEqual(
            (
                [
                    "Countries : ",  #
                    "Country : ",  #
                    "City : Seoul",  #
                    "password : cackle!",  #
                    "Country : ",  #
                    "City : Kyiv",  #
                    "password : peace_for_ukraine",  #
                    "password : Password for authorization\n"
                    "        BAIT: bace4d59-fa7e-beef-cafe-9129474bcd81",  #
                ],
                [2, 3, 4, 5, 7, 8, 9, 11]),
            result)

    def test_get_xml_data_n(self):
        target_path = str(SAMPLES_PATH / "bad.xml")
        lines = Util.read_file(target_path)
        with self.assertRaises(XMLSyntaxError):
            Util.get_xml_from_lines(lines)

    def test_json_load_p(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            self.assertTrue(os.path.isdir(tmp_dir))
            file_path = os.path.join(tmp_dir, __name__)
            with open(file_path, "wb") as f:
                f.write(b'{}')
            data = Util.json_load(file_path)
            self.assertIsInstance(data, dict)

            with open(file_path, "wb") as f:
                f.write(b'[]')
            data = Util.json_load(file_path)
            self.assertIsInstance(data, list)

            with open(file_path, "wb") as f:
                f.write(b'"' + AZ_DATA + b'"')
            data = Util.json_load(file_path)
            self.assertIsInstance(data, str)
            self.assertEqual(AZ_STRING, data)

            rand_int = random.randint(-100, 100)
            with open(file_path, "wb") as f:
                f.write(str(rand_int).encode())
            data = Util.json_load(file_path)
            self.assertIsInstance(data, int)
            self.assertEqual(rand_int, data)

            rand_float = rand_int / 3.14
            with open(file_path, "wb") as f:
                f.write(str(rand_float).encode())
            data = Util.json_load(file_path)
            self.assertIsInstance(data, float)
            self.assertEqual(rand_float, data)

            with open(file_path, "wb") as f:
                f.write(b'true')
            data = Util.json_load(file_path)
            self.assertIsInstance(data, bool)
            self.assertTrue(data)

            with open(file_path, "wb") as f:
                f.write(b'null')
            data = Util.json_load(file_path)
            self.assertIsNone(data)

    def test_json_load_n(self):
        self.assertIsNone(Util.json_load("not_existed_path"))
        with tempfile.TemporaryDirectory() as tmp_dir:
            self.assertTrue(os.path.isdir(tmp_dir))
            file_path = os.path.join(tmp_dir, __name__)
            with open(file_path, "wb") as f:
                f.write(AZ_DATA)
            self.assertIsNone(Util.json_load(file_path))

    def test_json_dump_p(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            self.assertTrue(os.path.isdir(tmp_dir))
            file_path = os.path.join(tmp_dir, __name__)
            rand_int = random.randint(-1000000, 1000000)
            test_dict = {"dummy_int": rand_int, "dummy_str": AZ_STRING}
            Util.json_dump(test_dict, file_path=file_path, indent=None)
            with open(file_path, "rb") as f:
                self.assertEqual(
                    b'{"dummy_int": ' + str(rand_int).encode(DEFAULT_ENCODING) + b', "dummy_str": "' + AZ_DATA + b'"}',
                    f.read())
            Util.json_dump(test_dict, file_path=file_path, encoding='utf-16', indent=None)
            with open(file_path, "rb") as f:
                read_data = f.read()
                expected_data = \
                    b'\xff\xfe{\x00"\x00d\x00u\x00m\x00m\x00y\x00_\x00i\x00n\x00t\x00"\x00:\x00 \x00' \
                    + str(rand_int).encode('utf-16')[2:] + \
                    b',\x00 \x00"\x00d\x00u\x00m\x00m\x00y\x00_\x00s\x00t\x00r\x00"\x00:\x00 \x00' \
                    b'"\x00T\x00h\x00e\x00 \x00q\x00u\x00i\x00c\x00k\x00 \x00b\x00r\x00o\x00w\x00n\x00 \x00' \
                    b'f\x00o\x00x\x00 \x00j\x00u\x00m\x00p\x00s\x00 \x00o\x00v\x00e\x00r\x00 \x00t\x00h\x00e\x00 ' \
                    b'\x00l\x00a\x00z\x00y\x00 \x00d\x00o\x00g\x00"\x00}\x00'
                self.assertEqual(expected_data, read_data)
                expected_text = f'{{"dummy_int": {rand_int}, "dummy_str": "{AZ_STRING}"}}'
                read_text = read_data.decode(encoding='utf-16')
                self.assertEqual(expected_text, read_text)

    def test_json_dump_n(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            self.assertTrue(os.path.isdir(tmp_dir))
            file_path = os.path.join(tmp_dir, __name__)
            test_bytes = AZ_DATA
            Util.json_dump(test_bytes, file_path=file_path, encoding=DEFAULT_ENCODING)
            with open(file_path, "rb") as f:
                self.assertEqual(0, len(f.read()))

    def test_parse_py_p(self):
        result = Util.parse_python("""password = \
        "Hello" \
        ' World!'""")
        self.assertIsInstance(result, list)
        self.assertListEqual(["password = 'Hello World!'"], result)

    def test_parse_py_n(self):
        # empty
        self.assertFalse(Util.parse_python(""))
        # wrong syntax
        with self.assertRaises(SyntaxError):
            self.assertFalse(Util.parse_python("""<html>"Hello World!"</html>"""))

    def test_decode_base64_p(self):
        self.assertEqual(AZ_DATA, Util.decode_base64("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="))
        self.assertEqual(b"\xFF\xFF\xFF", Util.decode_base64("////"))
        self.assertEqual(b"\xFB\xEF\xBE", Util.decode_base64("++++"))
        self.assertEqual(b"\xFF\xFF\xFF", Util.decode_base64("____", urlsafe_detect=True))
        self.assertEqual(b"\xFB\xEF\xBE", Util.decode_base64("----", urlsafe_detect=True))
        self.assertEqual(b"\xFF\xFE", Util.decode_base64("//4", padding_safe=True))
        self.assertEqual(b"\xFF\xFE", Util.decode_base64("__4", padding_safe=True, urlsafe_detect=True))

    def test_decode_base64_n(self):
        with self.assertRaises(binascii.Error):
            Util.decode_base64("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw")
        with self.assertRaises(binascii.Error):
            Util.decode_base64("-_+_-", padding_safe=True, urlsafe_detect=True)
        with self.assertRaises(binascii.Error):
            Util.decode_base64("/** ! */", urlsafe_detect=True)
        with self.assertRaises(binascii.Error):
            Util.decode_base64("-----BEGIN+++++", urlsafe_detect=True)
        with self.assertRaises(binascii.Error):
            Util.decode_base64("____")
        with self.assertRaises(binascii.Error):
            Util.decode_base64("----")

    def test_get_chunks_n(self):
        self.assertGreater(MAX_LINE_LENGTH, CHUNK_SIZE)
        self.assertGreater(CHUNK_SIZE, OVERLAP_SIZE)
        self.assertGreater(CHUNK_STEP_SIZE, OVERLAP_SIZE)
        # wrong cases which should not appear due line length is checked before
        self.assertListEqual([(0, CHUNK_SIZE)], Util.get_chunks(0))
        self.assertListEqual([(0, CHUNK_SIZE)], Util.get_chunks(42))
        self.assertListEqual([(0, CHUNK_SIZE)], Util.get_chunks(CHUNK_STEP_SIZE))
        self.assertListEqual([(0, CHUNK_SIZE), (CHUNK_STEP_SIZE, CHUNK_SIZE)], Util.get_chunks(CHUNK_SIZE))
        self.assertListEqual([(0, CHUNK_SIZE), (CHUNK_STEP_SIZE, MAX_LINE_LENGTH)], Util.get_chunks(MAX_LINE_LENGTH))
        with self.assertRaises(Exception):
            Util.get_chunks(None)

    def test_get_chunks_p(self):
        line_length = 42 + MAX_LINE_LENGTH
        self.assertListEqual(  #
            [  #
                (0, CHUNK_SIZE),  #
                (CHUNK_STEP_SIZE, line_length),  #
            ],  #
            Util.get_chunks(line_length))
        line_length = 2 * MAX_LINE_LENGTH
        self.assertListEqual(  #
            [  #
                (0, CHUNK_SIZE),  #
                (1 * CHUNK_STEP_SIZE, CHUNK_SIZE + CHUNK_STEP_SIZE),  #
                (2 * CHUNK_STEP_SIZE, CHUNK_SIZE + 2 * CHUNK_STEP_SIZE),  #
                (3 * CHUNK_STEP_SIZE, line_length),  #
            ],  #
            Util.get_chunks(line_length))
        line_length = 3 * MAX_LINE_LENGTH + 42
        self.assertListEqual(  #
            [  #
                (0, CHUNK_SIZE),  #
                (1 * CHUNK_STEP_SIZE, CHUNK_SIZE + CHUNK_STEP_SIZE),  #
                (2 * CHUNK_STEP_SIZE, CHUNK_SIZE + 2 * CHUNK_STEP_SIZE),  #
                (3 * CHUNK_STEP_SIZE, CHUNK_SIZE + 3 * CHUNK_STEP_SIZE),  #
                (4 * CHUNK_STEP_SIZE, CHUNK_SIZE + 4 * CHUNK_STEP_SIZE),  #
                (5 * CHUNK_STEP_SIZE, CHUNK_SIZE + 5 * CHUNK_STEP_SIZE),  #
                (6 * CHUNK_STEP_SIZE, line_length),  #
            ],  #
            Util.get_chunks(line_length))

    def test_get_chunks_coverage_n(self):
        line_len = MAX_LINE_LENGTH
        while 7 * MAX_LINE_LENGTH > line_len:
            line_len += random.randint(1, OVERLAP_SIZE)
            data = bytearray(line_len)
            chunks = Util.get_chunks(line_len)
            for start, end in chunks:
                for i in range(start, end):
                    data[i] += 1
            self.assertNotIn(0, data)
            # overlapped items should be passed not more than twice
            self.assertGreaterEqual(2, max(data))

    def test_subtext_n(self):
        self.assertEqual("", Util.subtext("", 0, 0))
        self.assertEqual("", Util.subtext(' ' * 42, 0, 0))

    def test_subtext_p(self):
        self.assertEqual("var=value0123456789;", Util.subtext("                 var=value0123456789;   ", 21, 10))
        self.assertEqual(AZ_STRING, Util.subtext(AZ_STRING, len(AZ_STRING) >> 1, 1 + len(AZ_STRING) >> 1))
        self.assertEqual("x jump", Util.subtext(AZ_STRING, len(AZ_STRING) >> 1, 3))
        self.assertEqual("ox jumps", Util.subtext(AZ_STRING, len(AZ_STRING) >> 1, 4))
        self.assertEqual("fox jumps", Util.subtext(AZ_STRING, len(AZ_STRING) >> 1, 5))
        self.assertEqual("fox jumps ov", Util.subtext(AZ_STRING, len(AZ_STRING) >> 1, 6))
        self.assertEqual("The quick", Util.subtext(AZ_STRING, 0, 5))
        self.assertEqual("The quick", Util.subtext(AZ_STRING, 3, 5))
        self.assertEqual("fox jumps", Util.subtext(AZ_STRING, AZ_STRING.find("jumps"), 5))
        self.assertEqual("e lazy dog", Util.subtext(AZ_STRING, len(AZ_STRING) - 2, 5))
        self.assertEqual("the lazy dog", Util.subtext(AZ_STRING, len(AZ_STRING) - 2, 6))
        self.assertEqual(AZ_STRING[:39], Util.subtext(AZ_STRING, 15, 20))
        self.assertEqual(AZ_STRING[-40:], Util.subtext(AZ_STRING, 33, 20))

    def test_is_xml_n(self):
        self.assertFalse(Util.is_xml(b''))
        self.assertFalse(Util.is_xml(b"!<>"))
        self.assertFalse(Util.is_xml(b"</onlyClosingTagIsFail>"))
        self.assertFalse(Util.is_xml(b"</p><p>"))
        self.assertFalse(Util.is_xml(b"<br />"))
        self.assertFalse(Util.is_xml(bytearray(b'\n' * MAX_LINE_LENGTH) + bytearray(b"    <xml>far far away</xml>")))
        self.assertFalse(Util.is_xml(b"<html> unmatched tags </xml>"))
        self.assertFalse(Util.is_xml(b"<?xml version='1.0' encoding='utf-8'?>"))

    def test_is_html_n(self):
        self.assertFalse(Util.is_html(b"</html><html>"))

    def test_is_mxfile_n(self):
        self.assertFalse(Util.is_mxfile(b"<mxfile>"))
        self.assertFalse(Util.is_mxfile(b"</mxfile><mxfile>"))

    def test_xml_n(self):
        self.assertFalse(Util.is_xml(None))
        self.assertFalse(Util.is_xml(''))
        self.assertFalse(Util.is_html(None))
        self.assertFalse(Util.is_html(None))

    def test_xml_p(self):
        self.assertTrue(Util.is_xml(b"<?xml version='1.0' encoding='utf-8'?><xml> matched tags </xml>"))
        data = b"<mxfile atr=0><table></table></mxfile>"
        self.assertTrue(Util.is_xml(data))
        self.assertTrue(Util.is_html(data))
        self.assertTrue(Util.is_mxfile(data))
        self.assertTrue(
            Util.is_xml(
                bytearray(b'\n<xml> far far away ') + bytearray(b'\n' * MAX_LINE_LENGTH) +
                bytearray(b' long long ago </xml>')))

    def test_get_excel_column_name_n(self):
        self.assertFalse(Util.get_excel_column_name(None))
        self.assertFalse(Util.get_excel_column_name(-1))
        self.assertFalse(Util.get_excel_column_name(3.14))

    def test_get_excel_column_name_p(self):
        self.assertEqual("A", Util.get_excel_column_name(0))
        self.assertEqual("AQ", Util.get_excel_column_name(42))
        self.assertEqual("CS", Util.get_excel_column_name(96))
        self.assertEqual("AAA", Util.get_excel_column_name(702))
        self.assertEqual("XFD", Util.get_excel_column_name(16383))
        self.assertEqual("FXSHRXX", Util.get_excel_column_name(MAXINT))
