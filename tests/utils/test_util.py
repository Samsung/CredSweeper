import os
import random
import string
import tempfile
import unittest

from credsweeper.common.constants import Chars, DEFAULT_ENCODING
from credsweeper.utils import Util
from tests import AZ_DATA, AZ_STRING, SAMPLES_DIR


class TestUtils(unittest.TestCase):

    def test_get_extension_n(self):
        self.assertEqual("", Util.get_extension("/"))
        self.assertEqual("", Util.get_extension("/tmp"))
        self.assertEqual("", Util.get_extension("tmp"))
        self.assertEqual("", Util.get_extension("tmp/"))
        self.assertEqual("", Util.get_extension(".gitignore"))
        self.assertEqual("", Util.get_extension("/tmp/.hidden"))
        self.assertEqual("", Util.get_extension("/tmp.ext/"))

    def test_get_extension_p(self):
        self.assertEqual(".ext", Util.get_extension("c:\\tmp.ext"))
        self.assertEqual(".json", Util.get_extension("c:\\tmp.ext:zip:text.json"))
        self.assertEqual(".ext", Util.get_extension("tmp.ext"))
        self.assertEqual(".jpg", Util.get_extension("tmp.JPG"))
        self.assertEqual(".ї", Util.get_extension("tmp.Ї", lower=True))
        self.assertEqual(".Ї", Util.get_extension("tmp.Ї", lower=False))
        self.assertEqual(".♡", Util.get_extension("tmp.♡"))
        self.assertEqual(".ㅋㅅ", Util.get_extension("tmp.ㅋㅅ"))
        self.assertEqual(".ß", Util.get_extension("tmp.ß"))
        self.assertEqual(".txt", Util.get_extension("/.hidden.tmp.txt"))

    def test_get_shannon_entropy_n(self):
        self.assertEqual(0, Util.get_shannon_entropy("", "abc"))
        self.assertEqual(0, Util.get_shannon_entropy(None, "abc"))
        self.assertEqual(0, Util.get_shannon_entropy("abc", ""))
        self.assertEqual(0, Util.get_shannon_entropy("x", "y"))
        self.assertEqual(0, Util.get_shannon_entropy("y", "x"))

    def test_get_shannon_entropy_p(self):
        test_shannon_entropy = Util.get_shannon_entropy(AZ_STRING, string.printable)
        self.assertLess(4.4, test_shannon_entropy)
        self.assertGreater(4.5, test_shannon_entropy)
        # using alphabet from the project
        self.assertLess(3.0, Util.get_shannon_entropy("defABCDEF", Chars.HEX_CHARS.value))
        self.assertGreater(3.0, Util.get_shannon_entropy("fABCDEF", Chars.HEX_CHARS.value))
        self.assertLess(3.0, Util.get_shannon_entropy("rstuvwxyz", Chars.BASE36_CHARS.value))
        self.assertGreater(3.0, Util.get_shannon_entropy("tuvwxyz", Chars.BASE36_CHARS.value))
        self.assertLess(4.5, Util.get_shannon_entropy("qrstuvwxyz0123456789+/=", Chars.BASE64_CHARS.value))
        self.assertGreater(4.5, Util.get_shannon_entropy("rstuvwxyz0123456789+/=", Chars.BASE64_CHARS.value))

    def test_is_entropy_validate_n(self):
        self.assertFalse(Util.is_entropy_validate(" "))
        self.assertFalse(Util.is_entropy_validate("efABCDEF"))
        self.assertFalse(Util.is_entropy_validate("tuvwxyz"))
        self.assertFalse(Util.is_entropy_validate("a0123456789+/="))

    def test_is_entropy_validate_p(self):
        self.assertTrue(Util.is_entropy_validate(AZ_STRING))
        self.assertTrue(Util.is_entropy_validate("defABCDEF"))
        self.assertTrue(Util.is_entropy_validate("rstuvwxyz"))
        self.assertTrue(Util.is_entropy_validate("qrstuvwxyz0123456789+/="))

    def test_util_read_file_n(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_file_p.tmp')
            # required binary write mode
            with open(file_path, "wb") as tmp_file:
                tmp_file.write(AZ_DATA)
            assert os.path.isfile(file_path)
            # CP1026 incompatible with ASCII but encodes something
            test_tuple = (1, 'fake', 'undefined', 'utf_16', 'utf_32', 'CP1026')
            test_result = Util.read_file(file_path, test_tuple)
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
            test_tuple = ('oem', 'utf_8')
            test_result = Util.read_file(file_path, test_tuple)
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
            read_lines = Util.read_file(file_path, ('utf-16-be', 'undefined'))
            test_bytes = bytes([0xfe, 0xff]) + unicode_text.encode('utf-16-be')
            test_lines = Util.decode_bytes(test_bytes, ('utf-16-be', 'undefined'))
            assert 0 < len(read_lines)
            assert read_lines == test_lines

    def test_read_data_p(self):
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

    def test_get_xml_data_p(self):
        target_path = str(SAMPLES_DIR / "xml_password.xml")
        lines = Util.get_xml_data(target_path)

        assert lines == ([
            "Countries : ", "Country : ", "City : Seoul", "password : cackle!", "Country : ", "City : Kyiv",
            "password : peace_for_ukraine"
        ], [2, 3, 4, 5, 7, 8, 9])

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
