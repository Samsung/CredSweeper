import os
import random
import tempfile

from credsweeper.utils import Util


class TestUtils:

    def test_util_read_file_n(self):
        test_tuple = (1, 'fake', None)
        assert 0 == len(Util.read_file('dummy', test_tuple))

    def test_util_read_file_p(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_file_p.tmp')
            tmp_file = open(file_path, "wt")
            az_string = "The quick brown fox jumps over the lazy dog"
            tmp_file.write(az_string)
            tmp_file.close()
            assert os.path.isfile(file_path)
            test_tuple = ('latin_1', None)
            test_result = Util.read_file(file_path, test_tuple)
            assert 1 == len(test_result)
            assert az_string == test_result[0]

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
                    raise Exception(f"Wrong refurbish:{utf8_char} {bin_char} {encoded_bin}")
            except Exception as exc:
                continue
            # the byte sequence is correct for UTF-8 and is added to data
            bin_text += bin_char
            n -= 1

        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_utf8_bin_p.tmp')
            tmp_file = open(file_path, "wb")
            tmp_file.write(bin_text)
            tmp_file.close()
            assert os.path.isfile(tmp_file.name)
            read_lines = Util.read_file(tmp_file.name)
            decoded_lines = Util.decode_bytes(bin_text)
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
                    raise Exception(f"Wrong refurbish:{utf16_char} {bin_char} {encoded_bin}")
            except Exception as exc:
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
            tmp_file = open(file_path, "wb")
            tmp_file.write(bin_text)
            tmp_file.close()
            assert os.path.isfile(tmp_file.name)
            read_lines = Util.read_file(tmp_file.name)
            test_lines = Util.decode_bytes(bin_text)
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
            except Exception as exc:
                continue
            # the byte sequence is correct for UTF-16-LE and is added to data
            unicode_text += unicode_char
            n -= 1
            if 0 == n % 32:
                unicode_text += '\n'

        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_utf16le_bin_p.tmp')
            tmp_file = open(file_path, "wb")
            tmp_file.write(bytes([0xff, 0xfe]))  # BOM LE
            tmp_file.write(unicode_text.encode('utf-16-le'))
            tmp_file.close()
            assert os.path.isfile(tmp_file.name)
            read_lines = Util.read_file(tmp_file.name)
            test_lines = Util.decode_bytes(bytes([0xff, 0xfe]) + unicode_text.encode('utf-16-le'))
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
                    raise Exception(f"Wrong refurbish:{unicode_char} {encoded_bin} {utf16_char}")
            except Exception as exc:
                continue
            # the byte sequence is correct for UTF-16-BE and is added to data
            unicode_text += unicode_char
            n -= 1
            if 0 == n % 32:
                unicode_text += '\n'

        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            file_path = os.path.join(tmp_dir, 'test_util_read_utf16le_bin_p.tmp')
            tmp_file = open(file_path, "wb")
            tmp_file.write(bytes([0xfe, 0xff]))  # BOM BE
            tmp_file.write(unicode_text.encode('utf-16-be'))
            tmp_file.close()
            assert os.path.isfile(tmp_file.name)
            read_lines = Util.read_file(tmp_file.name, tuple('utf-16-be'))
            test_lines = Util.decode_bytes(bytes([0xfe, 0xff]) + unicode_text.encode('utf-16-be'), tuple('utf-16-be'))
            assert read_lines == test_lines
