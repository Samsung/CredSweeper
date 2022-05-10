import os
import random
import string
import tempfile

from credsweeper.common.constants import AVAILABLE_ENCODINGS
from credsweeper.utils import Util


class TestUtils:

    def test_util_read_file_n(self):
        test_tuple = (1, 'fake', None)
        assert 0 == len(Util.read_file('dummy', test_tuple))

    def test_util_read_file_p(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            with tempfile.NamedTemporaryFile(mode='w+t', dir=tmp_dir, suffix='txt') as tmp_file:
                az_string = 'The quick brown fox jumps over the lazy dog'
                tmp_file.write(az_string)
                tmp_file.flush()
                assert os.path.isfile(tmp_file.name)
                test_tuple = ('latin_1', None)
                test_result = Util.read_file(tmp_file.name, test_tuple)
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
        n = random.randint(10000, 100000)
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
                    raise Exception(f"Wrong refurb:{utf8_char} {bin_char} {encoded_bin}")
            except Exception as exc:
                print(f'{exc}, {bin_char}')
                continue
            # the byte sequence is correct for UTF-8 and is added to data
            bin_text += bin_char
            n -= 1

        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            with tempfile.NamedTemporaryFile(mode='wb', dir=tmp_dir, suffix='.bin') as tmp_file:
                tmp_file.write(bin_text)
                tmp_file.flush()
                assert os.path.isfile(tmp_file.name)
                read_lines = Util.read_file(tmp_file.name)
                decoded_text = bin_text.decode('utf-8')
                test_lines = decoded_text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
                assert test_lines == read_lines

    def test_util_read_utf16le_bin_p(self):
        bin_text = bytearray()
        n = random.randint(1000, 1000)
        i = 0
        while 0 < n:
            bin_char = bytearray()
            try:
                i += 1
                if 0 == i % 100:
                    bin_char.append(0x0a)
                    bin_char.append(0x00)
                else:
                    bin_char.append(random.randint(0, 255))
                    bin_char.append(random.randint(0, 255))
                utf16_char = bin_char.decode('utf-16-le')
                encoded_bin = utf16_char.encode('utf-16-le')
                if bin_char != encoded_bin:
                    raise Exception(f"Wrong refurb:{utf16_char} {bin_char} {encoded_bin}")
            except Exception as exc:
                print(f'{exc}, {bin_char}')
                continue
            # the byte sequence is correct for UTF-16-LE and is added to data
            bin_text += bin_char
            n -= 1

        with tempfile.TemporaryDirectory() as tmp_dir:
            assert os.path.isdir(tmp_dir)
            with tempfile.NamedTemporaryFile(mode='wb', dir=tmp_dir, suffix='.bin') as tmp_file:
                tmp_file.write(bin_text)
                tmp_file.flush()
                assert os.path.isfile(tmp_file.name)
                read_lines = Util.read_file(tmp_file.name)
                decoded_text = bin_text.decode('utf-16-le')
                test_lines = decoded_text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
                assert test_lines == read_lines
