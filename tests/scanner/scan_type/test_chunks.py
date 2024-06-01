import random
import unittest

from credsweeper.common.constants import MAX_LINE_LENGTH, CHUNK_STEP_SIZE
from credsweeper.scanner.scan_type import ScanType


class TestScanTypeChunks(unittest.TestCase):

    def test_get_chunks_n(self):
        with self.assertRaises(Exception):
            ScanType.get_chunks(None)

    def test_get_chunks_p(self):
        self.assertSetEqual({(0, 0)}, ScanType.get_chunks(0))
        self.assertSetEqual({(0, 42)}, ScanType.get_chunks(42))
        self.assertSetEqual(  #
            {  #
                (0, MAX_LINE_LENGTH),  #
                (42, 42 + MAX_LINE_LENGTH),  #
            },  #
            ScanType.get_chunks(42 + MAX_LINE_LENGTH))
        self.assertSetEqual(  #
            {  #
                (0, MAX_LINE_LENGTH),  #
                (CHUNK_STEP_SIZE, CHUNK_STEP_SIZE + MAX_LINE_LENGTH),  #
                (MAX_LINE_LENGTH, 2 * MAX_LINE_LENGTH),  #
            },  #
            ScanType.get_chunks(2 * MAX_LINE_LENGTH))
        self.assertSetEqual(  #
            {  #
                (0, MAX_LINE_LENGTH),  #
                (CHUNK_STEP_SIZE, CHUNK_STEP_SIZE + MAX_LINE_LENGTH),  #
                (2 * CHUNK_STEP_SIZE, 2 * CHUNK_STEP_SIZE + MAX_LINE_LENGTH),  #
                (2 * MAX_LINE_LENGTH, 3 * MAX_LINE_LENGTH),  #
            },  #
            ScanType.get_chunks(3 * MAX_LINE_LENGTH))

    def test_get_chunks_coverage_p(self):
        line_len = 0
        while 42 * MAX_LINE_LENGTH > line_len:
            line_len += random.randint(1, MAX_LINE_LENGTH)
            data = bytearray(line_len)
            chunks = ScanType.get_chunks(line_len)
            for start, end in chunks:
                for i in range(start, end):
                    data[i] += 1
            self.assertNotIn(0, data)
            self.assertGreaterEqual(3, max(data))
