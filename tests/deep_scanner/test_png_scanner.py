import base64
import unittest

from credsweeper.deep_scanner.png_scanner import PngScanner

sample_png_b64 = """
iVBORw0KGgoAAAANSUhEUgAAAAgAAAAICAAAAADhZOFXAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAdnJLH8AAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUw
AADqYAAAOpgAABdwnLpRPAAAACx0RVh0Q29tbWVudABlN2RiYTljMS1kZWFkLWJlZWYtY2FmZS02MTM5NDc0YmNmODKLJWKsAAAAEElEQVQI12P8zwABTAwU
MQBJQQEPsgmdYgAAAABJRU5ErkJggg==
"""


class TestPngScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_match_n(self):
        with self.assertRaises(AttributeError):
            PngScanner.match(None)
        self.assertFalse(PngScanner.match(b''))

    def test_match_p(self):
        self.assertTrue(PngScanner.match(b'\x89PNG\r\n\x1a\n'))
        self.assertTrue(PngScanner.match(base64.b64decode(sample_png_b64)))

    def test_yield_png_chunks_p(self):
        self.assertListEqual([(114, 'PNG_TEXT:Comment', b'e7dba9c1-dead-beef-cafe-6139474bcf82')],
                             list(PngScanner.yield_png_chunks(base64.b64decode(sample_png_b64))))
