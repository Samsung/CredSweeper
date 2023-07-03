import unittest

from credsweeper.scanner.scan_type import PemKeyPattern


class TestPemKeyPattern(unittest.TestCase):

    def test_remove_leading_config_lines_p(self):
        lines = ["Proc-Type: 4,ENCRYPTED", "DEK-Info: DES-EDE3-CBC,BA2D3F11273F6I7A", ""]
        for line in lines:
            self.assertTrue(PemKeyPattern.is_leading_config_line(line), line)

    def test_remove_leading_config_lines_n(self):
        lines = [
            "MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp",
            "wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5",
            "1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh"
        ]
        for line in lines:
            self.assertFalse(PemKeyPattern.is_leading_config_line(line), line)

    def test_sanitize_line_p(self):
        lines = [
            "    MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCqx5mEeaMNCqr",
            "  \" hNtDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n\n' +",
            "#    //tDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n"
        ]
        should_be = [
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCqx5mEeaMNCqr",
            "hNtDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n",
            "//tDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n"
        ]
        for expect_line, line in zip(should_be, lines):
            self.assertEqual(expect_line, PemKeyPattern.sanitize_line(line), line)

    def test_sanitize_line_n(self):
        """Check that valid PEM lines will not be changed"""
        lines = [
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDCqx5mEeaMNCqr",
            "hNtDzrYypSREYpBHTUKoa+y0rRy74nLA1Z4+nKVOTdXNuMGLp9KxHqwIlDk8QK5n"
        ]
        for line in lines:
            self.assertEqual(line, PemKeyPattern.sanitize_line(line), line)
