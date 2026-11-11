import unittest

from credsweeper.deep_scanner.lang_scanner import LangScanner


class TestLangScanner(unittest.TestCase):

    def test_parse_py_p(self):
        result = LangScanner.parse_python("""password = \
        "Hello" \
        ' World!'""")
        self.assertIsInstance(result, list)
        self.assertListEqual(["password = 'Hello World!'"], result)

    def test_parse_py_n(self):
        # empty
        self.assertListEqual([], LangScanner.parse_python(''))
        # bash
        with self.assertRaises(SyntaxError):
            LangScanner.parse_python("""PSWD=$MYPW""")
        # wrong syntax
        with self.assertRaises(SyntaxError):
            LangScanner.parse_python("""<html>"Hello World!"</html>""")
        with self.assertRaises(SyntaxError):
            LangScanner.parse_python("""{'wrong': ': '"\." is syntax warning'}""")

    def test_match_p(self):
        self.assertTrue(LangScanner.match(b'cred=[\n"test"\n]\n'))

    def test_match_n(self):
        with self.assertRaises(TypeError):
            self.assertFalse(LangScanner.match(None))
        self.assertFalse(LangScanner.match(b''))
        self.assertFalse(LangScanner.match(b'%Lang+'))
