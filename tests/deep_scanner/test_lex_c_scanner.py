import unittest

from credsweeper.deep_scanner.lexer_scanner import LexerScanner
from credsweeper.file_handler.descriptor import Descriptor


class TestLexCScanner(unittest.TestCase):

    def test_guess_n(self):
        self.assertFalse(LexerScanner.get_lexer("</LexC><LexC>", Descriptor("./pom.xml", ".xml", "not C source")))
        with self.assertRaises(AttributeError):
            LexerScanner.get_lexer("int main(){return 0;};", None)

    def test_guess_p(self):
        self.assertTrue(LexerScanner.get_lexer("int main(){return 0;};", Descriptor("./main.c", ".c", "C source")))

    def test_get_lines_n(self):
        lines, line_numbers = LexerScanner.get_lines_semicolon("")
        self.assertListEqual([], lines)
        self.assertListEqual([], line_numbers)

    def test_get_lines_p(self):
        lines, line_numbers = LexerScanner.get_lines_semicolon("""#pragma comment(lib, "api.lib")
#ifdef NONE
  #define NONE 0
#else
  #warning "NONE"
#endif
  easy_setopt(curl, CURLOPT_XOAUTH2_BEARER,
              "c4e448d652a961fda0ab64f882c8c161d\
5985f805d45d80c9ddca1");
  easy_setopt(curl, CURLOPT_SASL_AUTHZID,
              "c4e448d652a961fda0ab64f882c8c161d5985f805d45d80c9ddca2");
  easy_setopt(curl, CURLOPT_URL, URL);
""")
        self.assertListEqual(
            ['#pragma comment(lib, "api.lib")',
             '#ifdef NONE',
             ' #define NONE 0',
             '#else',
             ' #warning "NONE"',
             '#endif',
             ' easy_setopt(curl, CURLOPT_XOAUTH2_BEARER,  "c4e448d652a961fda0ab64f882c8c161d5985f805d45d80c9ddca1");',
             '  easy_setopt(curl, CURLOPT_SASL_AUTHZID,  "c4e448d652a961fda0ab64f882c8c161d5985f805d45d80c9ddca2");',
             '  easy_setopt(curl, CURLOPT_URL, URL);',
             ' '], lines)
        self.assertListEqual([1, 2, 3, 4, 5, 6, 7, 8, 10, 11], line_numbers)
        self.assertEqual(len(lines), len(line_numbers))
