import unittest

from pygments.lexers.c_cpp import CLexer
from pygments.lexers.html import XmlLexer
from pygments.lexers.javascript import TypeScriptLexer
from pygments.lexers.special import TextLexer
from pygments.lexers.teraterm import TeraTermLexer

from credsweeper.deep_scanner.lexer_scanner import LexerScanner
from credsweeper.file_handler.descriptor import Descriptor


class TestLexerScanner(unittest.TestCase):

    def setUp(self) -> None:
        self.maxDiff = None

    def test_get_lexer_n(self):
        self.assertIsInstance(LexerScanner.get_lexer("</LexC><LexC>", Descriptor("./pom.xml", ".xml", "not C source")),
                              TextLexer)
        with self.assertRaises(AttributeError):
            LexerScanner.get_lexer("int main(){return 0;};", None)

    def test_get_lexer_p(self):
        self.assertIsInstance(
            LexerScanner.get_lexer("int main(){return 0;};", Descriptor("./main.c", ".c", "C source")), CLexer)
        self.assertIsInstance(
            LexerScanner.get_lexer('const PSWRD = encode("x34to-T0");', Descriptor("./main.ts", ".ts", "TypeScript")),
            TypeScriptLexer)

    def test_get_lines_n(self):
        lines, line_numbers = LexerScanner.get_lines_semicolon("", CLexer())
        self.assertListEqual([], lines)
        self.assertListEqual([], line_numbers)

    def test_get_lines_p(self):
        text = """/* A License */
#pragma comment(lib, "api.lib")
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
  char key ={
    1,2,3,4,5,6,7,8,9
    };
/**
  * ___Begin Private Key___
  * 347987598TheKeyEncodedValue21939874981
  * ___End Private Key___
  */
  char *password = /***** security *****/ "ThePassword"; 
// the end"""
        lexer = LexerScanner.get_lexer(text, Descriptor("test.c", ".c", ".c"))
        self.assertIsInstance(lexer, CLexer)
        lines, line_numbers = LexerScanner.get_lines_semicolon(text, lexer)
        self.assertEqual(len(lines), len(line_numbers))
        self.assertListEqual([
            '/* A License */', ' #pragma comment(lib, "api.lib")', '#ifdef NONE', ' #define NONE 0', '#else',
            ' #warning "NONE"', '#endif',
            ' easy_setopt(curl, CURLOPT_XOAUTH2_BEARER,  "c4e448d652a961fda0ab64f882c8c161d5985f805d45d80c9ddca1");',
            '  easy_setopt(curl, CURLOPT_SASL_AUTHZID,  "c4e448d652a961fda0ab64f882c8c161d5985f805d45d80c9ddca2");',
            '  easy_setopt(curl, CURLOPT_URL, URL);', '  char key ={  1,2,3,4,5,6,7,8,9  };', '/**',
            '  * ___Begin Private Key___', '  * 347987598TheKeyEncodedValue21939874981', '  * ___End Private Key___',
            '  */', '/***** security *****/', '   char *password =  "ThePassword";', '  // the end'
        ], lines)
