import random
import unittest

from hypothesis import strategies, given

from credsweeper.deep_scanner.csv_scanner import CsvScanner
from tests import AZ_STRING, SAMPLES_PATH, AZ_DATA


class TestCsvScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_match_n(self):
        self.assertFalse(CsvScanner.match(random.randbytes(random.randint(4, 16))))
        self.assertFalse(CsvScanner.match(b''))
        self.assertFalse(CsvScanner.match(b'||||'))
        self.assertFalse(CsvScanner.match(AZ_DATA))
        self.assertFalse(CsvScanner.match(AZ_DATA + b'\r\n'))

    def test_match_p(self):
        self.assertTrue(CsvScanner.match(b'a|b\r1|2'))
        self.assertTrue(CsvScanner.match(b'a|b\n1|2'))
        self.assertTrue(CsvScanner.match(b'a|b\r\n1|2'))

    def test_get_structure_n(self):
        with self.assertRaises(ValueError):
            CsvScanner.get_structure('First line,"and escaped,coma"\nSecond,line,with more comas\n')
        with self.assertRaises(ValueError):
            CsvScanner.get_structure("First,line\nSecond,line,with,more,comas")
        with self.assertRaises(Exception):
            CsvScanner.get_structure(f"{AZ_STRING[:19]}\n{AZ_STRING[20:]}\n")
        with self.assertRaises(Exception):
            CsvScanner.get_structure("'user and password'\nadmin&tizen\n")
        with self.assertRaises(Exception):
            CsvScanner.get_structure('')
        with self.assertRaises(Exception):
            CsvScanner.get_structure("user&password\nadmin&tizen\n")
        with self.assertRaises(Exception):
            CsvScanner.get_structure('"user and password"\nadmin&tizen\n')
        with self.assertRaises(ValueError):
            CsvScanner.get_structure("user,password\tadmin,tizen\t")

    def test_get_structure_from_sample_n(self):
        with self.assertRaises(ValueError):
            with open(SAMPLES_PATH / "aws_client_id") as f:
                CsvScanner.get_structure(f.read())

    def test_get_structure_p(self):
        structure = CsvScanner.get_structure("user,password\nadmin,tizen\nempty,\n")
        self.assertIsInstance(structure, list)
        self.assertEqual(2, len(structure))
        self.assertDictEqual({'password': 'tizen', 'user': 'admin'}, structure[0])
        self.assertDictEqual({'password': '', 'user': 'empty'}, structure[1])
        #CsvScanner.get_structure("Feuer und Wasser\ncommt nicht zusammen\n")
