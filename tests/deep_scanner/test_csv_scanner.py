import unittest

from credsweeper.deep_scanner.csv_scanner import CsvScanner
from tests import AZ_STRING, TESTS_PATH, SAMPLES_PATH


class TestCsvScanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

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

