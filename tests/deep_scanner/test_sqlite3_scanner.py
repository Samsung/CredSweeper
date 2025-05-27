import unittest

from credsweeper.deep_scanner.sqlite3_scanner import Sqlite3Scanner
from tests import SAMPLE_SQLITE


class TestSqlite3Scanner(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_walk_n(self):
        with self.assertRaises(Exception):
            list(Sqlite3Scanner.walk_sqlite(None))

    def test_walk_p(self):
        self.assertListEqual([('KEYS', {
            'ID': -1,
            'KEY': None
        }),
                              ('KEYS', {
                                  'ID': 1,
                                  'KEY': b'0\x82\x01=\x02\x01\x00\x02A\x00\xaf\xa2\x08\xbf\\U\xc2\xb8`\xa1'
                                  b'z~(\xe5\x03\x84\xbas\x10\xf8;]\xa1\xb6\xbd\xf1\xda8\x1d>'
                                  b'\xf8\x9c\xd6\x9e\x9b\xdf\x8a.\x01\xa25s\xae\xb9\t\x8d\xc1\xc4\x03O'
                                  b'{\xe4))\xd5\xb2\xa9\xfe\xcc\x18\xaf\xca\x87g\x02\x03'
                                  b'\x01\x00\x01\x02A\x00\x90P\xc9uLN\xdf\xe8\x96\xe68\xfb\xcfh'
                                  b'\x96\xe2\x8a> \x94\x88[`\x95\x030\xe6\xc9\xb3&Z+Q\x14\x80Y\xb6L'
                                  b"O\xff%-\x93\xca\xf2\xb0\x0f\xcc\x9aQJ\x03,'\x86\xca\xab\x87"
                                  b'\xf9JY\xc2\xcfq\x02!\x00\xd8\xcd\x0f\xdft-0-\xa9\xed/_\xa0\xbf\x96'
                                  b'\xdd\xe9=\x06\xcb\x8au\x7fR\xfb\xf7M9\xfb\xae\xe8Y\x02!\x00\xcfcsB'
                                  b'\x9fc\xba\xf53\xdd\x95a\x81\xf7\xab\xd36\xd6\x94\xbcS\xe7gR'
                                  b'\x00\\\xf0\x01e\x9e\xf5\xbf\x02!\x00\xcd\xf3W]\xcd\xaeS\xb3=Vm\x07i'
                                  b'\xdc7\x04M\xdaDG=\x1b\xcb=X\xd0\x9f\xd32-\x00\xd9\x02!\x00\xa9P'
                                  b'W,\x806\x8a\xcf_}\xbbTu(@\x16\xdb\x81\x8a\xc2\xcayt\xc7\xe4\xd5'
                                  b'\xfbx\x18\x80\x13\xbf\x02!\x00\xcc\x88\xf9P\xdc\xdf\x85ni\x80\x9c'
                                  b'\x0c\x1f=F\xfeq\xfa\x11\xad%1)~\xaeJ\xadR\x8aQ\xd0\x89'
                              }),
                              ('USERS', {
                                  'ID': 1,
                                  'PASSWORD': 'Dt1Js8m#1s',
                                  'TOKEN': 'xoxa-FLYLIKEAGIREOGI-b1da04e31f',
                                  'USER': '1d3e45d1-dead-beef-c0de-294622932701'
                              }),
                              ('USERS', {
                                  'ID': 2,
                                  'PASSWORD': 'password',
                                  'TOKEN': '1d3e45d1deadbeefc0de29beda932701',
                                  'USER': 'user'
                              })], list(Sqlite3Scanner.walk_sqlite(SAMPLE_SQLITE.read_bytes())))
