import json
import unittest

from credsweeper.deep_scanner.snk_scanner import SnkScanner


class TestSnkScanner(unittest.TestCase):

    def test_match_n(self):
        # Wrong data type
        with self.assertRaises(AttributeError):
            SnkScanner.match(None)
        with self.assertRaises(AttributeError):
            SnkScanner.match(1)
        # Too short
        self.assertFalse(SnkScanner.match(b""))
        self.assertFalse(SnkScanner.match(b"\x07\x02\x00\x00\x00$\x00\x00RSA1"))

    def test_match_p(self):
        # Valid .snk signature with private key
        self.assertTrue(SnkScanner.match(b"\x07\x02\x00\x00\x00$\x00\x00RSA2\x00\x04\x00\x00"))

    @staticmethod
    def __make_payload(pub_exp, modulus, prime1, prime2, exponent1, exponent2, coefficient, private_exponent):
        return (b"\x07\x02\x00\x00\x00$\x00\x00RSA2\x40\x00\x00\x00"  #
                + int(pub_exp).to_bytes(4, "little")  #
                + int(modulus).to_bytes(8, "little")  #
                + int(prime1).to_bytes(4, "little")  #
                + int(prime2).to_bytes(4, "little")  #
                + int(exponent1).to_bytes(4, "little")  #
                + int(exponent2).to_bytes(4, "little")  #
                + int(coefficient).to_bytes(4, "little")  #
                + int(private_exponent).to_bytes(8, "little")  #
                )

    def test_extract_n(self):
        self.assertIsNone(SnkScanner.extract(b"\x07\x02\x00\x00\x00$\x00\x00RSA2\xFF\x04\x00\x00"))
        self.assertIsNone(SnkScanner.extract(b"\x07\x02\x00\x00\x00$\x00\x00RSA2\x10\x00\x00\x00"))
        self.assertIsNone(SnkScanner.extract(b"\x07\x02\x00\x00\x00$\x00\x00RSA2\x00\xFF\xFF\xFF"))
        self.assertIsNone(SnkScanner.extract(b"\x07\x02\x00\x00\x00$\x00\x00RSA2\x00\x04\x00\x00"))
        # each param was mutated separately
        self.assertIsNone(SnkScanner.extract(self.__make_payload(71, 64507, 251, 257, 103, 241, 42, 26353)))
        self.assertIsNone(SnkScanner.extract(self.__make_payload(17, 76450, 251, 257, 103, 241, 42, 26353)))
        self.assertIsNone(SnkScanner.extract(self.__make_payload(17, 64507, 125, 257, 103, 241, 42, 26353)))
        self.assertIsNone(SnkScanner.extract(self.__make_payload(17, 64507, 251, 725, 103, 241, 42, 26353)))
        self.assertIsNone(SnkScanner.extract(self.__make_payload(17, 64507, 251, 257, 310, 241, 42, 26353)))
        self.assertIsNone(SnkScanner.extract(self.__make_payload(17, 64507, 251, 257, 103, 124, 42, 26353)))
        self.assertIsNone(SnkScanner.extract(self.__make_payload(17, 64507, 251, 257, 103, 241, 24, 26353)))
        self.assertIsNone(SnkScanner.extract(self.__make_payload(17, 64507, 251, 257, 103, 241, 42, 32635)))

    def test_extract_p(self):
        jwk_string = SnkScanner.extract(self.__make_payload(17, 64507, 251, 257, 103, 241, 42, 26353))
        self.assertIsNotNone(jwk_string)
        jwk = json.loads(jwk_string)
        self.assertDictEqual(
            {
                "kty": "RSA",  #
                "e": "EQAAAA",  #
                "n": "-_sAAAAAAAA",  #
                "d": "8WYAAAAAAAA",  #
                "p": "-wAAAA",  #
                "q": "AQEAAA",  #
                "dp": "ZwAAAA",  #
                "dq": "8QAAAA",  #
                "qi": "KgAAAA",  #
            },
            jwk)
