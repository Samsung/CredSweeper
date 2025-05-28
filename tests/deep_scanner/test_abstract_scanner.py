import random
import unittest

from credsweeper.deep_scanner.abstract_scanner import AbstractScanner
from tests import AZ_STRING, AZ_DATA


class TestAbstractScanner(unittest.TestCase):

    def test_structure_processing_n(self):
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure=None)))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure=42)))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure=3.14)))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure=AZ_STRING)))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure=AZ_DATA)))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure=())))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure=[])))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure={})))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure={0: [], 1: (), 2: {}})))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure={"key": None})))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure={"key": 0})))
        self.assertListEqual([], list(AbstractScanner.structure_processing(structure={"key": False})))

    def test_structure_processing_p(self):
        self.assertListEqual([(0, 1), (1, 2), (2, 3)], list(AbstractScanner.structure_processing(structure=(1, 2, 3))))
        self.assertListEqual([(0, 1), (1, 2), (2, 3)], list(AbstractScanner.structure_processing(structure=[1, 2, 3])))
        self.assertListEqual([(0, 1), (1, 2), (2, 3)],
                             list(AbstractScanner.structure_processing(structure={
                                 0: 1,
                                 1: 2,
                                 2: 3
                             })))
        self.assertListEqual([(42, 3.14)], list(AbstractScanner.structure_processing(structure={42: 3.14})))
        self.assertListEqual([("key", AZ_STRING), ("VALUE", AZ_DATA), (AZ_STRING, AZ_DATA)],
                             list(AbstractScanner.structure_processing(structure={
                                 "key": AZ_STRING,
                                 "VALUE": AZ_DATA
                             })))

    def test_key_value_combination_n(self):
        # bytes in key do not produce augmented pair
        self.assertListEqual([],
                             list(AbstractScanner.key_value_combination(structure={
                                 "key": AZ_STRING,
                                 b"VALUE": AZ_DATA
                             })))
        # and wrong symbols do not produce the pair
        self.assertListEqual([],
                             list(AbstractScanner.key_value_combination(structure={
                                 "KEY": AZ_STRING,
                                 "VaLuE": AZ_DATA
                             })))
        # bytes which cannot be decoded do not produce the augmentation
        self.assertListEqual([],
                             list(AbstractScanner.key_value_combination(structure={
                                 "Key": random.randbytes(16),
                                 "VALUE": AZ_DATA
                             })))

    def test_key_value_combination_p(self):
        self.assertListEqual([(AZ_STRING, AZ_DATA)],
                             list(AbstractScanner.key_value_combination(structure={
                                 "Key": AZ_STRING,
                                 "VALUE": AZ_DATA
                             })))
        # bytes in key value may produce the augmentation
        self.assertListEqual([(AZ_STRING, AZ_DATA)],
                             list(AbstractScanner.key_value_combination(structure={
                                 "Key": AZ_DATA,
                                 "VALUE": AZ_DATA
                             })))
