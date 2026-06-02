import unittest

from credsweeper import CredSweeper
from credsweeper.common.constants import RECURSIVE_SCAN_LIMITATION
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from tests.file_handler.zip_bomb_1 import zb1
from tests.file_handler.zip_bomb_2 import zb2


class TestStructContentProvider(unittest.TestCase):

    def test_free_n(self) -> None:
        provider = StructContentProvider({})
        provider.free()
        self.assertIsNone(provider.struct)
        provider.free()
        provider.free()

    def test_data_n(self) -> None:
        with self.assertRaises(NotImplementedError):
            _ = StructContentProvider({}).data

    def test_scan_zipfile_bomb_n(self) -> None:
        # negative limit, depth=5
        cs = CredSweeper(depth=5)
        zb_struct = [zb1, zb2, "password=tizen"]
        content_provider = StructContentProvider(zb_struct, "zip_bombs")
        res_2 = cs.deep_scanner.structure_scan(content_provider, 5, -1)
        self.assertEqual(0, len(res_2))

    def test_scan_zipfile_bomb_p(self) -> None:
        # default limit, depth=5
        cs = CredSweeper(depth=5)
        zb_struct = [zb1, zb2, "password=tizen"]
        content_provider = StructContentProvider(zb_struct, "zip_bombs")
        res_2 = cs.deep_scanner.structure_scan(content_provider, 5, RECURSIVE_SCAN_LIMITATION)
        self.assertEqual(1, len(res_2))
