import unittest

from credsweeper.file_handler.struct_content_provider import StructContentProvider


class TestStructContentProvider(unittest.TestCase):

    def test_free_n(self) -> None:
        provider = StructContentProvider({})
        provider.free()
        self.assertIsNone(provider.struct)

    def test_data_n(self) -> None:
        with self.assertRaises(NotImplementedError):
            _ = StructContentProvider({}).data
