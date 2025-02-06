import unittest

from credsweeper.common.constants import DiffRowType
from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.file_handler.diff_content_provider import DiffContentProvider
from credsweeper.file_handler.struct_content_provider import StructContentProvider
from credsweeper.utils import DiffRowData, DiffDict


class TestStructContentProvider(unittest.TestCase):

    def test_free_n(self) -> None:
        provider = StructContentProvider({})
        provider.free()
        self.assertIsNone(provider.struct)

    def test_data_n(self) -> None:
        with self.assertRaises(NotImplementedError):
            _ = StructContentProvider({}).data
