import unittest

from credsweeper.file_handler.text_provider import TextProvider


class TestTextProvider(unittest.TestCase):

    def test_get_files_sequence_n(self) -> None:
        tp = TextProvider([])
        self.assertEqual([], tp.get_files_sequence([]))

