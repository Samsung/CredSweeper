import io
import os
import tempfile
import unittest
from unittest.mock import MagicMock

from credsweeper.file_handler.text_provider import TextProvider
from tests import AZ_DATA, AZ_STRING


class TestTextProvider(unittest.TestCase):

    def test_get_files_sequence_n(self) -> None:
        tp = TextProvider([])
        self.assertEqual([], tp.get_files_sequence([]))

    def test_get_scannable_files_io_p(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            sample_path = os.path.join(tmp_dir, "sample")
            with open(sample_path, "wb") as f:
                az_data_utf16 = AZ_STRING.encode("UTF-16")
                self.assertNotEqual(az_data_utf16, AZ_DATA)
                f.write(az_data_utf16)
            io_data = io.BytesIO(AZ_DATA)

            config = MagicMock()
            config.not_allowed_path_pattern.match.return_value = False
            config.exclude_patterns.return_value = []
            config.exclude_paths.return_value = []
            config.exclude_extensions.return_value = []
            config.depth.return_value = True

            file_providers = TextProvider([str(sample_path)])
            file_text_providers = file_providers.get_scannable_files(config)
            self.assertEqual(1, len(file_text_providers))
            file_text_targets = file_text_providers[0].get_analysis_target()
            self.assertEqual(1, len(file_text_targets))
            self.assertEqual(AZ_STRING, file_text_targets[0].line)

            text_provider = TextProvider([io_data])
            io_text_providers = text_provider.get_scannable_files(config)
            self.assertEqual(1, len(io_text_providers))
            io_text_targets = io_text_providers[0].get_analysis_target()
            self.assertEqual(1, len(io_text_targets))
            self.assertEqual(AZ_STRING, io_text_targets[0].line)
