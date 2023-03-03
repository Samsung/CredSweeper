import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from credsweeper.file_handler.text_provider import TextProvider
from tests import AZ_DATA, AZ_STRING, SAMPLES_DIR


class TestTextProvider(unittest.TestCase):

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

            file_providers_str = TextProvider([str(sample_path)])
            file_text_providers_str = file_providers_str.get_scannable_files(config)
            self.assertEqual(1, len(file_text_providers_str))
            file_text_targets_str = file_text_providers_str[0].get_analysis_target()
            self.assertEqual(1, len(file_text_targets_str))
            self.assertEqual(AZ_STRING, file_text_targets_str[0].line)

            file_providers_pathlib = TextProvider([Path(sample_path)])
            file_text_providers_pathlib = file_providers_pathlib.get_scannable_files(config)
            self.assertEqual(1, len(file_text_providers_pathlib))
            file_text_targets_pathlib = file_text_providers_pathlib[0].get_analysis_target()
            self.assertEqual(1, len(file_text_targets_pathlib))
            self.assertEqual(AZ_STRING, file_text_targets_pathlib[0].line)

            with patch("builtins.open") as open_mock_str:
                text_provider_str_io = TextProvider([(str(sample_path), io_data)])
                io_text_providers_str_io = text_provider_str_io.get_scannable_files(config)
                self.assertEqual(1, len(io_text_providers_str_io))
                io_text_targets_str_io = io_text_providers_str_io[0].get_analysis_target()
                self.assertEqual(1, len(io_text_targets_str_io))
                self.assertEqual(AZ_STRING, io_text_targets_str_io[0].line)
                open_mock_str.assert_not_called()

            # return the cursor to begin
            io_data.seek(0, io.SEEK_SET)

            with patch("builtins.open") as open_mock_io:
                text_provider_pathlib_io = TextProvider([(Path(sample_path), io_data)])
                io_text_providers_pathlib_io = text_provider_pathlib_io.get_scannable_files(config)
                self.assertEqual(1, len(io_text_providers_pathlib_io))
                io_text_targets_pathlib_io = io_text_providers_pathlib_io[0].get_analysis_target()
                self.assertEqual(1, len(io_text_targets_pathlib_io))
                self.assertEqual(AZ_STRING, io_text_targets_pathlib_io[0].line)
                open_mock_io.assert_not_called()

            # return the cursor again
            io_data.seek(0, io.SEEK_SET)

            with patch("builtins.open") as open_mock_io:
                text_provider_io = TextProvider([io_data])
                io_text_providers_io = text_provider_io.get_scannable_files(config)
                self.assertEqual(1, len(io_text_providers_io))
                io_text_targets_io = io_text_providers_io[0].get_analysis_target()
                self.assertEqual(1, len(io_text_targets_io))
                self.assertEqual(AZ_STRING, io_text_targets_io[0].line)
                open_mock_io.assert_not_called()

    def test_get_scannable_files_io_n(self) -> None:
        io_data = io.BytesIO(AZ_DATA)

        config = MagicMock()
        config.not_allowed_path_pattern.match.return_value = False
        config.exclude_patterns.return_value = []
        config.exclude_paths.return_value = []
        config.exclude_extensions.return_value = []
        config.depth.return_value = True

        provider = TextProvider([(io_data, SAMPLES_DIR)])
        self.assertEqual([], provider.get_scannable_files(config))
