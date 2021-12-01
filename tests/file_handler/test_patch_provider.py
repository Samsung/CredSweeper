from pathlib import Path
from unittest import mock

from credsweeper.file_handler.patch_provider import PatchProvider

class TestPatchProvider:
    def test_load_patch_data_p(self) -> None:
        """Evaluate load diff file"""
        dir_path = Path(__file__).resolve().parent.parent
        file_path = dir_path/"samples"/"password.patch"
        patch_provider = PatchProvider([file_path], "added")

        raw_patches = patch_provider.load_patch_data()

        expected = [
            [
                'diff --git a/.changes/1.16.98.json b/.changes/1.16.98.json\n',
                'new file mode 100644\n',
                'index 00000000..7ebf3947\n',
                '--- /dev/null\n',
                '+++ b/.changes/1.16.98.json\n',
                '@@ -0,0 +1,4 @@\n',
                '+{\n',
                '+  "category": "``cloudformation``",\n',
                '+  "password": "dkajco1"\n',
                '+}\n',
                '\n'
            ]
        ]

        assert raw_patches == expected

    @mock.patch("logging.warning")
    def test_load_patch_data_utf16_n(self, mock_logging_warning: mock) -> None:
        """Evaluate load diff file"""
        dir_path = Path(__file__).resolve().parent.parent
        file_path = dir_path/"samples"/"password_utf16.patch"
        patch_provider = PatchProvider([file_path], "added")

        raw_patches = patch_provider.load_patch_data()

        expected = [
            [
                'diff --git a/.changes/1.16.98.json b/.changes/1.16.98.json\n',
                'new file mode 100644\n',
                'index 00000000..7ebf3947\n',
                '--- /dev/null\n',
                '+++ b/.changes/1.16.98.json\n',
                '@@ -0,0 +1,4 @@\n',
                '+{\n',
                '+  "category": "``cloudformation``",\n',
                '+  "password": "dkajco1"\n',
                '+}\n',
                '\n'
            ]
        ]

        warning_message = f"UnicodeDecodeError: Can't read patch content from \"{file_path}\"."
        mock_logging_warning.assert_called_once_with(warning_message)
        assert raw_patches == expected

    @mock.patch("logging.error")
    def test_load_patch_data_western_n(self, mock_logging_error: mock) -> None:
        """Evaluate load diff file"""
        dir_path = Path(__file__).resolve().parent.parent
        file_path = dir_path/"samples"/"password_western.patch"
        patch_provider = PatchProvider([file_path], "added")

        raw_patches = patch_provider.load_patch_data()

        expected = [[]]
        error_message = f"UnicodeError: Can't read patch content from \"{file_path}\"."
        mock_logging_error.assert_called_once_with(error_message)
        assert raw_patches == expected

    @mock.patch("logging.error")
    def test_load_patch_data_n(self, mock_logging_error: mock) -> None:
        """Evaluate load diff file"""
        dir_path = Path(__file__).resolve().parent.parent
        file_path = dir_path/"samples"/"iso_ir_111.patch"
        patch_provider = PatchProvider([file_path], "added")

        raw_patches = patch_provider.load_patch_data()

        expected = [[]]

        error_message = f"UnicodeError: Can't read patch content from \"{file_path}\"."
        mock_logging_error.assert_called_once_with(error_message)
        assert raw_patches == expected
