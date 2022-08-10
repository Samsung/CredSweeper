from pathlib import Path
from unittest import mock
from unittest.mock import Mock, patch

from credsweeper.file_handler.patch_provider import PatchProvider


class TestPatchProvider:

    def test_load_patch_data_p(self) -> None:
        """Evaluate base load diff file"""
        dir_path = Path(__file__).resolve().parent.parent
        file_path = dir_path / "samples" / "password.patch"
        patch_provider = PatchProvider([str(file_path)], "added")

        raw_patches = patch_provider.load_patch_data()

        expected = [[
            'diff --git a/.changes/1.16.98.json b/.changes/1.16.98.json',  #
            'new file mode 100644',  #
            'index 00000000..7ebf3947',  #
            '--- /dev/null',  #
            '+++ b/.changes/1.16.98.json',  #
            '@@ -0,0 +1,4 @@',  #
            '+{',  #
            '+  "category": "``cloudformation``",',  #
            '+  "password": "dkajco1"',  #
            '+}',  #
            '',  #
            ''  #
        ]]

        assert raw_patches == expected

    def test_load_patch_data_utf16_n(self) -> None:
        """Evaluate load diff file with UTF-16 encoding"""
        dir_path = Path(__file__).resolve().parent.parent
        file_path = dir_path / "samples" / "password_utf16.patch"
        patch_provider = PatchProvider([str(file_path)], "added")

        with patch('logging.Logger.info') as mocked_logger:
            raw_patches = patch_provider.load_patch_data()
            warning_message = f"UnicodeError: Can't read content from \"{file_path}\" as utf8."
            mocked_logger.assert_called_with(warning_message)

        expected = [[
            'diff --git a/.changes/1.16.98.json b/.changes/1.16.98.json',  #
            'new file mode 100644',  #
            'index 00000000..7ebf3947',  #
            '--- /dev/null',  #
            '+++ b/.changes/1.16.98.json',  #
            '@@ -0,0 +1,4 @@',  #
            '+{',  #
            '+  "info": "난 차를 마십니다"',  #
            '+  "category": "``cloudformation``",',  #
            '+  "password": "dkajco1"',  #
            '+}',  #
            '',  #
            ''  #
        ]]
        assert raw_patches == expected

    def test_load_patch_data_western_n(self) -> None:
        """Evaluate load diff file with Western encoding"""
        dir_path = Path(__file__).resolve().parent.parent
        file_path = dir_path / "samples" / "password_western.patch"
        patch_provider = PatchProvider([str(file_path)], "added")

        with patch('logging.Logger.info') as mocked_logger:
            raw_patches = patch_provider.load_patch_data()
            warning_message = f"UnicodeError: Can't read content from \"{file_path}\" as utf16."
            mocked_logger.assert_called_with(warning_message)

        expected = [[
            'diff --git a/.changes/1.16.98.json b/.changes/1.16.98.json',  #
            'new file mode 100644',  #
            'index 00000000..7ebf3947',  #
            '--- /dev/null',  #
            '+++ b/.changes/1.16.98.json',  #
            '@@ -0,0 +1,4 @@',  #
            '+{',  #
            '+  "category": "``cloudformation``",',  #
            '+  "password": "dkajcö1"',  #
            '+}',  #
            '',  #
            ''  #
        ]]
        assert raw_patches == expected

    @mock.patch("logging.info")
    def test_load_patch_data_n(self, mock_logging_info: Mock()) -> None:
        """Evaluate warning occurrence while load diff file with ISO-IR-111 encoding"""
        dir_path = Path(__file__).resolve().parent.parent
        file_path = dir_path / "samples" / "iso_ir_111.patch"
        patch_provider = PatchProvider([str(file_path)], "added")

        with patch('logging.Logger.info') as mocked_logger:
            raw_patches = patch_provider.load_patch_data()
            warning_message = f"UnicodeError: Can't read content from \"{file_path}\" as utf16."
            mocked_logger.assert_called_with(warning_message)

        expected = [[
            'ëÉÒÉÌÌÉÃÁ',  #
            'diff --git a/.changes/1.16.98.json b/.changes/1.16.98.json',  #
            'new file mode 100644',  #
            'index 00000000..7ebf3947',  #
            '--- /dev/null',  #
            '+++ b/.changes/1.16.98.json',  #
            '@@ -0,0 +1,4 @@',  #
            '+{',  #
            '+  "category": "``cloudformation``",',  #
            '+  "password": "dkajco1"',  #
            '+}',  #
            '',  #
            ''  #
        ]]
        assert raw_patches == expected
