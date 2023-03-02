import io
import os
import tempfile
from unittest.mock import patch

from credsweeper.common.constants import DiffRowType
from credsweeper.config import Config
from credsweeper.file_handler.patch_provider import PatchProvider
from credsweeper.utils import Util
from tests import SAMPLES_DIR


class TestPatchProvider:

    def test_load_patch_data_p(self, config: Config) -> None:
        """Evaluate base load diff file"""
        file_path = SAMPLES_DIR / "password.patch"
        patch_provider = PatchProvider([file_path], DiffRowType.ADDED)

        raw_patches = patch_provider.load_patch_data(config)

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

    def test_load_patch_data_io_p(self, config: Config) -> None:
        """Evaluate base load diff file with io.BytesIO"""
        file_path = SAMPLES_DIR / "password.patch"
        data = Util.read_data(str(file_path))
        io_data = io.BytesIO(data)
        patch_provider = PatchProvider([io_data], DiffRowType.ADDED)

        raw_patches = patch_provider.load_patch_data(config)

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

    def test_load_patch_data_utf16_n(self, config: Config) -> None:
        """Evaluate load diff file with UTF-16 encoding"""
        file_path = SAMPLES_DIR / "password_utf16.patch"
        patch_provider = PatchProvider([str(file_path)], DiffRowType.ADDED)

        with patch('logging.Logger.info') as mocked_logger:
            raw_patches = patch_provider.load_patch_data(config)
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

    def test_load_patch_data_western_n(self, config: Config) -> None:
        """Evaluate load diff file with Western encoding"""
        file_path = SAMPLES_DIR / "password_western.patch"
        patch_provider = PatchProvider([str(file_path)], DiffRowType.ADDED)

        with patch('logging.Logger.info') as mocked_logger:
            raw_patches = patch_provider.load_patch_data(config)
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

    def test_load_patch_data_n(self, config: Config) -> None:
        """Evaluate warning occurrence while load diff file with ISO-IR-111 encoding"""
        file_path = SAMPLES_DIR / "iso_ir_111.patch"
        patch_provider = PatchProvider([str(file_path)], DiffRowType.ADDED)

        with patch('logging.Logger.info') as mocked_logger:
            raw_patches = patch_provider.load_patch_data(config)
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

    def test_oversize_n(self, config: Config) -> None:
        """Evaluate warning occurrence while load oversize diff file"""
        # use UTF-16 encoding to prevent any Windows style transformation
        file_path = SAMPLES_DIR / "password_utf16.patch"
        patch_provider = PatchProvider([str(file_path)], DiffRowType.ADDED)

        config.size_limit = 0
        with patch('logging.Logger.warning') as mocked_logger:
            raw_patches = patch_provider.load_patch_data(config)
            warning_message = f"Size (512) of the file '{file_path}' is over limit (0)"
            mocked_logger.assert_called_with(warning_message)

        assert isinstance(raw_patches, list)
        assert len(raw_patches) == 0

    def test_memory_error_n(self, config: Config) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = os.path.join(tmp_dir, "test.patch")
            assert not os.path.exists(file_path)
            with open(file_path, "w") as f:
                f.write("""diff --git a/creds.py
@@ -00000000000000000000000000000000000000000000000000000000000000000000000000000000000000002985304056119834851 +1,4 @@
+{
+  "wrong diff",
+  "sword": "FISH"
+  t............................................. li.k re...o0i:api........///:..N&.@........00000000..7ebf3947
--- /dev/null
+++ b/.changes.........json
@@ -0,0 +1,4 @@
+{
+  correct
+  lines

""")
            patch_provider = PatchProvider([str(file_path)], DiffRowType.ADDED)
            with patch('logging.Logger.error') as mocked_logger:
                test_files = patch_provider.get_scannable_files(config)
                assert len(test_files) == 1
                assert test_files[0].get_analysis_target() == []
                mocked_logger.assert_called_with("Wrong diff <class 'MemoryError'> ")

    def test_overflow_error_n(self, config: Config) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = os.path.join(tmp_dir, "test.patch")
            assert not os.path.exists(file_path)
            with open(file_path, "w") as f:
                f.write("""OverflowError
diff --git a/.changes/1.16.98.json b/.changes/1.16.98.json
new file mode 100644
index 00000000..7ebf3947
--- /dev/null
+++ b/.changes/1.16.98.json
@@ -0,0 +12345678901234567890,12345678901234567894 @@
+{
+  "category": "``cloudformation``",
+  "password": "dkajco1"
+}


""")
            patch_provider = PatchProvider([str(file_path)], DiffRowType.ADDED)
            with patch('logging.Logger.error') as mocked_logger:
                test_files = patch_provider.get_scannable_files(config)
                assert len(test_files) == 1
                assert test_files[0].get_analysis_target() == []
                mocked_logger.assert_called_with(
                    "Wrong diff <class 'OverflowError'> cannot fit 'int' into an index-sized integer")
