import io
import os
import tempfile
from unittest.mock import patch

from credsweeper.common.constants import DiffRowType, UTF_16, UTF_8
from credsweeper.config.config import Config
from credsweeper.file_handler.patches_provider import PatchesProvider
from credsweeper.utils.util import Util
from tests import SAMPLES_PATH


class TestPatchesProvider:

    def test_load_patch_data_p(self, config: Config) -> None:
        """Evaluate base load diff file"""
        patch_file = SAMPLES_PATH / "password.patch"
        patch_provider = PatchesProvider([patch_file], DiffRowType.ADDED)

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
        patch_file = SAMPLES_PATH / "password.patch"
        data = Util.read_data(str(patch_file))
        io_data = io.BytesIO(data)
        patch_provider = PatchesProvider([io_data], DiffRowType.ADDED)

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
        patch_file = SAMPLES_PATH / "password_utf16.patch"
        patch_provider = PatchesProvider([str(patch_file)], DiffRowType.ADDED)

        with patch('logging.Logger.info') as mocked_logger:
            raw_patches = patch_provider.load_patch_data(config)
            warning_message = f"UnicodeError: Can't decode content as {UTF_8}."
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
        patch_file = SAMPLES_PATH / "password_western.patch"
        patch_provider = PatchesProvider([patch_file], DiffRowType.ADDED)

        with patch('logging.Logger.info') as mocked_logger:
            raw_patches = patch_provider.load_patch_data(config)
            warning_message = f"UnicodeError: Can't decode content as {UTF_16}."
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
        patch_file = SAMPLES_PATH / "iso_ir_111.patch"
        patch_provider = PatchesProvider([str(patch_file)], DiffRowType.ADDED)

        with patch('logging.Logger.info') as mocked_logger:
            raw_patches = patch_provider.load_patch_data(config)
            warning_message = f"UnicodeError: Can't decode content as {UTF_16}."
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
        patch_file = SAMPLES_PATH / "password_utf16.patch"
        patch_provider = PatchesProvider([str(patch_file)], DiffRowType.ADDED)

        config.size_limit = 0
        with patch('logging.Logger.warning') as mocked_logger:
            raw_patches = patch_provider.load_patch_data(config)
            warning_message = f"Size (512) of the file '{patch_file}' is over limit (0)"
            mocked_logger.assert_called_with(warning_message)

        assert isinstance(raw_patches, list)
        assert len(raw_patches) == 0

    def test_memory_error_n(self, config: Config) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            patch_file = os.path.join(tmp_dir, "test.patch")
            assert not os.path.exists(patch_file)
            with open(patch_file, "w") as f:
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
            patch_provider = PatchesProvider([str(patch_file)], DiffRowType.ADDED)
            with patch('logging.Logger.error') as mocked_logger:
                test_files = patch_provider.get_scannable_files(config)
                assert len(test_files) == 1
                targets = [x for x in test_files[0].yield_analysis_target(0)]
                assert len(targets) == 7
                mocked_logger.assert_not_called()

    def test_overflow_error_n(self, config: Config) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            patch_file = os.path.join(tmp_dir, "test.patch")
            assert not os.path.exists(patch_file)
            with open(patch_file, "w") as f:
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
            patch_provider = PatchesProvider([str(patch_file)], DiffRowType.ADDED)
            with patch('logging.Logger.error') as mocked_logger:
                test_files = patch_provider.get_scannable_files(config)
                assert len(test_files) == 1
                targets = [x for x in test_files[0].yield_analysis_target(0)]
                assert len(targets) == 4
                mocked_logger.assert_not_called()
