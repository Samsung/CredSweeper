import os
import tempfile

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