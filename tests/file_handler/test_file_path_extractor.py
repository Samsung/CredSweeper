from credsweeper.file_handler.file_path_extractor import FilePathExtractor


class TestFilePathExtractor:
    def test_apply_gitignore_p(self) -> None:
        """Evaluate that code files would be included after filtering with .gitignore"""

        files = ["file.py", "src/file.py", "src/dir/file.py"]

        filtered_files = FilePathExtractor.apply_gitignore(files)

        assert set(filtered_files) == set(files)

    def test_apply_gitignore_n(self) -> None:
        """Evaluate that .gitignore correctly filters out files from project"""

        files = [".idea", ".idea/file1.txt", ".idea/dir/file1.txt", ".cache", "system.log", "src/dir/file.so"]

        filtered_files = FilePathExtractor.apply_gitignore(files)

        assert len(filtered_files) == 0
