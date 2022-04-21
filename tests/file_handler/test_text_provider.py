from credsweeper.file_handler.text_provider import TextProvider


class TestTextProvider:
    def test_get_files_sequence_n(self) -> None:
        tp = TextProvider([])
        assert len(tp.get_files_sequence([])) == 0
