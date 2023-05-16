import os
import tempfile

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.text_content_provider import TextContentProvider
from tests import SAMPLES_PATH


class TestTextContentProvider:

    def test_get_analysis_target_p(self) -> None:
        """Evaluate that lines data correctly extracted from file"""
        target_path = SAMPLES_PATH / "password.template"
        content_provider = TextContentProvider(target_path)

        analysis_targets = content_provider.get_analysis_target()

        all_lines = ['password = "cackle!"', '']
        expected_target = AnalysisTarget('password = "cackle!"', 1, all_lines, str(target_path), ".template", "")

        assert len(analysis_targets) == 2

        target = analysis_targets[0]
        assert target == expected_target

        target_path = SAMPLES_PATH / "xml_password.xml"
        content_provider = TextContentProvider(target_path)

        analysis_targets = content_provider.get_analysis_target()

        all_lines = [
            "Countries : ", "Country : ", "City : Seoul", "password : cackle!", "Country : ", "City : Kyiv",
            "password : peace_for_ukraine"
        ]
        expected_target = AnalysisTarget("password : cackle!", 5, all_lines, str(target_path), ".xml", "")

        assert len(analysis_targets) == 7

        target = analysis_targets[3]
        assert target == expected_target

    def test_get_analysis_target_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_path = os.path.join(tmp_dir, "test_get_analysis_target_n.xml")

            with open(target_path, "w") as f:
                f.write("<password>crackle!</worng_grammar>")

            content_provider = TextContentProvider(target_path)

            analysis_targets = content_provider.get_analysis_target()

            all_lines = ["<password>crackle!</worng_grammar>"]
            expected_target = AnalysisTarget("<password>crackle!</worng_grammar>", 1, all_lines, target_path, ".xml",
                                             "")

            assert len(analysis_targets) == 1

            target = analysis_targets[0]
            assert target == expected_target
