import os
import tempfile
import unittest

from credsweeper.file_handler.analysis_target import AnalysisTarget
from credsweeper.file_handler.descriptor import Descriptor
from credsweeper.file_handler.text_content_provider import TextContentProvider
from tests import SAMPLES_PATH


class TestTextContentProvider(unittest.TestCase):

    def test_get_analysis_target_p(self) -> None:
        """Evaluate that lines data correctly extracted from file"""
        target_path = SAMPLES_PATH / "password.gradle"
        content_provider = TextContentProvider(target_path)

        analysis_targets = [x for x in content_provider.yield_analysis_target(0)]

        all_lines = ['password = "cackle!"', '']
        expected_target = AnalysisTarget(0, all_lines, [x for x in range(len(all_lines))],
                                         Descriptor(str(target_path), target_path.suffix, ""))

        self.assertEqual(6, len(analysis_targets))

        target = analysis_targets[0]
        self.assertEqual(expected_target.line, target.line)

        target_path = SAMPLES_PATH / "xml_password.xml"
        content_provider = TextContentProvider(target_path)

        analysis_targets = [x for x in content_provider.yield_analysis_target(0)]

        all_lines = [
            "Countries : ", "Country : ", "City : Seoul", "password : cackle!", "Country : ", "City : Kyiv",
            "password : peace_for_ukraine"
        ]
        expected_target = AnalysisTarget(3, all_lines, [x for x in range(len(all_lines))],
                                         Descriptor(str(target_path), ".xml", ""))

        self.assertEqual(7, len(analysis_targets))

        target = analysis_targets[3]
        self.assertEqual(expected_target.line, target.line)

    def test_get_analysis_target_n(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            target_path = os.path.join(tmp_dir, "test_get_analysis_target_n.xml")

            with open(target_path, "w") as f:
                f.write("<password>crackle!</worng_grammar>")

            content_provider = TextContentProvider(target_path)

            analysis_targets = [x for x in content_provider.yield_analysis_target(0)]

            all_lines = ["<password>crackle!</worng_grammar>"]
            expected_target = AnalysisTarget(0, all_lines, [x for x in range(len(all_lines))],
                                             Descriptor(target_path, ".xml", ""))

            self.assertEqual(1, len(analysis_targets))

            target = analysis_targets[0]
            self.assertEqual(expected_target.line, target.line)
