import inspect
import re
import textwrap
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import TestCase


def example_bytes_scanning() -> None:
    import io

    from credsweeper import CredSweeper, FilesProvider

    to_scan = b"line one\npassword='cackle!'"
    cred_sweeper = CredSweeper()
    content_provider = FilesProvider([("example.py", io.BytesIO(to_scan))])
    cred_sweeper.run(content_provider=content_provider)
    for candidate in cred_sweeper.credential_manager.get_credentials():
        print(candidate)


def example_ml_validation() -> None:
    import io

    from credsweeper import CredSweeper, FilesProvider, MlValidator, ThresholdPreset
    from credsweeper.credentials.candidate_key import CandidateKey

    to_scan = b'line one\npassword = "cackle!"'
    cred_sweeper = CredSweeper()
    files_provider = FilesProvider([("example.py", io.BytesIO(to_scan))])
    content_providers = files_provider.get_scannable_files(cred_sweeper.config)
    candidates = cred_sweeper.file_scan(content_providers[0])

    grouped_candidates = {}
    for candidate in candidates:
        key = CandidateKey(candidate.line_data_list[0])
        grouped_candidates.setdefault(key, []).append(candidate)

    groups_for_ml = [(key, group) for key, group in grouped_candidates.items()
                     if any(candidate.use_ml for candidate in group)]

    validator = MlValidator(threshold=ThresholdPreset.medium)
    is_credential, probabilities = validator.validate_groups(
        groups_for_ml,
        batch_size=16,
        progress_callback=None,
    )

    for (_, group), accepted, probability in zip(groups_for_ml, is_credential, probabilities):
        if accepted:
            for candidate in group:
                if candidate.use_ml:
                    candidate.ml_probability = float(probability)
                    print(candidate)


class TestExample(TestCase):

    def _read_guide(self) -> str:
        guide_path = Path(__file__).resolve().parents[1] / "docs" / "source" / "guide.rst"
        return guide_path.read_text(encoding="utf-8")

    def _assert_example_is_in_guide(self, example_function) -> None:
        source_lines, _ = inspect.getsourcelines(example_function)
        example_source = textwrap.dedent("".join(source_lines[1:])).strip("\n")
        expected_code = "\n".join(f"    {line}" if line else "" for line in example_source.splitlines())
        self.assertIn(expected_code, self._read_guide())

    @staticmethod
    def _normalize_probability(value: str) -> str:
        return re.sub(
            r"ml_probability: [0-9.eE+-]+",
            "ml_probability: <probability>",
            value,
        )

    def _assert_result_is_in_guide(self, output: str) -> None:
        result_lines = [line.strip() for line in output.splitlines() if line.strip().startswith("rule: Password |")]
        self.assertTrue(result_lines, msg=f"No password result was printed. Output: {output!r}")

        # ML probabilities can vary slightly between environments. Compare the
        # complete result line while normalizing only the probability value.
        normalized_guide = self._normalize_probability(self._read_guide())
        for result_line in result_lines:
            self.assertIn(self._normalize_probability(result_line), normalized_guide)

    def test_guide_example_bytes_scanning_p(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            example_bytes_scanning()

        self.assertIn("cackle!", output.getvalue())
        self._assert_example_is_in_guide(example_bytes_scanning)
        self._assert_result_is_in_guide(output.getvalue())

    def test_guide_example_ml_validation_p(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            example_ml_validation()

        self.assertIn("cackle!", output.getvalue())
        self._assert_example_is_in_guide(example_ml_validation)
        self._assert_result_is_in_guide(output.getvalue())
