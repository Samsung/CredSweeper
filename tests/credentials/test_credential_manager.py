import pytest

from credsweeper.app import CredSweeper
from credsweeper.file_handler.analysis_target import AnalysisTarget


class TestCredentialManager:

    @pytest.mark.parametrize(
        "line", ["apiKeyToken = 'mybstscrt'", "SecretToken = 'mybstscrt'", "secret = AKIAGIREOGIAWSKEY123"])
    def test_groups_p(self, line):
        cred_sweeper = CredSweeper()
        targets = [AnalysisTarget(line, i + 1, [line], "") for i, line in enumerate([line])]
        detections = cred_sweeper.scanner.scan(targets)
        cred_sweeper.credential_manager.set_credentials(detections)
        groups = cred_sweeper.credential_manager.group_credentials()
        # Assert that credentials can be grouped
        assert len(groups) == 1

    @pytest.mark.parametrize("line", [
        "func(secret='acbd22', token='longscrttok')", "single_token='acbd22'",
        "{secret: 'acbd22', token: 'longscrttok'}"
    ])
    def test_groups_n(self, line):
        cred_sweeper = CredSweeper()
        targets = [AnalysisTarget(line, i + 1, [line], "") for i, line in enumerate([line])]
        detections = cred_sweeper.scanner.scan(targets)
        cred_sweeper.credential_manager.set_credentials(detections)
        groups = cred_sweeper.credential_manager.group_credentials()
        # Assert that no credentials can be grouped in tested cases
        assert len(groups) == len(detections)
