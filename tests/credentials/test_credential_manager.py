import pytest

from credsweeper.app import CredSweeper
from credsweeper.file_handler.string_content_provider import StringContentProvider


class TestCredentialManager:

    @pytest.mark.parametrize(
        "line",
        [
            "apiKey = 'mybstscrt'",  #
            "SecretNonce = 'mybstscrt'",  #
            '"auth-credential-token": "AKIAGIREOGIAWSKEY123",',  #
            "PASSWORD_SALT = {123, 53, 77, 9, 4, 2, 58, 9, 3, 234, 5, 6, 7, 0};",  #
        ])
    def test_groups_p(self, line):
        cred_sweeper = CredSweeper()
        provider = StringContentProvider([line])
        detections = cred_sweeper.scanner.scan(provider)
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
        provider = StringContentProvider([line])
        detections = cred_sweeper.scanner.scan(provider)
        cred_sweeper.credential_manager.set_credentials(detections)
        groups = cred_sweeper.credential_manager.group_credentials()
        # Assert that no credentials can be grouped in tested cases
        assert len(groups) == len(detections)
