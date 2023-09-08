import unittest

import deepdiff  # type: ignore

from credsweeper.app import CredSweeper
from credsweeper.common.constants import Severity
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.text_provider import TextProvider
from tests import SAMPLES_PATH


class TestDoc(unittest.TestCase):
    def setUp(self) -> None:
        self.cred_sweeper = CredSweeper(doc=True, severity=Severity.CRITICAL, ml_threshold=0)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_id_passwd_pair_p(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "doc_id_passwd_pair"])
        self.cred_sweeper.run(content_provider=content_provider)
        found_credentials = self.cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(25, len(found_credentials), found_credentials)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_ip_pw_p(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "doc_id_pw"])
        self.cred_sweeper.run(content_provider=content_provider)
        found_credentials = self.cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(27, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_ip_id_passwd_triple_p(self) -> None:
        content_provider: FilesProvider = TextProvider([SAMPLES_PATH / "doc_ip_id_password_triple"])
        self.cred_sweeper.run(content_provider=content_provider)
        found_credentials = self.cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(8, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
