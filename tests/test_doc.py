import unittest

import deepdiff  # type: ignore

from credsweeper.app import CredSweeper
from credsweeper.file_handler.abstract_provider import AbstractProvider
from credsweeper.file_handler.files_provider import FilesProvider
from tests import SAMPLES_PATH


class TestDoc(unittest.TestCase):

    def setUp(self) -> None:
        self.cred_sweeper = CredSweeper(doc=True, ml_threshold=0)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_secret_pair_p(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "doc_secret_pair"])
        self.cred_sweeper.run(content_provider=content_provider)
        found_credentials = self.cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(39, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_passwd_pair_p(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "doc_passwd_pair"])
        self.cred_sweeper.run(content_provider=content_provider)
        found_credentials = self.cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(73, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_ip_id_passwd_triple_p(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "doc_ip_id_password_triple"])
        self.cred_sweeper.run(content_provider=content_provider)
        found_credentials = self.cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(5, len(found_credentials))

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_id_pair_passwd_pair_p(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "doc_id_pair_passwd_pair"])
        self.cred_sweeper.run(content_provider=content_provider)
        found_credentials = self.cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(246, len(found_credentials), found_credentials)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

    def test_id_passwd_pair_p(self) -> None:
        content_provider: AbstractProvider = FilesProvider([SAMPLES_PATH / "doc_id_passwd_pair"])
        self.cred_sweeper.run(content_provider=content_provider)
        found_credentials = self.cred_sweeper.credential_manager.get_credentials()
        self.assertEqual(44, len(found_credentials), found_credentials)

    # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
