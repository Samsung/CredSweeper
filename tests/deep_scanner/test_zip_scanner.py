import io
import unittest
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile

from credsweeper.app import CredSweeper
from credsweeper.deep_scanner.zip_scanner import ZipScanner
from credsweeper.file_handler.data_content_provider import DataContentProvider
from tests import AZ_DATA


class TestZipScanner(unittest.TestCase):

    def test_match_p(self):
        self.assertTrue(ZipScanner.match(b'PK\003\004'))
        # empty archive - no files
        self.assertTrue(ZipScanner.match(b'PK\x05\x06\x00\x00'))
        # not supported spanned archive (multi volume)
        self.assertFalse(ZipScanner.match(b'PK\x07\x08'))

    def test_match_n(self):
        # wrong data type
        with self.assertRaises(AttributeError):
            self.assertFalse(ZipScanner.match(None))
        with self.assertRaises(AttributeError):
            self.assertFalse(ZipScanner.match(1))
        # few bytes than required
        self.assertFalse(ZipScanner.match(b''))
        self.assertFalse(ZipScanner.match(b'P'))
        self.assertFalse(ZipScanner.match(b'PK'))
        self.assertFalse(ZipScanner.match(b'PK\003'))
        # wrong signature
        self.assertFalse(ZipScanner.match(b'PK\003\003'))
        # plain text data
        self.assertFalse(ZipScanner.match(AZ_DATA))

    def test_corrupt_member_does_not_hide_intact_credentials(self) -> None:
        # A bad CRC must not suppress credentials in earlier or later valid members.
        bad_data = b"Synthetic broken member; no credential present"
        secret = b'password = "cackle!"\n'
        for bad_first in (True, False):
            with self.subTest(bad_first=bad_first):
                data = io.BytesIO()
                with ZipFile(data, "w") as archive:
                    if bad_first:
                        archive.writestr("bad.txt", bad_data, compress_type=ZIP_STORED)
                    archive.writestr("password.gradle", secret, compress_type=ZIP_DEFLATED)
                    if not bad_first:
                        archive.writestr("bad.txt", bad_data, compress_type=ZIP_STORED)

                healthy = data.getvalue()
                broken = healthy.replace(bad_data, b"X" + bad_data[1:], 1)

                with ZipFile(io.BytesIO(broken)) as archive:
                    with self.assertRaises(BadZipFile):
                        archive.read("bad.txt")
                    self.assertEqual(secret, archive.read("password.gradle"))

                app = CredSweeper(depth=4, use_filters=False, ml_threshold=0)
                healthy_provider = DataContentProvider(data=healthy, file_path="synthetic.zip", file_type=".zip")
                healthy_candidates = app.deep_scanner.recursive_scan(healthy_provider,
                                                                     depth=4,
                                                                     recursive_limit_size=65536)
                self.assertTrue(
                    any('password = "cackle!"' in line.line for candidate in healthy_candidates
                        for line in candidate.line_data_list), "Healthy ZIP control did not detect the credential")

                provider = DataContentProvider(data=broken, file_path="synthetic.zip", file_type=".zip")
                candidates = app.deep_scanner.recursive_scan(provider, depth=4, recursive_limit_size=65536)
                found = any('password = "cackle!"' in line.line for candidate in candidates
                            for line in candidate.line_data_list)
                self.assertTrue(found, f"Valid member hidden when bad_first={bad_first}")
