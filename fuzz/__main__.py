#!/usr/bin/env python

# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import hashlib
import logging
import os
import sys
from unittest.mock import patch, MagicMock

import atheris
# # # In simple case interested lib(s) may be imported during 'with'
# # # It runs quickly but not precisely
# with atheris.instrument_imports(enable_loader_override=False):
import requests
from google_auth_oauthlib.flow import InstalledAppFlow
from oauthlib.oauth2 import InvalidGrantError
from requests import Response

from credsweeper import CredSweeper, DataContentProvider, ApplyValidation
from credsweeper.common.constants import DiffRowType
from credsweeper.file_handler.patch_provider import PatchProvider
from credsweeper.utils import Util
from credsweeper.validations import GithubTokenValidation, GoogleApiKeyValidation, MailChimpKeyValidation, \
    StripeApiKeyValidation, SquareClientIdValidation, SlackTokenValidation, SquareAccessTokenValidation, \
    GoogleMultiValidation

# set log level for fuzzing
logging.basicConfig(level=logging.CRITICAL)
logger = logging.getLogger(__name__)

# Use depth=3 to deep scan in .zip and .gz files + find by extension feature
cred_sweeper = CredSweeper(depth=3, find_by_ext=True)
api_validation = ApplyValidation()

INPUT_DATA_SIZE = 0x0600
BEHAVIOUR_BYTE_SIZE = 0x01
MOCK_RESPONSE_SIZE = 0x01FF


def mock_request(behaviour_code: int, status_code_seed: int, content: bytes, candidate, patch_object, path_name):
    if 0 == behaviour_code:
        response = Response()
        response._content = content
        status_codes = [200, 300, 400, 401, 403, 500, 0, 999]
        # maximum 16 items due only 4 bits is used from mock_fuzz_byte
        assert len(status_codes) <= 0x10
        response.status_code = status_codes[status_code_seed % len(status_codes)]
        logger.debug("<<<<<<<< %d '%s'", response.status_code, content.decode(encoding='ascii', errors='ignore'))
        with patch.object(patch_object, path_name, return_value=response):
            api_validation.validate(candidate)
    if 1 == behaviour_code:
        # generate common exception
        logger.debug("<<<<<<<< Side_effect=Exception('fuzz %s Exception')", path_name)
        with patch.object(patch_object, path_name, side_effect=Exception(f"fuzz {path_name} Exception")):
            api_validation.validate(candidate)
    else:
        # generate ConnectError exception
        logger.debug("<<<<<<<< %s side_effect=requests.exceptions.ConnectionError", path_name)
        with patch.object(patch_object, path_name, side_effect=requests.exceptions.ConnectionError):
            api_validation.validate(candidate)


def mock_flow(behaviour_code: int, candidate):
    if 0 == behaviour_code:
        logger.debug(f"<<<<<<<< flow.fetch_token.return_value = None")
        with patch.object(InstalledAppFlow, InstalledAppFlow.from_client_config.__name__) as mock:
            flow = MagicMock()
            flow.fetch_token.return_value = None
            mock.return_value = flow
            api_validation.validate(candidate)
    if 1 == behaviour_code:
        logger.debug(f"<<<<<<<< InvalidGrantError('fuzz InvalidGrantError')")
        with patch.object(InstalledAppFlow, InstalledAppFlow.from_client_config.__name__) as mock:
            flow = MagicMock()
            flow.fetch_token.side_effect = InvalidGrantError('fuzz InvalidGrantError')
            mock.return_value = flow
            api_validation.validate(candidate)
    else:
        logger.debug(f"<<<<<<<< Exception('fuzz flow Exception')")
        with patch.object(InstalledAppFlow, InstalledAppFlow.from_client_config.__name__) as mock:
            flow = MagicMock()
            flow.fetch_token.side_effect = Exception('fuzz flow Exception')
            mock.return_value = flow
            api_validation.validate(candidate)


def fuzz_credsweeper_scan(data):
    # seed file name is sha1 of the content
    file_name = hashlib.sha1(data).hexdigest()
    fdp = atheris.FuzzedDataProvider(data)
    # offset:0x0000
    to_scan = fdp.ConsumeBytes(INPUT_DATA_SIZE)
    logger.debug("%s >>>>>>>> %s", file_name, to_scan.decode(encoding='ascii', errors="ignore"))

    cred_sweeper.credential_manager.candidates.clear()
    content_provider = PatchProvider([file_name], change_type=DiffRowType.ADDED)
    with patch.object(Util, Util.read_file.__name__) as mock_read:
        mock_read.return_value = Util.decode_bytes(to_scan)
        with patch.object(CredSweeper, CredSweeper.export_results.__name__):
            cred_sweeper.run(content_provider)

    cred_sweeper.credential_manager.candidates.clear()
    content_provider = PatchProvider([file_name], change_type=DiffRowType.DELETED)
    with patch.object(Util, Util.read_file.__name__) as mock_read:
        mock_read.return_value = Util.decode_bytes(to_scan)
        with patch.object(CredSweeper, CredSweeper.export_results.__name__):
            cred_sweeper.run(content_provider)

    cred_sweeper.credential_manager.candidates.clear()
    provider = DataContentProvider(to_scan, file_name)
    candidates = cred_sweeper.data_scan(provider, 1, INPUT_DATA_SIZE)

    # API validation
    if INPUT_DATA_SIZE < len(data):
        # offset:0x0600
        fuzz_bytes = fdp.ConsumeBytes(1)
        behaviour_code = 0xF & fuzz_bytes[0]
        assert 0 <= behaviour_code <= 15
        status_code_seed = fuzz_bytes[0] >> 4
        assert 0 <= status_code_seed <= 15
        # offset:0x0601
        content: bytes = fdp.ConsumeBytes(MOCK_RESPONSE_SIZE) if 0 == behaviour_code else b''
        for candidate in candidates:
            for validation in candidate.validations:
                if validation.__class__.__name__ in [  #
                    GithubTokenValidation.__name__,  #
                    GoogleApiKeyValidation.__name__,  #
                    MailChimpKeyValidation.__name__,  #
                    SquareClientIdValidation.__name__,  #
                    StripeApiKeyValidation.__name__]:
                    mock_request(behaviour_code, status_code_seed, content, candidate, requests, requests.get.__name__)
                elif validation.__class__.__name__ in [  #
                    SquareAccessTokenValidation.__name__,  #
                    SlackTokenValidation.__name__]:
                    mock_request(behaviour_code, status_code_seed, content, candidate, requests, requests.post.__name__)
                elif validation.__class__.__name__ in [GoogleMultiValidation.__name__]:
                    mock_flow(behaviour_code, candidate)

    cred_sweeper.credential_manager.set_credentials(candidates)
    cred_sweeper.post_processing()


def main():
    # # # Instrument all works with ~26K functions, but it does not lose seeds during reducing
    if os.getenv('DO_ATHERIS_INSTRUMENT'):
        atheris.instrument_all()
    atheris.Setup(  #
        sys.argv + ["-max_len=2048"],  #
        fuzz_credsweeper_scan,  #
        internal_libfuzzer=True,  #
        enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
