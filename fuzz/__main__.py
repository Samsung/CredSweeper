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
import io
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

from credsweeper.app import CredSweeper
from credsweeper.common.constants import DiffRowType
from credsweeper.file_handler.patches_provider import PatchesProvider
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.validations import GithubTokenValidation, GoogleApiKeyValidation, MailChimpKeyValidation, \
    StripeApiKeyValidation, SquareClientIdValidation, SlackTokenValidation, SquareAccessTokenValidation, \
    GoogleMultiValidation
from credsweeper.validations.apply_validation import ApplyValidation

# set log level for fuzzing
logging.basicConfig(level=logging.CRITICAL)
logger = logging.getLogger(__name__)

# Use depth=3 to deep scan in .zip and .gz files + find by extension feature
cred_sweeper = CredSweeper(depth=3, find_by_ext=True, ml_threshold=0.0001)
api_validation = ApplyValidation()

MOCK_RESPONSE_SIZE = 0x0100  # 256 bytes enough for mocking response
INPUT_DATA_SIZE = 0x1000 - MOCK_RESPONSE_SIZE  # 4096 - 256 = 3840


def mock_request(status_code: int, content: bytes, candidate, patch_object, path_name):
    response = Response()
    response._content = content
    response.status_code = status_code
    logger.debug("<<<<<<<< %d '%s'", response.status_code, content.decode(encoding='ascii', errors='ignore'))
    with patch.object(patch_object, path_name, return_value=response):
        api_validation.validate(candidate)


def mock_request_side_effect(side_effect, candidate, patch_object, path_name):
    # generate common exception
    logger.debug("<<<<<<<< Side_effect %s for %s", str(side_effect), path_name)
    with patch.object(patch_object, path_name, side_effect=side_effect):
        api_validation.validate(candidate)


def mock_flow(behaviour_code: int, candidate):
    if 0 == behaviour_code:
        # generate common exception
        logger.debug(f"<<<<<<<< Exception('fuzz flow Exception')")
        with patch.object(InstalledAppFlow, InstalledAppFlow.from_client_config.__name__) as mock:
            flow = MagicMock()
            flow.fetch_token.side_effect = Exception('fuzz flow Exception')
            mock.return_value = flow
            api_validation.validate(candidate)
    elif 1 == behaviour_code:
        logger.debug(f"<<<<<<<< InvalidGrantError('fuzz InvalidGrantError')")
        with patch.object(InstalledAppFlow, InstalledAppFlow.from_client_config.__name__) as mock:
            flow = MagicMock()
            flow.fetch_token.side_effect = InvalidGrantError('fuzz InvalidGrantError')
            mock.return_value = flow
            api_validation.validate(candidate)
    else:
        logger.debug(f"<<<<<<<< flow.fetch_token.return_value = None")
        with patch.object(InstalledAppFlow, InstalledAppFlow.from_client_config.__name__) as mock:
            flow = MagicMock()
            flow.fetch_token.return_value = None
            mock.return_value = flow
            api_validation.validate(candidate)


def fuzz_credsweeper_scan(data: bytes):
    # seed file name is sha1 of the content
    file_name = hashlib.sha1(data).hexdigest()
    fdp = atheris.FuzzedDataProvider(data)
    # offset:0x0000
    to_scan = fdp.ConsumeBytes(INPUT_DATA_SIZE)
    logger.debug("%s >>>>>>>> %s", file_name, to_scan.decode(encoding='ascii', errors="ignore"))

    _io = io.BytesIO(to_scan)

    candidates = []

    cred_sweeper.credential_manager.candidates.clear()
    patch_provider_add = PatchesProvider([_io], change_type=DiffRowType.ADDED)
    with patch.object(CredSweeper, CredSweeper.export_results.__name__):
        cred_sweeper.run(patch_provider_add)
    candidates.extend(cred_sweeper.credential_manager.get_credentials())

    _io.seek(0, io.SEEK_SET)

    cred_sweeper.credential_manager.candidates.clear()
    patch_provider_del = PatchesProvider([_io], change_type=DiffRowType.DELETED)
    with patch.object(CredSweeper, CredSweeper.export_results.__name__):
        cred_sweeper.run(patch_provider_del)
    candidates.extend(cred_sweeper.credential_manager.get_credentials())

    _io.seek(0, io.SEEK_SET)

    cred_sweeper.credential_manager.candidates.clear()
    text_provider = FilesProvider(["dummy.template", _io])
    with patch.object(CredSweeper, CredSweeper.export_results.__name__):
        cred_sweeper.run(text_provider)
    candidates.extend(cred_sweeper.credential_manager.get_credentials())

    # API validation
    content = b''
    # obtain data for mocking validation if a seed is not exhausted
    if INPUT_DATA_SIZE < len(data):
        # offset:0x0800
        content = fdp.ConsumeBytes(MOCK_RESPONSE_SIZE)
    # validate candidates with default exception
    for candidate in candidates:
        for validation in candidate.validations:
            # mocking GET
            if validation.__class__.__name__ in [  #
                    GithubTokenValidation.__name__,  #
                    GoogleApiKeyValidation.__name__,  #
                    MailChimpKeyValidation.__name__,  #
                    SquareClientIdValidation.__name__,  #
                    StripeApiKeyValidation.__name__,  #
            ]:
                for side_effect in [Exception(f"common exception"), requests.exceptions.ConnectionError]:
                    mock_request_side_effect(side_effect, candidate, requests, requests.get.__name__)
                for status_code in [0, 200, 400, 401, 403, 500, 999]:
                    mock_request(status_code, content, candidate, requests, requests.get.__name__)
            # mocking POST
            elif validation.__class__.__name__ in [  #
                    SquareAccessTokenValidation.__name__,  #
                    SlackTokenValidation.__name__,  #
            ]:
                for side_effect in [Exception(f"common exception"), requests.exceptions.ConnectionError]:
                    mock_request_side_effect(side_effect, candidate, requests, requests.post.__name__)
                for status_code in [0, 200, 400, 401, 403, 500, 999]:
                    mock_request(status_code, content, candidate, requests, requests.post.__name__)
            elif validation.__class__.__name__ in [GoogleMultiValidation.__name__]:
                for i in range(3):
                    mock_flow(i, candidate)
        candidate.to_dict_list()


def main():
    # # # Instrument all works with ~30K functions. It is slow, but necessary for fuzzing for new seeds and reducing.
    # # # Instrumentation may being skipped when checking coverage with existing seeds or seeds minimization.
    if os.getenv('DO_ATHERIS_INSTRUMENT'):
        atheris.instrument_all()
    atheris.Setup(  #
        sys.argv + ["-max_len=4096"],  # -rss_limit_mb=6912
        fuzz_credsweeper_scan,  #
        internal_libfuzzer=True,  #
        enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
