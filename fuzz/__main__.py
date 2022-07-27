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
#import hashlib
import os
import sys
import atheris

# # # In simple case interested lib(s) may be imported during 'with'
# # # It runs quickly but not precisely
# with atheris.instrument_imports(enable_loader_override=False):
import requests.exceptions

import credsweeper
from oauthlib.oauth2 import InvalidGrantError
from requests import Response
from unittest.mock import patch, MagicMock

cred_sweeper = credsweeper.app.CredSweeper()


def fuzz_credsweeper_scan(data):
    #print(hashlib.sha1(data).hexdigest())
    fdp = atheris.FuzzedDataProvider(data)
    # offset:0x0000
    fuzz_bytes = fdp.ConsumeBytes(1)
    fuzz_byte = fuzz_bytes[0] if 1 == len(fuzz_bytes) else 0

    # offset:0x0001
    to_scan = fdp.ConsumeBytes(1535)
    provider = credsweeper.file_handler.byte_content_provider.ByteContentProvider(to_scan)
    global cred_sweeper
    candidates = cred_sweeper.file_scan(provider)
    api_validation = credsweeper.validations.apply_validation.ApplyValidation()

    with patch("google_auth_oauthlib.flow.InstalledAppFlow.from_client_config") as mock_flow:
        # print(f" BUF {fdp.buffer()} REMAINED BYTES {fdp.remaining_bytes()}")
        flow = MagicMock()
        if 0x10 & fuzz_byte:
            flow.fetch_token.side_effect = InvalidGrantError('fuzz InvalidGrantError')
        elif 0x20 & fuzz_byte:
            flow.fetch_token.side_effect = Exception('fuzz flow Exception')
        else:
            flow.fetch_token.return_value = None
        mock_flow.return_value = flow

        if 0x40 & fuzz_byte:
            # generate ConnectError exception
            with patch("requests.get", side_effect=requests.exceptions.ConnectionError):
                with patch("requests.post", side_effect=requests.exceptions.ConnectionError):
                    for candidate in candidates:
                        api_validation.validate(candidate)
        if 0x80 & fuzz_byte:
            # generate ConnectError exception
            with patch("requests.get", side_effect=Exception('fuzz get Exception')):
                with patch("requests.post", side_effect=Exception('fuzz post Exception')):
                    for candidate in candidates:
                        api_validation.validate(candidate)
        else:
            # print(" requests.good ")
            response = Response()
            # offset:0x0600
            content = fdp.ConsumeBytes(512)
            response._content = content
            status_codes = [0, 200, 400, 401, 403]
            # maximum 16 items due only 4 bits is used from mock_fuzz_byte
            assert len(status_codes) <= 0x10
            response.status_code = status_codes[(0xF & fuzz_byte) % len(status_codes)]
            with patch("requests.get", return_value=response):
                with patch("requests.post", return_value=response):
                    for candidate in candidates:
                        api_validation.validate(candidate)

    cred_sweeper.credential_manager.set_credentials(candidates)
    cred_sweeper.post_processing()


def main():
    # # # Instrument all works with ~20K functions, but it does not lose seeds during reducing
    if not os.getenv('SKIP_ATHERIS_INSTRUMENT'):
        atheris.instrument_all()
    atheris.Setup(  #
        sys.argv + ["-max_len=2048"],  #
        fuzz_credsweeper_scan,  #
        internal_libfuzzer=True,  #
        enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
