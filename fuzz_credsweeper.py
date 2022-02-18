#!/usr/bin/python3

# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import sys

import atheris
from regex import regex

from credsweeper.credentials import LineData
from tests.conftest import file_path

from tests.filters.conftest import success_line

from credsweeper.rules import Rule
from tests.test_utils.dummy_line_data import get_line_data, config

from credsweeper.filters import ValueSimilarityCheck

with atheris.instrument_imports(enable_loader_override=False):
    import credsweeper


def fuzz_credsweeper_value_similarity_check(data):
    fdp = atheris.FuzzedDataProvider(data)
    line_num = 0
    pattern = regex.compile('^.*$')
    line_data = LineData(config, fdp.ConsumeString(fdp.ConsumeIntInRange(0, 32)), line_num, '', pattern)
    line_data.key=fdp.ConsumeString(3)
    line_data.value = fdp.ConsumeString(3)
    ValueSimilarityCheck().run(line_data)


# @mock.patch("json.load", MagicMock(config_json))

def fuzz_credsweeper_scan(data):
    fdp = atheris.FuzzedDataProvider(data)
    to_scan = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1000))

    cred_sweeper = credsweeper.app.CredSweeper()
    provider = credsweeper.file_handler.byte_content_provider.ByteContentProvider(to_scan)
    cred_sweeper.file_scan(provider)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_credsweeper_value_similarity_check, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
