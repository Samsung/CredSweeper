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
import warnings
from unittest.mock import patch

import atheris
# # # In simple case interested lib(s) may be imported during 'with'
# # # It runs quickly but not precisely
# with atheris.instrument_imports(enable_loader_override=False):
from bs4 import XMLParsedAsHTMLWarning

from credsweeper.app import CredSweeper
from credsweeper.common.constants import DiffRowType
from credsweeper.file_handler.files_provider import FilesProvider
from credsweeper.file_handler.patches_provider import PatchesProvider
from tests import NEGLIGIBLE_ML_THRESHOLD

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# set log level for fuzzing
logging.basicConfig(level=logging.CRITICAL)
logger = logging.getLogger(__name__)

# Use depth=3 to deep scan in .zip and .gz files + find by extension feature
cred_sweeper = CredSweeper(find_by_ext=True, ml_threshold=NEGLIGIBLE_ML_THRESHOLD)

INPUT_DATA_SIZE = 0x1000


def fuzz_credsweeper_scan(data: bytes):
    # seed file name is sha1 of the content
    file_name = hashlib.sha1(data).hexdigest()
    fdp = atheris.FuzzedDataProvider(data)
    # offset:0x0000
    to_scan = fdp.ConsumeBytes(INPUT_DATA_SIZE)
    logger.debug("%s >>>>>>>> %s", file_name, to_scan.decode(encoding='ascii', errors="ignore"))

    _io = io.BytesIO(to_scan)

    candidates = []

    cred_sweeper.config.doc = False
    cred_sweeper.config.depth = 3
    cred_sweeper.credential_manager.candidates.clear()
    patch_provider_add = PatchesProvider([_io], change_type=DiffRowType.ADDED)
    with patch.object(CredSweeper, CredSweeper.export_results.__name__):
        cred_sweeper.run(patch_provider_add)
    candidates.extend(cred_sweeper.credential_manager.get_credentials())

    _io.seek(0, io.SEEK_SET)

    cred_sweeper.config.doc = False
    cred_sweeper.config.depth = 0
    cred_sweeper.credential_manager.candidates.clear()
    patch_provider_del = PatchesProvider([_io], change_type=DiffRowType.DELETED)
    with patch.object(CredSweeper, CredSweeper.export_results.__name__):
        cred_sweeper.run(patch_provider_del)
    candidates.extend(cred_sweeper.credential_manager.get_credentials())

    _io.seek(0, io.SEEK_SET)

    cred_sweeper.config.doc = True
    cred_sweeper.config.depth = 0
    cred_sweeper.credential_manager.candidates.clear()
    text_provider = FilesProvider(["dummy.template", _io])
    with patch.object(CredSweeper, CredSweeper.export_results.__name__):
        cred_sweeper.run(text_provider)
    candidates.extend(cred_sweeper.credential_manager.get_credentials())

    _io.seek(0, io.SEEK_SET)

    cred_sweeper.config.doc = False
    cred_sweeper.config.depth = 3
    cred_sweeper.credential_manager.candidates.clear()
    text_provider = FilesProvider(["dummy.template", _io])
    with patch.object(CredSweeper, CredSweeper.export_results.__name__):
        cred_sweeper.run(text_provider)
    candidates.extend(cred_sweeper.credential_manager.get_credentials())

    for candidate in candidates:
        candidate.to_dict_list(False, False)


def main():
    # # # Instrument all works with ~30K functions. It is slow, but necessary for fuzzing for new seeds and reducing.
    # # # Instrumentation may being skipped when checking coverage with existing seeds or seeds minimization.
    if os.getenv('DO_ATHERIS_INSTRUMENT'):
        atheris.instrument_all()
    atheris.Setup(  #
        sys.argv + [f"-max_len={INPUT_DATA_SIZE}"],  # -rss_limit_mb=6912
        fuzz_credsweeper_scan,  #
        internal_libfuzzer=True,  #
        enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
