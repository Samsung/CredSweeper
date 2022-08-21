#!/bin/bash -eu
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
#
################################################################################

set -e
set -x

pwd
ls -al
echo "SRC:$SRC"
echo "OUT:$OUT"

python3 -m pip install --upgrade pip
python3 -m pip install --requirement requirements.txt
python3 -m pip install atheris
export DO_ATHERIS_INSTRUMENT=1
pyinstaller --distpath ${OUT} --onefile --name fuzz_credsweeper fuzz_credsweeper.py
ls -al $OUT
chmod 0777 $OUT/fuzz_credsweeper
ls -al $OUT
env
nm fuzz_credsweeper
