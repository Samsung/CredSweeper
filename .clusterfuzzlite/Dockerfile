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

FROM gcr.io/oss-fuzz-base/base-builder-python

RUN if [ -z "$SRC" ] ; echo "BAD SRC"; exit 1; fi

WORKDIR $SRC

RUN if [ -z "$SRC" ] ; echo "BAD SRC"; exit 1; fi
RUN if [ -z "$OUT" ] ; echo "BAD OUT"; exit 1; fi

COPY fuzz $SRC/
COPY credsweeper $SRC/
ADD requirements.txt $SRC/
ADD .clusterfuzzlite/fuzz_credsweeper $OUT/

RUN ls -al $SRC/
RUN find $SRC/

RUN python3 -m pip install -r $SRC/requirements.txt
# RUN python3 -m pip install -r $SRC/fuzz/requirements.txt
RUN cp -v fuzz/__main__.py $SRC/fuzz_credsweeper.py
ENV DO_ATHERIS_INSTRUMENT=1
RUN pyinstaller --distpath $OUT --onefile --name fuzz_credsweeper.pkg fuzz_credsweeper.py
RUN ls -al $OUT/