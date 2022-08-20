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

RUN if [ -z "$SRC" ] ;then echo "BAD SRC"; exit 1; fi

WORKDIR $SRC

RUN python3 --version
RUN if [ -z "$SRC" ] ;then echo "BAD SRC"; exit 1; fi
RUN if [ -z "$OUT" ] ;then echo "BAD OUT"; exit 1; fi

# ADD fuzz/requirements.txt  $SRC/fuzz_requirements.txt
ADD fuzz/__main__.py  $SRC/fuzz_credsweeper.py
ADD credsweeper $SRC/credsweeper
ADD requirements.txt $SRC/
RUN ls -al $SRC/
RUN find $SRC/

COPY .clusterfuzzlite/build.sh $SRC/
COPY .clusterfuzzlite/fuzz_credsweeper $SRC/
RUN ls -al $OUT/
RUN find $OUT/

#RUN python3 -m pip install --upgrade pip && python3 -m pip install -r $SRC/requirements.txt
# RUN python3 -m pip install -r $SRC/fuzz/requirements.txt

#RUN pyinstaller --distpath $OUT --onefile --name fuzz_credsweeper.pkg fuzz_credsweeper.py
#RUN ls -al $OUT/