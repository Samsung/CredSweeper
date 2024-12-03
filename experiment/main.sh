#!/usr/bin/env bash

set -ex

CREDSWEEPER_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." > /dev/null 2>&1 && pwd )"
export PYTHONPATH=${CREDSWEEPER_DIR}:$PYTHONPATH
echo $PYTHONPATH
${CREDSWEEPER_DIR}/.venv/bin/python -m credsweeper --banner

now=$(date +%Y%m%d_%H%M%S)

RESULT_DIR=${CREDSWEEPER_DIR}/experiment/results
mkdir -vp ${RESULT_DIR}

# set env TUNER to use keras-tuner
#TUNER=--tuner
${CREDSWEEPER_DIR}/.venv/bin/python main.py --data ~/w/CredData-master --jobs $(nproc) ${TUNER} | tee ${RESULT_DIR}/${now}.train.log
error_code=${PIPESTATUS}
if [ 0 -ne ${error_code} ]; then exit ${error_code}; fi

cd ${CREDSWEEPER_DIR}
report_file=${RESULT_DIR}/${now}.json
${CREDSWEEPER_DIR}/.venv/bin/python -m credsweeper --sort --path ~/w/CredData-master/data --log info --job $(nproc) --subtext --save-json ${report_file}

cd ~/w/CredData-master/
.venv/bin/python -m benchmark --scanner credsweeper --load ${report_file} | tee ${report_file}.log
