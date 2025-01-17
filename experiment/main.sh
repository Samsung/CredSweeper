#!/usr/bin/env bash

set -ex

START_TIME=$(date +%s)
NOW=$(date +%Y%m%d_%H%M%S)
echo ">>> START ${BASH_SOURCE[0]} in $(pwd) at ${NOW}"

# use the path environments without / at end

echo "CREDSWEEPER_DIR='${CREDSWEEPER_DIR}'"
if [ -z "${CREDSWEEPER_DIR}" ] || [ ! -d "${CREDSWEEPER_DIR}" ]; then
    echo "CREDSWEEPER_DIR environment is empty or does not exist"
    exit 1
fi

echo "CREDDATA_DIR='${CREDDATA_DIR}'"
if [ -z "${CREDDATA_DIR}" ] || [ ! -d "${CREDDATA_DIR}" ]; then
    echo "CREDDATA_DIR environment is empty or does not exist"
    exit 1
fi

echo "JOBS=$(nproc)"
if [ -z "${JOBS}" ]; then
    JOBS=$(nproc)
    echo "Used JOBS=${JOBS} for multiple process"
elif [ ! 0 -lt ${JOBS} ]; then
    echo "Unappropriated JOBS=${JOBS}"
    exit 1
fi

export PYTHONPATH="${CREDSWEEPER_DIR}":$PYTHONPATH

# check whether current version
"${CREDSWEEPER_DIR}"/.venv/bin/python -m credsweeper --banner

WORK_DIR="${CREDSWEEPER_DIR}/experiment"
cd "${WORK_DIR}"
RESULT_DIR="${WORK_DIR}/results"
mkdir -vp "${RESULT_DIR}"

# set env TUNER to use keras-tuner
#TUNER=--tuner
# set env DOC to apply doc dataset
#DOC=--doc
"${CREDSWEEPER_DIR}"/.venv/bin/python main.py --data "${CREDDATA_DIR}" --jobs ${JOBS} ${TUNER} ${DOC} | tee "${RESULT_DIR}/${NOW}.train.log"
error_code=${PIPESTATUS}
if [ 0 -ne ${error_code} ]; then exit ${error_code}; fi

cd "${CREDSWEEPER_DIR}"
report_file=${RESULT_DIR}/${NOW}.json
${CREDSWEEPER_DIR}/.venv/bin/python -m credsweeper ${DOC} --sort --path "${CREDDATA_DIR}/data" --log info --jobs ${JOBS}  --subtext --save-json ${report_file}

cd "${CREDDATA_DIR}"
.venv/bin/python -m benchmark --scanner credsweeper --load ${report_file} | tee ${CREDSWEEPER_DIR}/.ci/benchmark.txt

SPENT_TIME=$(date -ud "@$(( $(date +%s) - ${START_TIME} ))" +"%H:%M:%S")
echo "<<< DONE ${BASH_SOURCE[0]} in $(pwd) at $(date) elapsed ${SPENT_TIME}"
