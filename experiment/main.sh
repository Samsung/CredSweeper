#!/usr/bin/env bash

set -ex

START_TIME=$(date +%s)
NOW=$(date +%Y%m%d_%H%M%S)
echo ">>> START ${BASH_SOURCE[0]} in $(pwd) at ${NOW}"

free --wide --human

# use the path environments without / at end

echo "CREDSWEEPER_DIR='${CREDSWEEPER_DIR}'"
if [ -z "${CREDSWEEPER_DIR}" ] || [ ! -d "${CREDSWEEPER_DIR}" ]; then
    echo "CREDSWEEPER_DIR environment is empty or does not exist"
    exit 1
fi

export PYTHONPATH="${CREDSWEEPER_DIR}":$PYTHONPATH
# check current version of CredSweeper
"${CREDSWEEPER_DIR}"/.venv/bin/python -m credsweeper --banner
git log -1
git status


echo "CREDDATA_DIR='${CREDDATA_DIR}'"
if [ -z "${CREDDATA_DIR}" ] || [ ! -d "${CREDDATA_DIR}" ]; then
    echo "CREDDATA_DIR environment is empty or does not exist"
    exit 1
fi

# do some check in CredData repo
(cd "${CREDDATA_DIR}" && git log -1 && git status)

echo "JOBS=${JOBS} of $(nproc)"
if [ -z "${JOBS}" ]; then
    JOBS=$(nproc)
    echo "Used JOBS=${JOBS} for multiple process"
elif [ ! 0 -lt ${JOBS} ]; then
    echo "Unappropriated JOBS=${JOBS}"
    exit 1
fi

echo "BATCH=${BATCH}"
if [ -z "${BATCH}" ]; then
    BATCH=256
    echo "Used BATCH=${BATCH}"
elif [ ! 0 -lt ${JOBS} ]; then
    echo "Unappropriated BATCH=${BATCH}"
    exit 1
fi


WORK_DIR="${CREDSWEEPER_DIR}/experiment"
cd "${WORK_DIR}"
RESULT_DIR="${WORK_DIR}/results"
mkdir -vp "${RESULT_DIR}"

# set env TUNER to use keras-tuner
#TUNER=--tuner
# set env DOC to apply doc dataset
#DOC=--doc
"${CREDSWEEPER_DIR}"/.venv/bin/python main.py --data "${CREDDATA_DIR}" --jobs ${JOBS} ${TUNER} ${DOC} --batch_size ${BATCH} | tee "${RESULT_DIR}/${NOW}.train.log"
error_code=${PIPESTATUS}
if [ 0 -ne ${error_code} ]; then exit ${error_code}; fi

cd "${CREDSWEEPER_DIR}"
report_file=${RESULT_DIR}/${NOW}.json
if [ -z "${TESTDATA_DIR}" ]; then
    echo "Used CREDDATA_DIR=${CREDDATA_DIR} for BenchMark and train rules only"
    ${CREDSWEEPER_DIR}/.venv/bin/python -m credsweeper ${DOC} --sort  --rules ${CREDSWEEPER_DIR}/experiment/results/train_config.yaml --path "${CREDDATA_DIR}/data" --log info --jobs ${JOBS}  --subtext --save-json ${report_file} --no-stdout
    cd "${CREDDATA_DIR}"
else
    echo "TESTDATA_DIR=${TESTDATA_DIR}"
    ${CREDSWEEPER_DIR}/.venv/bin/python -m credsweeper ${DOC} --sort --path "${TESTDATA_DIR}/data" --log info --jobs ${JOBS}  --subtext --save-json ${report_file} --no-stdout
    cd "${TESTDATA_DIR}"
fi

.venv/bin/python -m benchmark --scanner credsweeper --load ${report_file} | tee ${CREDSWEEPER_DIR}/.ci/benchmark.txt

SPENT_SECONDS=$(( $(date +%s) - ${START_TIME} ))
if [ 86400 -lt ${SPENT_SECONDS} ];then
    SPENT_TIME=$(date -ud "@${SPENT_SECONDS}" +"$(( ${SPENT_SECONDS} / 86400 ))-%H:%M:%S")
else
    SPENT_TIME=$(date -ud "@${SPENT_SECONDS}" +"%H:%M:%S")
fi
echo "<<< DONE ${BASH_SOURCE[0]} in $(pwd) at $(date) elapsed ${SPENT_TIME}"
