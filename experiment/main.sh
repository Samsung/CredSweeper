#!/usr/bin/env bash

set -ex

CREDSWEEPER_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." > /dev/null 2>&1 && pwd )"
export PYTHONPATH=${CREDSWEEPER_DIR}:$PYTHONPATH
echo $PYTHONPATH
${CREDSWEEPER_DIR}/.venv/bin/python -m credsweeper --banner

now=$(date +%Y%m%d_%H%M%S)

RESULT_DIR=${CREDSWEEPER_DIR}/experiment/results
mkdir -vp ${RESULT_DIR}

${CREDSWEEPER_DIR}/.venv/bin/python main.py --data ~/w/CredData --jobs 32 | tee ${RESULT_DIR}/train.${now}.log

cd ${CREDSWEEPER_DIR}
report_file=${RESULT_DIR}/${now}.json
${CREDSWEEPER_DIR}/.venv/bin/python -m credsweeper --sort --path ~/q/DataCred/auxiliary/data/ --log error --job 32 --save-json ${report_file}

cd ~/q/DataCred/auxiliary/
.venv/bin/python -m benchmark --scanner credsweeper --load ${report_file} | tee ${report_file}.log

#last_tf_model=$(cat train.log | tail -n1)

#echo $last_tf_model

#pwd

#python -m tf2onnx.convert --saved-model results/$last_tf_model --output ../credsweeper/ml_model/ml_model.onnx --verbose

