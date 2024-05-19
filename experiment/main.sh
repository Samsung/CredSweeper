#!/usr/bin/env bash

set -e

CREDSWEEPER_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." > /dev/null 2>&1 && pwd )"
export PYTHONPATH=${CREDSWEEPER_DIR}:$PYTHONPATH
echo $PYTHONPATH
${CREDSWEEPER_DIR}/.venv/bin/python -m credsweeper --banner

rm -rf data

${CREDSWEEPER_DIR}/.venv/bin/python main.py --data ~/w/CredData --jobs 32 | tee train.log


#last_tf_model=$(cat train.log | tail -n1)

#echo $last_tf_model

#pwd

#python -m tf2onnx.convert --saved-model results/$last_tf_model --output ../credsweeper/ml_model/ml_model.onnx --verbose

