#!/usr/bin/env bash

set -e

CREDSWEEPER_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." > /dev/null 2>&1 && pwd )"
export PYTHONPATH=${CREDSWEEPER_DIR}:$PYTHONPATH
echo $PYTHONPATH
python -m credsweeper --banner

rm -rf data

python main.py --data ~/q/DataCred/CredData -j 32


last_tf_model=$(ls -t1 results | head -n1)

echo $last_tf_model

python -m tf2onnx.convert --saved-model results/$last_tf_model --output ../credsweeper/ml_model/ml_model.onnx --verbose

