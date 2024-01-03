#!/usr/bin/env bash

set -e

# tensorflow model may be obtained like this: git restore -s be06d6059f0def4f0fdb50444c08db4ce542173e -- ml_model.h5
# use virtual environment and the requirements.txt - there are very specific luke combination of packages verions
# python -m venv .venv
# . .venv/bin/activate
# python -m pip install --upgrade pip
# python -m pip install --requirement requirements.txt

# [optional] thransform model form h5 to saved directory
python -c 'import tensorflow as tf;model=tf.keras.models.load_model("ml_model.h5");model.save("ml_model")'
# transform the model
python -m tf2onnx.convert --saved-model ml_model --output ml_model.onnx --verbose --rename-inputs feature_input,line_input
# md5sum for integrity
md5sum --binary ml_model.onnx
