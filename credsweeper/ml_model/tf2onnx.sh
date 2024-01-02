python -c 'import tensorflow as tf;model=tf.keras.models.load_model("ml_model.h5");model.save("ml_model")'
python -m tf2onnx.convert --saved-model ml_model --output ml_model.onnx --verbose --rename-inputs feature_input,line_input
md5sum ml_model.onnx >ml_model.onnx.md5
