import os
import random
import subprocess
import sys
from argparse import ArgumentParser
from copy import deepcopy
from datetime import datetime
from typing import Tuple, List

import numpy as np
import tensorflow as tf
from tensorflow.python.keras import Model

from experiment.src.data_loader import read_detected_data, read_metadata, join_label, get_missing, eval_no_model, \
    get_y_labels, eval_with_model
from experiment.src.features import prepare_data
from experiment.src.lstm_model import get_model_string_features
from experiment.src.prepare_data import prepare_train_data
from experiment.src.split import load_fixed_split

print(__file__, flush=True)
print("Available devices:", tf.config.list_physical_devices())


def get_predictions_keras(model: Model, data: List[np.ndarray]) -> Tuple[np.ndarray, np.ndarray]:
    """Predict hard labels and probabilities from data using Keras model

    Args:
        model: fitted keras model
        data: List of np.arrays. Number and shape depends on model

    Return:
        Tuple of 2 np arrays. First array is hard (0,1) labels, second array contain probabilities
    """
    probability = model.predict(data).ravel()
    prediction = probability > 0.5

    return prediction, probability


def main(cred_data_location: str) -> str:
    print(f"Train model on data from {cred_data_location}")
    print("Use original ang augmented data for train")

    detected_data = read_detected_data("data/result.json")
    meta_data = read_metadata(f"{cred_data_location}/meta")

    detected_data_copy = deepcopy(detected_data)
    meta_data_copy = deepcopy(meta_data)

    # Combine original and augmented data together
    aug_detected_data = read_detected_data("data/result_aug_data.json", "aug_data/")
    detected_data.update(aug_detected_data)
    aug_metadata = read_metadata(f"{cred_data_location}/aug_data/meta", "aug_data/")
    meta_data.update(aug_metadata)

    df = join_label(detected_data, meta_data)

    train_repo_list, test_repo_list = load_fixed_split()

    df_train = df[df["repo"].isin(train_repo_list)]

    print('-' * 40)
    print(f"Train size: {len(df_train)}")

    df_train = df_train.drop_duplicates(subset=["line", "ext"])
    print(f"Train size after drop_duplicates: {len(df_train)}")

    if not os.path.exists("X_train_value") or not os.path.exists("X_train_features"):
        X_train_value, X_train_features = prepare_data(df_train)
        np.save("X_train_value", X_train_value)
        np.save("X_train_features", X_train_features)
    else:
        X_train_value = np.load("X_train_value")
        X_train_features = np.load("X_train_features")
    y_train = get_y_labels(df_train)

    print(f"Class-1 prop on train: {np.mean(y_train):.2f}")

    keras_model = get_model_string_features(X_train_value.shape[-1], X_train_features.shape[-1])

    fit_history = keras_model.fit(
        [X_train_value, X_train_features],
        y_train,
        batch_size=128,
        epochs=40,
        # Class 1 in train data is roughly ~4 times more abundant than 0. As can be seen from the log
        class_weight={
            0: 1,
            1: 2
        })
    # Epoch 40/42
    # 90/90 [==============================] - 17s 184ms/step - loss: 0.0054 - acc: 0.9990 - precision: 0.9972 - recall: 0.9984
    os.makedirs("results/", exist_ok=True)
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_file_name = f"results/ml_model_at-{current_time}"
    keras_model.save(model_file_name, include_optimizer=False)

    print('-' * 40)
    print("Validate results on the test subset")
    df = join_label(detected_data_copy, meta_data_copy)
    df_missing = get_missing(detected_data_copy, meta_data_copy)
    df_test = df[df["repo"].isin(test_repo_list)]
    df_missing_test = df_missing[df_missing["repo"].isin(test_repo_list)]
    X_test_value, X_test_features = prepare_data(df_test)
    y_test = get_y_labels(df_test)

    print(f"Test size: {len(df_test)}")
    print(f"Class-1 prop on test: {np.mean(y_test):.2f}")

    test_predictions, test_probabilities = get_predictions_keras(keras_model, [X_test_value, X_test_features])

    print("Results on test without model:")
    eval_no_model(df_test, df_missing_test)
    print("Results on test with model:")
    eval_with_model(df_test.copy(), df_missing_test, test_predictions)
    return model_file_name


if __name__ == "__main__":
    pypath = os.getenv("PYTHONPATH")
    if not pypath or 0 != subprocess.call([sys.executable, "-m", "credsweeper", "--banner"]):
        raise RuntimeError(f"Check PYTHONPATH environment: {pypath}")
    parser = ArgumentParser()
    parser.add_argument("--data",
                        nargs="?",
                        help="CredData location",
                        dest="cred_data_location",
                        metavar="PATH",
                        required=True)
    parser.add_argument("-j",
                        "--jobs",
                        help="number of parallel processes to use (default: 4)",
                        default=4,
                        dest="jobs",
                        metavar="POSITIVE_INT")
    args = parser.parse_args()

    fixed_seed = 42  # int(datetime.now().timestamp())
    # print(f"Random seed:{fixed_seed}")
    if fixed_seed is not None:
        tf.random.set_seed(fixed_seed)
        np.random.seed(fixed_seed)
        random.seed(fixed_seed)

    _cred_data_location = args.cred_data_location
    j = int(args.jobs)

    prepare_train_data(_cred_data_location, j)
    _model_file_name = main(_cred_data_location)
    print(f"You can find your model in: {_model_file_name}")
    # python -m tf2onnx.convert --saved-model results/ml_model_at-20240201_073238 --output ../credsweeper/ml_model/ml_model.onnx --verbose
