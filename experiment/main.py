import os
import pathlib
import pickle
import random
from argparse import ArgumentParser
from copy import deepcopy
from datetime import datetime
from typing import Tuple, List

import numpy as np
import tensorflow as tf
from sklearn.utils import compute_class_weight
from tensorflow.python.keras import Model

from experiment.plot import save_plot
from experiment.src.data_loader import read_detected_data, read_metadata, join_label, get_missing, eval_no_model, \
    get_y_labels, eval_with_model
from experiment.src.features import prepare_data
from experiment.src.lstm_model import get_model_string_features
from experiment.src.prepare_data import prepare_train_data
from experiment.src.split import load_fixed_split


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


def main(cred_data_location: str, jobs: int) -> str:
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    prepare_train_data(_cred_data_location, jobs)

    print(f"Train model on data from {cred_data_location}")
    print("Use original ang augmented data for train")

    detected_data = read_detected_data("data/result.json")
    meta_data = read_metadata(f"{cred_data_location}/meta")

    detected_data_copy = deepcopy(detected_data)
    meta_data_copy = deepcopy(meta_data)

    # Combine original and augmented data together
    # aug_detected_data = read_detected_data("data/result_aug_data.json", "aug_data/")
    # detected_data.update(aug_detected_data)
    # aug_metadata = read_metadata(f"{cred_data_location}/aug_data/meta", "aug_data/")
    # meta_data.update(aug_metadata)

    df_train = join_label(detected_data, meta_data)

    # to prevent extra memory consumption - delete unnecessary objects
    del detected_data
    del meta_data

    train_repo_list, test_repo_list = load_fixed_split()
    test_repo_list.extend(train_repo_list)

    # not test - will be
    # df_train = df  # [~df["repo"].isin(test_repo_list)]

    print(f"Train size: {len(df_train)}")
    df_train = df_train.drop_duplicates(subset=["line", "path"])
    len_df_train = len(df_train)
    print(f"Train size after drop_duplicates: {len_df_train}")

    x_train_value, x_train_features = prepare_data(df_train)
    print("\nx_train_value\n", x_train_value, x_train_value.dtype)  # dbg
    print("\nx_train_features\n", x_train_features, x_train_features.dtype)  # dbg
    y_train = get_y_labels(df_train)
    print("\ny_train\n", y_train, y_train.dtype)  # dbg
    del df_train
    class_weights = compute_class_weight(class_weight='balanced', classes=np.unique(y_train), y=y_train)
    class_weight = dict(enumerate(class_weights))
    print(f"class_weight: {class_weight}")  # information about class weights
    print("\ny_train\n", len(y_train), np.count_nonzero(y_train == 1), np.count_nonzero(y_train == 0))

    print(f"Class-1 prop on train: {np.mean(y_train):.4f}")

    df = join_label(detected_data_copy, meta_data_copy)
    df_missing = get_missing(detected_data_copy, meta_data_copy)
    df_test = df[df["repo"].isin(test_repo_list)]
    df_test = df_test.drop_duplicates(subset=["line", "path"])
    df_missing_test = df_missing[df_missing["repo"].isin(test_repo_list)]
    x_test_value, x_test_features = prepare_data(df_test)
    y_test = get_y_labels(df_test)

    keras_model = get_model_string_features(x_train_value.shape[-1], x_train_features.shape[-1])
    batch_size = 128

    fit_history = keras_model.fit(x=[x_train_value, x_train_features],
                                  y=y_train,
                                  batch_size=batch_size,
                                  epochs=26,
                                  verbose=2,
                                  validation_data=([x_test_value, x_test_features], y_test),
                                  class_weight=class_weight,
                                  use_multiprocessing=True)

    dir_path = pathlib.Path("results")
    os.makedirs(dir_path, exist_ok=True)
    model_file_name = dir_path / f"ml_model_at-{current_time}"
    keras_model.save(model_file_name, include_optimizer=False)

    with open(dir_path / f"history-{current_time}.pickle", "wb") as f:
        pickle.dump(fit_history, f)

    save_plot(stamp=current_time,
              title=f"batch:{batch_size} train:{len_df_train} test:{len(df_test)} weights:{class_weights}",
              history=fit_history,
              dir_path=dir_path)

    print("Validate results on the test subset")
    print(f"Test size: {len(df_test)}")
    print(f"Class-1 prop on test: {np.mean(y_test):.4f}")

    test_predictions, test_probabilities = get_predictions_keras(keras_model, [x_test_value, x_test_features])

    print("Results on test without model:")
    eval_no_model(df_test, df_missing_test)
    print("Results on test with model:")
    eval_with_model(df_test.copy(), df_missing_test, test_predictions)

    return str(model_file_name.absolute())


if __name__ == "__main__":
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
    _jobs = int(args.jobs)

    _model_file_name = main(_cred_data_location, _jobs)
    print(f"You can find your model in: {_model_file_name}")
    # python -m tf2onnx.convert --saved-model results/ml_model_at-20240201_073238 --output ../credsweeper/ml_model/ml_model.onnx --verbose
