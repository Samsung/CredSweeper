import os
import random
from argparse import ArgumentParser
from copy import deepcopy
from time import time
from typing import Tuple, List
import tensorflow as tf
import numpy as np
from tensorflow.python.keras import Model

from experiment.src.data_loader import read_detected_data, read_metadata, join_label, get_missing, eval_no_model, \
    get_y_labels, eval_with_model
from experiment.src.prepare_data import prepare_train_data
from experiment.src.features import prepare_data
from experiment.src.lstm_model import get_model_string_features
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


def main(cred_data_location: str) -> str:
    print(f"Train model on data from {cred_data_location}")
    print("Use original ang augmented data for train")

    detected_data = read_detected_data("data/result.json")
    meta_data = read_metadata(f"{cred_data_location}/meta")

    detected_data_copy = deepcopy(detected_data)
    meta_data_copy = deepcopy(meta_data)

    # Combine original and augmented data together
    detected_data.update(read_detected_data("data/result_aug_data.json", "aug_data/"))
    meta_data.update(read_metadata(f"{cred_data_location}/aug_data/meta", "aug_data/"))

    df = join_label(detected_data, meta_data)

    train_repo_list, test_repo_list = load_fixed_split()

    df_train = df[df["repo"].isin(train_repo_list)]

    print('-' * 40)
    print(f"Train size: {len(df_train)}")

    df_train = df_train.drop_duplicates(subset=["line", "ext"])
    print(f"Train size after drop_duplicates: {len(df_train)}")

    X_train_value, X_train_features = prepare_data(df_train)
    y_train = get_y_labels(df_train)

    print(f"Class-1 prop on train: {np.mean(y_train):.2f}")

    keras_model = get_model_string_features(X_train_value.shape[-1], X_train_features.shape[-1])

    fit_history = keras_model.fit(
        [X_train_value, X_train_features],
        y_train,
        batch_size=64,
        epochs=10,
        # Class 1 in train data is roughly ~4 times more abundant than 0. As can be seen from the log
        class_weight={
            0: 4,
            1: 1
        })

    os.makedirs("results/", exist_ok=True)
    current_time = int(time())
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
    eval_with_model(df_test, df_missing_test, test_predictions)
    return model_file_name


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

    fixed_seed = 42
    if fixed_seed is not None:
        tf.random.set_seed(fixed_seed)
        np.random.seed(fixed_seed)
        random.seed(fixed_seed)

    cred_data_location = args.cred_data_location
    j = int(args.jobs)

    prepare_train_data(cred_data_location, j)
    model_file_name = main(cred_data_location)
    print(f"You can find your model in: {model_file_name}")
