import os
import pathlib
import random
from argparse import ArgumentParser
from datetime import datetime
from typing import List

import numpy as np
import tensorflow as tf
from keras import Model
from sklearn.metrics import f1_score, precision_score, recall_score, log_loss, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.utils import compute_class_weight

from credsweeper.app import APP_PATH
from credsweeper.utils import Util
from experiment.plot import save_plot
from experiment.src.data_loader import read_detected_data, read_metadata, join_label, get_y_labels
from experiment.src.features import prepare_data
from experiment.src.lstm_model import get_model_string_features
from experiment.src.prepare_data import prepare_train_data


def evaluate_model(thresholds: dict, keras_model: Model, x_data: List[np.ndarray], y_label: np.ndarray):
    """Evaluate Keras model with printing scores

    Args:
        thresholds: dict of credsweeper thresholds
        keras_model: fitted keras model
        x_data: List of np.arrays. Number and shape depends on model
        y_label: expected result

    """
    predictions_proba = keras_model.predict(x_data).ravel()
    for name, threshold in thresholds.items():
        predictions = (predictions_proba > threshold)
        accuracy = accuracy_score(y_label, predictions)
        precision = precision_score(y_label, predictions)
        recall = recall_score(y_label, predictions)
        loss = log_loss(y_label, predictions)
        f1 = f1_score(y_label, predictions)
        print(f"{name}: {threshold:0.6f}, "
              f"accuracy: {accuracy:0.6f}, "
              f"precision:{precision:0.6f}, "
              f"recall: {recall:0.6f}, "
              f"loss: {loss:0.6f}, "
              f"F1:{f1:0.6f}")


def main(cred_data_location: str, jobs: int) -> str:
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")

    model_config = Util.json_load(APP_PATH / "ml_model" / "model_config.json")
    thresholds = model_config["thresholds"]
    assert isinstance(thresholds, dict), thresholds
    print(f"Load thresholds: {thresholds}")

    prepare_train_data(_cred_data_location, jobs)
    print(f"Train model on data from {cred_data_location}")

    # detected data means which data is passed to ML validator of credsweeper after filters with RuleName
    detected_data = read_detected_data("data/result.json")
    print(f"CredSweeper detected {len(detected_data)} credentials without ML")
    # all markup data
    meta_data = read_metadata(f"{cred_data_location}/meta")
    print(f"Metadata markup: {len(meta_data)} items")

    df_all = join_label(detected_data, meta_data)
    # to prevent extra memory consumption - delete unnecessary objects
    del detected_data
    del meta_data

    print(f"Common dataset: {len(df_all)} items")
    df_all = df_all.drop_duplicates(subset=["line", "type", "ext"])
    print(f"Common dataset: {len(df_all)} items after drop duplicates")

    # random split
    df_train, df_test = train_test_split(df_all, test_size=0.2, random_state=42)
    len_df_train = len(df_train)
    print(f"Train size: {len_df_train}")
    len_df_test = len(df_test)
    print(f"Test size: {len_df_test}")
    x_eval_value, x_eval_features = prepare_data(df_all)
    y_eval = get_y_labels(df_all)
    del df_all

    x_train_value, x_train_features = prepare_data(df_train)
    print("x_train_value dtype ", x_train_value.dtype)  # dbg
    print("x_train_features dtype", x_train_features.dtype)  # dbg
    y_train = get_y_labels(df_train)
    print("y_train dtype", y_train.dtype)  # dbg
    del df_train

    print(f"Class-1 prop on train: {np.mean(y_train):.4f}")

    class_weights = compute_class_weight(class_weight='balanced', classes=np.unique(y_train), y=y_train)
    class_weight = dict(enumerate(class_weights))
    print(f"class_weight: {class_weight}")  # information about class weights
    print(f"y_train size:{len(y_train)}, 1: {np.count_nonzero(y_train == 1)}, 0: {np.count_nonzero(y_train == 0)}")

    x_test_value, x_test_features = prepare_data(df_test)
    y_test = get_y_labels(df_test)
    print(f"Class-1 prop on test: {np.mean(y_test):.4f}")

    keras_model = get_model_string_features(x_train_value.shape[-1], x_train_features.shape[-1])
    batch_size = 256

    fit_history = keras_model.fit(x=[x_train_value, x_train_features],
                                  y=y_train,
                                  batch_size=batch_size,
                                  epochs=22,
                                  verbose=2,
                                  validation_data=([x_test_value, x_test_features], y_test),
                                  class_weight=class_weight,
                                  use_multiprocessing=True)

    dir_path = pathlib.Path("results")
    os.makedirs(dir_path, exist_ok=True)
    model_file_name = dir_path / f"ml_model_at-{current_time}"
    keras_model.save(model_file_name, include_optimizer=False)

    print("Validate results on the test subset")
    print(f"Test size: {len(y_test)}")
    print(f"Class-1 prop on eval: {np.mean(y_test):.4f}")
    evaluate_model(thresholds, keras_model, [x_test_value, x_test_features], y_test)

    print("Validate results on the full set")
    print(f"Test size: {len(y_eval)}")
    print(f"Class-1 prop on eval: {np.mean(y_eval):.4f}")
    evaluate_model(thresholds, keras_model, [x_eval_value, x_eval_features], y_eval)

    # ml history analysis
    save_plot(stamp=current_time,
              title=f"batch:{batch_size} train:{len_df_train} test:{len(df_test)} weights:{class_weights}",
              history=fit_history,
              dir_path=dir_path)

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
    print(f"\nYou can find your model in: {_model_file_name}")
    # python -m tf2onnx.convert --saved-model results/ml_model_at-20240201_073238 --output ../credsweeper/ml_model/ml_model.onnx --verbose
