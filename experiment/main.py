import hashlib
import os
import pathlib
import pickle
import random
import subprocess
import sys
from argparse import ArgumentParser
from datetime import datetime
from typing import List

import keras_tuner as kt
import numpy as np
import tensorflow as tf
from keras import Model  # type: ignore
from sklearn.metrics import f1_score, precision_score, recall_score, log_loss, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.utils import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

from experiment.plot import save_plot
from experiment.src.data_loader import read_detected_data, read_metadata, join_label, get_y_labels
from experiment.src.features import prepare_data
from experiment.src.log_callback import LogCallback
from experiment.src.lstm_model import MlModel
from experiment.src.model_config_preprocess import model_config_preprocess
from experiment.src.prepare_data import prepare_train_data, data_checksum


def evaluate_model(thresholds: dict, keras_model: Model, x_data: List[np.ndarray], y_label: np.ndarray):
    """Evaluate Keras model with printing scores

    Args:
        thresholds: dict of credsweeper thresholds
        keras_model: fitted keras model
        x_data: List of np.arrays. Number and shape depends on model
        y_label: expected result

    """
    predictions_proba = keras_model.predict(x_data, verbose=2).ravel()
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


def main(cred_data_location: str, jobs: int, use_tuner: bool = False) -> str:
    print(f"Memory at start: {LogCallback.get_memory_info()}")

    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")

    dir_path = pathlib.Path("results")
    os.makedirs(dir_path, exist_ok=True)

    print(f"Train model on data from {cred_data_location}")
    prepare_train_data(_cred_data_location, jobs)

    # detected data means which data is passed to ML validator of credsweeper after filters with RuleName
    cred_data_location_path = pathlib.Path(cred_data_location) / "data"
    detected_data = read_detected_data(f"results/detected_data.{data_checksum(cred_data_location_path)}.json")
    print(f"CredSweeper detected {len(detected_data)} credentials without ML")
    # all markup data
    meta_data = read_metadata(f"{cred_data_location}/meta")
    print(f"Metadata markup: {len(meta_data)} items")

    df_all = join_label(detected_data, meta_data, cred_data_location)
    # raise RuntimeError("TestDbg")
    # to prevent extra memory consumption - delete unnecessary objects
    del detected_data
    del meta_data

    # workaround for CI step
    for i in range(3):
        # there are 2 times possible fails due ml config was updated
        try:
            thresholds = model_config_preprocess(df_all)
            break
        except RuntimeError as exc:
            if "RESTART:" in str(exc):
                continue
            else:
                raise
    else:
        raise RuntimeError("Something went wrong")

    print(f"Common dataset: {len(df_all)} items")
    df_all = df_all.drop_duplicates(subset=["line", "variable", "value", "path", "ext"])
    print(f"Common dataset: {len(df_all)} items after drop duplicates")

    # random split
    lucky_number = random.randint(1, 1 << 32)
    print(f"Lucky number: {lucky_number}")
    df_train, df_test = train_test_split(df_all, test_size=0.15, random_state=lucky_number)
    len_df_train = len(df_train)
    print(f"Train size: {len_df_train}")
    len_df_test = len(df_test)
    print(f"Test size: {len_df_test}")

    print(f"Prepare full data")
    x_full_line, x_full_variable, x_full_value, x_full_features = prepare_data(df_all)
    y_full = get_y_labels(df_all)
    del df_all

    print(f"Prepare train data")
    x_train_line, x_train_variable, x_train_value, x_train_features = prepare_data(df_train)
    print("x_train_value dtype ", x_train_value.dtype)  # dbg
    print("x_train_features dtype", x_train_features.dtype)  # dbg
    y_train = get_y_labels(df_train)
    print("y_train dtype", y_train.dtype)  # dbg
    del df_train

    print(f"Class-1 prop on train: {np.mean(y_train):.4f}")

    classes = np.unique(y_train)
    class_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    max_weight = max(class_weights)
    class_weights = [weight / max_weight for weight in class_weights]
    print(f"y_train size:{len(y_train)}, 0: {np.count_nonzero(y_train == 0)}, 1: {np.count_nonzero(y_train == 1)}")
    class_weight = dict(zip(classes, class_weights))
    print(f"class_weight: {class_weight}")  # information about class weights

    print(f"Prepare test data")
    x_test_line, x_test_variable, x_test_value, x_test_features = prepare_data(df_test)
    y_test = get_y_labels(df_test)
    print(f"Class-1 prop on test: {np.mean(y_test):.4f}")
    del df_test

    print(f"Memory before search / compile: {LogCallback.get_memory_info()}")

    max_epochs = 100
    # ^^^ the line is patched in GitHub action to speed-up test train
    batch_size = 256
    patience = 5
    #return

    log_callback = LogCallback()
    if use_tuner:
        tuner = kt.GridSearch(
            hypermodel=MlModel(x_full_line.shape, x_full_variable.shape, x_full_value.shape, x_full_features.shape),
            objective='val_loss',
            directory=str(dir_path / f"{current_time}.tuner"),
            project_name='ml_tuning',
        )
        search_early_stopping = EarlyStopping(monitor="val_loss",
                                              patience=patience,
                                              mode="min",
                                              restore_best_weights=True,
                                              verbose=1)
        tuner.search(
            x=[x_train_line, x_train_variable, x_train_value, x_train_features],
            y=y_train,
            epochs=max_epochs,
            batch_size=batch_size,
            callbacks=[search_early_stopping, log_callback],
            validation_data=([x_test_line, x_test_variable, x_test_value, x_test_features], y_test),
            verbose=2,
        )
        print("Best Hyperparameters:")
        for k, v in tuner.get_best_hyperparameters()[0].values.items():
            print(f"{k}: {v}")
        keras_model = tuner.get_best_models()[0]
        del tuner
    else:
        keras_model = MlModel(x_full_line.shape, x_full_variable.shape, x_full_value.shape,
                              x_full_features.shape).build()

    early_stopping = EarlyStopping(monitor="val_loss",
                                   patience=patience,
                                   mode="min",
                                   restore_best_weights=True,
                                   verbose=1)
    model_checkpoint = ModelCheckpoint(filepath=str(dir_path / f"{current_time}.best_model"),
                                       monitor="val_loss",
                                       save_best_only=True,
                                       mode="min",
                                       verbose=1)

    print(f"Memory before train: {LogCallback.get_memory_info()}")

    fit_history = keras_model.fit(x=[x_train_line, x_train_variable, x_train_value, x_train_features],
                                  y=y_train,
                                  batch_size=batch_size,
                                  epochs=max_epochs,
                                  verbose=2,
                                  validation_data=([x_test_line, x_test_variable, x_test_value,
                                                    x_test_features], y_test),
                                  class_weight=class_weight,
                                  callbacks=[early_stopping, model_checkpoint, log_callback],
                                  use_multiprocessing=True)

    print(f"Memory after train: {LogCallback.get_memory_info()}")

    with open(dir_path / f"{current_time}.history.pickle", "wb") as f:
        pickle.dump(fit_history, f)

    model_file_name = dir_path / f"ml_model_at-{current_time}"
    keras_model.save(model_file_name, include_optimizer=False)

    print(f"Validate results on the train subset. Size: {len(y_train)} {np.mean(y_train):.4f}")
    evaluate_model(thresholds, keras_model, [x_train_line, x_train_variable, x_train_value, x_train_features], y_train)
    del x_train_line
    del x_train_variable
    del x_train_value
    del x_train_features
    del y_train

    print(f"Validate results on the test subset. Size: {len(y_test)} {np.mean(y_test):.4f}")
    evaluate_model(thresholds, keras_model, [x_test_line, x_test_variable, x_test_value, x_test_features], y_test)
    del x_test_line
    del x_test_variable
    del x_test_value
    del x_test_features
    del y_test

    print(f"Validate results on the full set. Size: {len(y_full)} {np.mean(y_full):.4f}")
    evaluate_model(thresholds, keras_model, [x_full_line, x_full_variable, x_full_value, x_full_features], y_full)
    del x_full_line
    del x_full_variable
    del x_full_value
    del x_full_features
    del y_full

    onnx_model_file = pathlib.Path(__file__).parent.parent / "credsweeper" / "ml_model" / "ml_model.onnx"
    # convert the model to onnx right now
    command = f"{sys.executable} -m tf2onnx.convert --saved-model {model_file_name.absolute()}" \
              f" --output {str(onnx_model_file)} --verbose"
    subprocess.check_call(command, shell=True, cwd=pathlib.Path(__file__).parent)
    with open(onnx_model_file, "rb") as f:
        onnx_md5 = hashlib.md5(f.read()).hexdigest()
        print(f"ml_model.onnx:{onnx_md5}")

    with open(pathlib.Path(__file__).parent.parent / "credsweeper" / "ml_model" / "ml_config.json", "rb") as f:
        config_md5 = hashlib.md5(f.read()).hexdigest()
        print(f"ml_config.json:{config_md5}")

    best_epoch = 1 + np.argmin(np.array(fit_history.history['val_loss']))

    # ml history analysis
    save_plot(
        stamp=current_time,
        title=f"batch:{batch_size} train:{len_df_train} test:{len_df_test} weights:{class_weights}",
        history=fit_history,
        dir_path=dir_path,
        best_epoch=int(best_epoch),
        info=f"ml_config.json:{config_md5} ml_model.onnx:{onnx_md5} best_epoch:{best_epoch}",
    )

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
    parser.add_argument("-t", "--tuner", help="use keras tuner", dest="use_tuner", action="store_true")
    args = parser.parse_args()

    fixed_seed = 20241126  # int(datetime.now().timestamp())
    # print(f"Random seed:{fixed_seed}")
    if fixed_seed is not None:
        tf.random.set_seed(fixed_seed)
        np.random.seed(fixed_seed)
        random.seed(fixed_seed)

    _cred_data_location = args.cred_data_location
    _jobs = int(args.jobs)

    # to keep the hash in log and verify
    command = f"md5sum {pathlib.Path(__file__).parent.parent}/credsweeper/ml_model/ml_config.json"
    subprocess.check_call(command, shell=True, cwd=pathlib.Path(__file__).parent)
    command = f"md5sum {pathlib.Path(__file__).parent.parent}/credsweeper/ml_model/ml_model.onnx"
    subprocess.check_call(command, shell=True, cwd=pathlib.Path(__file__).parent)

    _model_file_name = main(_cred_data_location, _jobs, args.use_tuner)
    # print in last line the name
    print(f"\nYou can find your model in:\n{_model_file_name}")
