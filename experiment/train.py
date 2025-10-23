import hashlib
import keras_tuner as kt
import numpy as np
import os
import pandas as pd
import pathlib
import pickle
import random
import subprocess
import sys
import tensorflow as tf
from argparse import ArgumentParser, BooleanOptionalAction
from datetime import datetime
from typing import List

import keras_tuner as kt
import numpy as np
import pandas as pd
from keras import Model  # type: ignore
from numpy import ndarray
from sklearn.metrics import f1_score, precision_score, recall_score, log_loss, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.utils import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from typing import List

from plot import save_plot
from data_loader import read_detected_data, read_metadata, join_label, get_y_labels
from features import prepare_data
from log_callback import LogCallback
from ml_model import MlModel
from model_config_preprocess import model_config_preprocess, ML_CONFIG_PATH
from prepare_data import prepare_train_data


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
        print(
            f"{name}: {threshold:0.6f}, "
            f"accuracy: {accuracy:0.6f}, "
            f"precision:{precision:0.6f}, "
            f"recall: {recall:0.6f}, "
            f"loss: {loss:0.6f}, "
            f"F1:{f1:0.6f}",
            flush=True)


def train(
    cred_data_location: str,
    jobs: int,
    epochs: int,
    batch_size: int,
    patience: int,
    doc_target: bool,
    use_tuner: bool,
    eval_test: bool,
    eval_train: bool,
    eval_full: bool,
) -> str:
    # fixed seed for std.random in main()
    tf.random.set_seed(random.randint(1, 0xffffffff))
    np.random.seed(random.randint(1, 0xffffffff))

    print(f"Memory at start: {LogCallback.get_memory_info()}", flush=True)

    subprocess.check_call(f"md5sum {ML_CONFIG_PATH.absolute()}", shell=True)  # dbg

    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")

    dir_path = pathlib.Path("results")
    os.makedirs(dir_path, exist_ok=True)

    print(f"Train model on data from {cred_data_location}", flush=True)
    meta_checksum, data_checksum = prepare_train_data(cred_data_location, jobs, doc_target)

    df_all_file = dir_path / f"{meta_checksum}-{data_checksum}.pkl"
    if df_all_file.exists():
        df_all = pd.read_pickle(df_all_file)
        print(f"Read from {df_all_file}", flush=True)
    else:
        # detected data means which data is passed to ML validator of credsweeper after filters with RuleName
        detected_data = read_detected_data(f"results/detected_data.{data_checksum}.json")
        print(f"CredSweeper detected {len(detected_data)} credentials without ML", flush=True)
        # all markup data
        meta_data = read_metadata(f"{cred_data_location}/meta")
        print(f"Metadata markup: {len(meta_data)} items", flush=True)
        df_all = join_label(detected_data, meta_data, cred_data_location)
        # np.save(df_all_file, df_all)
        df_all.to_pickle(df_all_file)
        print(f"Stored to {df_all_file}", flush=True)
        # to prevent extra memory consumption - delete unnecessary objects
        del detected_data
        del meta_data

    # workaround for CI step
    trial_cnt = 3
    while 0 < trial_cnt:
        trial_cnt -= 1
        # there are 2 times possible fails due ml config might be updated
        try:
            thresholds = model_config_preprocess(df_all, doc_target)
            break
        except RuntimeError as exc:
            if "RESTART:" in str(exc) and 0 <= trial_cnt:
                print(str(exc), flush=True)
                continue
            else:
                raise exc
    else:
        raise RuntimeError("Something went wrong")

    print(f"Common dataset: {len(df_all)} items", flush=True)
    df_all = df_all.drop_duplicates(subset=["line", "variable", "value", "path", "ext"])
    print(f"Common dataset: {len(df_all)} items after drop duplicates", flush=True)

    # random split
    lucky_number = random.randint(1, 1 << 32)
    print(f"Lucky number: {lucky_number}", flush=True)
    df_train, df_test = train_test_split(df_all, test_size=0.15, random_state=lucky_number)
    len_df_train = len(df_train)
    print(f"Train size: {len_df_train}", flush=True)
    len_df_test = len(df_test)
    print(f"Test size: {len_df_test}", flush=True)

    print(f"Prepare full data", flush=True)
    x_full_line, x_full_variable, x_full_value, x_full_features = prepare_data(df_all)
    y_full: ndarray = get_y_labels(df_all)
    del df_all

    print(f"Prepare train data", flush=True)
    x_train_line, x_train_variable, x_train_value, x_train_features = prepare_data(df_train)
    print("x_train_value dtype ", x_train_value.dtype, flush=True)  # dbg
    print("x_train_features dtype", x_train_features.dtype, flush=True)  # dbg
    y_train = get_y_labels(df_train)
    print("y_train dtype", y_train.dtype, flush=True)  # dbg
    del df_train

    print(f"Class-1 prop on train: {np.mean(y_train):.4f}", flush=True)

    classes = np.unique(y_train)
    class_weights = compute_class_weight(class_weight='balanced', classes=classes, y=y_train)
    max_weight = max(class_weights)
    class_weights = [weight / max_weight for weight in class_weights]
    print(f"y_train size:{len(y_train)}, 0: {np.count_nonzero(y_train == 0)}, 1: {np.count_nonzero(y_train == 1)}",
          flush=True)
    class_weight = dict(zip(classes, class_weights))
    print(f"class_weight: {class_weight}", flush=True)  # information about class weights

    print(f"Prepare test data", flush=True)
    x_test_line, x_test_variable, x_test_value, x_test_features = prepare_data(df_test)
    y_test = get_y_labels(df_test)
    print(f"Class-1 prop on test: {np.mean(y_test):.4f}", flush=True)
    del df_test

    print(f"Memory before search / compile: {LogCallback.get_memory_info()}", flush=True)

    hp_dict = {
        "line_lstm_dropout_rate": ((0.3, 0.5, 0.01), 0.4),
        "line_lstm_recurrent_dropout_rate": ((0.0, 0.4, 0.01), 0.1),
        "variable_lstm_dropout_rate": ((0.3, 0.5, 0.01), 0.4),
        "variable_lstm_recurrent_dropout_rate": ((0.0, 0.4, 0.01), 0.1),
        "value_lstm_dropout_rate": ((0.3, 0.5, 0.01), 0.4),
        "value_lstm_recurrent_dropout_rate": ((0.0, 0.4, 0.01), 0.1),
        "dense_a_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.2),
        "dense_b_lstm_dropout_rate": ((0.1, 0.5, 0.01), 0.2),
    }
    log_callback = LogCallback()
    if use_tuner:
        print(f"Tuner initial dict:{hp_dict}", flush=True)
        tuner_kwargs = {k: v[0] for k, v in hp_dict.items()}
        print(f"Tuner kwargs:{tuner_kwargs}", flush=True)

        tuner = kt.BayesianOptimization(
            hypermodel=MlModel(x_full_line.shape, x_full_variable.shape, x_full_value.shape, x_full_features.shape,
                               **tuner_kwargs),
            objective='val_loss',
            directory=str(dir_path / f"{current_time}.tuner"),
            project_name='ml_tuning',
            seed=random.randint(1, 0xffffffff),
            max_trials=30,
        )
        search_early_stopping = EarlyStopping(monitor="val_loss",
                                              patience=patience,
                                              mode="min",
                                              restore_best_weights=True,
                                              verbose=1)
        tuner.search(
            x=[x_train_line, x_train_variable, x_train_value, x_train_features],
            y=y_train,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=[search_early_stopping, log_callback],
            validation_data=([x_test_line, x_test_variable, x_test_value, x_test_features], y_test),
            verbose=2,
        )
        print("Best Hyperparameters:", flush=True)
        for k, v in tuner.get_best_hyperparameters()[0].values.items():
            print(f"{k}: {v}", flush=True)
        param_kwargs = {k: float(v) for k, v in tuner.get_best_hyperparameters()[0].values.items() if k in hp_dict}
        del tuner
    else:
        print(f"Model is trained with params from dict:{hp_dict}", flush=True)
        param_kwargs = {k: v[1] for k, v in hp_dict.items()}

    print(f"Model hyper parameters: {param_kwargs}", flush=True)

    # repeat train step to obtain actual history chart
    _model = MlModel(x_full_line.shape, x_full_variable.shape, x_full_value.shape, x_full_features.shape,
                     **param_kwargs)
    keras_model = _model.build(hp=None)  # this train will be used hyperparam in param_kwargs
    if not eval_full:
        # the data are not necessary
        del x_full_line
        del x_full_variable
        del x_full_value
        del x_full_features
        del y_full

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

    print(f"Memory before train: {LogCallback.get_memory_info()}", flush=True)

    fit_history = keras_model.fit(x=[x_train_line, x_train_variable, x_train_value, x_train_features],
                                  y=y_train,
                                  batch_size=batch_size,
                                  epochs=epochs,
                                  verbose=2,
                                  validation_data=([x_test_line, x_test_variable, x_test_value,
                                                    x_test_features], y_test),
                                  class_weight=class_weight,
                                  callbacks=[early_stopping, model_checkpoint, log_callback],
                                  use_multiprocessing=True)

    # if best_val_loss is not None and best_val_loss + 0.00001 < early_stopping.best:
    #     print(f"CHECK BEST TUNER EARLY STOP : {best_val_loss} vs CURRENT: {early_stopping.best}",flush=True)

    print(f"Memory after train: {LogCallback.get_memory_info()}", flush=True)

    with open(dir_path / f"{current_time}.history.pickle", "wb") as f:
        pickle.dump(fit_history, f)

    model_file_name = dir_path / f"ml_model_at-{current_time}"
    keras_model.save(model_file_name, include_optimizer=False)

    if eval_test:
        print(f"Validate results on the test subset. Size: {len(y_test)} {np.mean(y_test):.4f}", flush=True)
        evaluate_model(thresholds, keras_model, [x_test_line, x_test_variable, x_test_value, x_test_features], y_test)
    # drop small test set first to free a bit more memory for next evaluation
    del x_test_line
    del x_test_variable
    del x_test_value
    del x_test_features
    del y_test

    if eval_train:
        print(f"Validate results on the train subset. Size: {len(y_train)} {np.mean(y_train):.4f}", flush=True)
        evaluate_model(thresholds, keras_model, [x_train_line, x_train_variable, x_train_value, x_train_features],
                       y_train)
    del x_train_line
    del x_train_variable
    del x_train_value
    del x_train_features
    del y_train

    if eval_full:
        print(f"Validate results on the full set. Size: {len(y_full)} {np.mean(y_full):.4f}", flush=True)
        evaluate_model(thresholds, keras_model, [x_full_line, x_full_variable, x_full_value, x_full_features], y_full)
        del x_full_line
        del x_full_variable
        del x_full_value
        del x_full_features
        del y_full

    onnx_model_file = pathlib.Path(__file__).parent.parent / "credsweeper" / "ml_model" / "ml_model.onnx"
    # convert the model to onnx right now
    convert_args = f"{sys.executable} -m tf2onnx.convert --saved-model {model_file_name.absolute()}" \
                   f" --output {str(onnx_model_file)} --verbose"
    subprocess.check_call(convert_args, shell=True, cwd=pathlib.Path(__file__).parent)
    with open(onnx_model_file, "rb") as f:
        onnx_md5 = hashlib.md5(f.read()).hexdigest()
        print(f"ml_model.onnx:{onnx_md5}", flush=True)

    with open(ML_CONFIG_PATH, "rb") as f:
        config_md5 = hashlib.md5(f.read()).hexdigest()
        print(f"ml_config.json:{config_md5}", flush=True)

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
