from typing import Any

import keras_tuner as kt
from tensorflow.keras.layers import Dense, LSTM, Bidirectional, Input, Concatenate, Dropout
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from tensorflow.python.keras.metrics import BinaryAccuracy, Precision, Recall

from credsweeper.common.constants import ML_HUNK
from credsweeper.ml_model.ml_validator import MlValidator


class MlModel(kt.HyperModel):
    d_type = "float32"

    def __init__(self, line_shape: tuple, variable_shape: tuple, value_shape: tuple, feature_shape: tuple, **kwargs):
        self.line_shape = line_shape
        self.variable_shape = variable_shape
        self.value_shape = value_shape
        self.feature_shape = feature_shape
        self.__kwargs = kwargs

    def __get_hyperparam(self, param_name: str, hp=None) -> Any:
        if param := self.__kwargs.get(param_name):
            if isinstance(param, float):
                print(f"'{param_name}' constant = {param}", flush=True)
                return param
            elif hp and isinstance(param, tuple) and 3 == len(param):
                print(f"'{param_name}' tuning = {param}", flush=True)
                return hp.Float(param_name, min_value=param[0], max_value=param[1], step=param[2])
            else:
                raise ValueError(f"'{param_name}' was not inited well {param} tuner is {bool(hp)}")
        else:
            raise ValueError(f"'{param_name}' was not defined during init and tuner is used")

    def build(self, hp=None) -> Model:
        """Get keras model with string and feature input and single binary out"""
        value_lstm_dropout_rate = self.__get_hyperparam("value_lstm_dropout_rate", hp)
        line_lstm_dropout_rate = self.__get_hyperparam("line_lstm_dropout_rate", hp)
        variable_lstm_dropout_rate = self.__get_hyperparam("variable_lstm_dropout_rate", hp)
        dense_a_dropout_rate = self.__get_hyperparam("dense_a_lstm_dropout_rate", hp)
        dense_b_dropout_rate = self.__get_hyperparam("dense_b_lstm_dropout_rate", hp)

        line_input = Input(shape=(None, self.line_shape[2]), name="line_input", dtype=self.d_type)
        line_lstm = LSTM(units=self.line_shape[1], dtype=self.d_type)
        line_bidirectional = Bidirectional(layer=line_lstm, name="line_bidirectional")
        line_lstm_branch = Dropout(line_lstm_dropout_rate, name="line_dropout")(line_bidirectional(line_input))

        variable_input = Input(shape=(None, self.variable_shape[2]), name="variable_input", dtype=self.d_type)
        variable_lstm = LSTM(units=self.variable_shape[1], dtype=self.d_type)
        variable_bidirectional = Bidirectional(layer=variable_lstm, name="variable_bidirectional")
        variable_lstm_branch = Dropout(variable_lstm_dropout_rate,
                                       name="variable_dropout")(variable_bidirectional(variable_input))

        value_input = Input(shape=(None, self.value_shape[2]), name="value_input", dtype=self.d_type)
        value_lstm = LSTM(units=self.value_shape[1], dtype=self.d_type)
        value_bidirectional = Bidirectional(layer=value_lstm, name="value_bidirectional")
        value_lstm_branch = Dropout(value_lstm_dropout_rate, name="value_dropout")(value_bidirectional(value_input))

        feature_input = Input(shape=(self.feature_shape[1], ), name="feature_input", dtype=self.d_type)

        joined_features = Concatenate()([line_lstm_branch, variable_lstm_branch, value_lstm_branch, feature_input])

        # 3 bidirectional + features
        dense_units = 2 * MlValidator.MAX_LEN + 2 * 2 * ML_HUNK + self.feature_shape[1]
        # check after model compilation. Should be matched the combined size.

        # first hidden layer
        dense_a = Dense(units=dense_units, activation='relu', name="a_dense", dtype=self.d_type)(joined_features)
        dropout_dense_a = Dropout(dense_a_dropout_rate, name="a_dropout")(dense_a)

        # second hidden layer
        dense_b = Dense(units=dense_units, activation='relu', name="b_dense", dtype=self.d_type)(dropout_dense_a)
        dropout_dense_b = Dropout(dense_b_dropout_rate, name="b_dropout")(dense_b)

        dense_final = Dense(units=1, activation='sigmoid', name="prediction", dtype=self.d_type)(dropout_dense_b)

        metrics = [BinaryAccuracy(name="binary_accuracy"), Precision(name="precision"), Recall(name="recall")]

        model: Model = Model(inputs=[line_input, variable_input, value_input, feature_input], outputs=dense_final)
        model.compile(optimizer=Adam(), loss='binary_crossentropy', metrics=metrics)
        model.summary(line_length=120, expand_nested=True, show_trainable=True)

        return model
