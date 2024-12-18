import keras_tuner as kt
from tensorflow.keras.layers import Dense, LSTM, Bidirectional, Input, Concatenate, Dropout
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from tensorflow.python.keras.metrics import BinaryAccuracy, Precision, Recall

from credsweeper import MlValidator
from credsweeper.common.constants import ML_HUNK


class MlModel(kt.HyperModel):
    d_type = "float32"

    def __init__(
        self,
        line_shape: tuple,
        variable_shape: tuple,
        value_shape: tuple,
        feature_shape: tuple,
    ):
        self.line_shape = line_shape
        self.variable_shape = variable_shape
        self.value_shape = value_shape
        self.feature_shape = feature_shape

    def build(self, hp=None) -> Model:
        """Get keras model with string and feature input and single binary out"""
        if hp:
            min_val = 0.22
            max_val = 0.44
            step_val = 0.11
            dropout_line = hp.Float('dropout_line', min_value=min_val, max_value=max_val, step=step_val)
            dropout_variable = hp.Float('dropout_variable', min_value=min_val, max_value=max_val, step=step_val)
            dropout_value = hp.Float('dropout_value', min_value=min_val, max_value=max_val, step=step_val)
            dropout_dense = hp.Float('dropout_dense', min_value=min_val, max_value=max_val, step=step_val)
        else:
            # found best values
            dropout_line = 0.33
            dropout_variable = 0.33
            dropout_value = 0.33
            dropout_dense = 0.33

        line_input = Input(shape=(None, self.line_shape[2]), name="line_input", dtype=self.d_type)
        line_lstm = LSTM(units=self.line_shape[1], dtype=self.d_type)
        line_bidirectional = Bidirectional(layer=line_lstm, name="line_bidirectional")
        line_lstm_branch = Dropout(dropout_line, name="line_dropout")(line_bidirectional(line_input))

        variable_input = Input(shape=(None, self.variable_shape[2]), name="variable_input", dtype=self.d_type)
        variable_lstm = LSTM(units=self.variable_shape[1], dtype=self.d_type)
        variable_bidirectional = Bidirectional(layer=variable_lstm, name="variable_bidirectional")
        variable_lstm_branch = Dropout(dropout_variable,
                                       name="variable_dropout")(variable_bidirectional(variable_input))

        value_input = Input(shape=(None, self.value_shape[2]), name="value_input", dtype=self.d_type)
        value_lstm = LSTM(units=self.value_shape[1], dtype=self.d_type)
        value_bidirectional = Bidirectional(layer=value_lstm, name="value_bidirectional")
        value_lstm_branch = Dropout(dropout_value, name="value_dropout")(value_bidirectional(value_input))

        feature_input = Input(shape=(self.feature_shape[1], ), name="feature_input", dtype=self.d_type)

        joined_features = Concatenate()([line_lstm_branch, variable_lstm_branch, value_lstm_branch, feature_input])

        # 3 bidirectional + features
        dense_units = 2 * MlValidator.MAX_LEN + 2 * 2 * ML_HUNK + self.feature_shape[1]
        # check after model compilation. Should be matched the combined size.
        dense_a = Dense(units=dense_units, activation='relu', name="dense", dtype=self.d_type)
        joined_layers = dense_a(joined_features)
        dropout_layer = Dropout(dropout_dense, name="dense_dropout")(joined_layers)
        dense_b = Dense(units=1, activation='sigmoid', name="prediction", dtype=self.d_type)
        output = dense_b(dropout_layer)

        metrics = [BinaryAccuracy(name="binary_accuracy"), Precision(name="precision"), Recall(name="recall")]

        model: Model = Model(inputs=[line_input, variable_input, value_input, feature_input], outputs=output)
        model.compile(optimizer=Adam(), loss='binary_crossentropy', metrics=metrics)
        model.summary(line_length=120, expand_nested=True, show_trainable=True)

        return model
