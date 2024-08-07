from tensorflow.keras.layers import Dense, LSTM, Bidirectional, Input, Concatenate, Dropout
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from tensorflow.python.keras.metrics import BinaryAccuracy, Precision, Recall

from credsweeper import MlValidator
from credsweeper.common.constants import ML_HUNK


def get_model(
        line_shape: tuple,
        variable_shape: tuple,
        value_shape: tuple,
        feature_shape: tuple,
        extension_shape: tuple,
        # learning_rate: float,
) -> Model:
    """Get keras model with string and feature input and single binary out"""
    d_type = "float32"

    line_input = Input(shape=(None, line_shape[2]), name="line_input", dtype=d_type)
    line_lstm = LSTM(units=line_shape[1], dtype=d_type)
    line_bidirectional = Bidirectional(layer=line_lstm)
    line_lstm_branch = Dropout(0.33)(line_bidirectional(line_input))

    variable_input = Input(shape=(None, variable_shape[2]), name="variable_input", dtype=d_type)
    variable_lstm = LSTM(units=variable_shape[1], dtype=d_type)
    variable_bidirectional = Bidirectional(layer=variable_lstm)
    variable_lstm_branch = Dropout(0.33)(variable_bidirectional(variable_input))

    value_input = Input(shape=(None, value_shape[2]), name="value_input", dtype=d_type)
    value_lstm = LSTM(units=value_shape[1], dtype=d_type)
    value_bidirectional = Bidirectional(layer=value_lstm)
    value_lstm_branch = Dropout(0.33)(value_bidirectional(value_input))

    extension_input = Input(shape=(None, extension_shape[2]), name="extension_input", dtype=d_type)
    extension_lstm = LSTM(units=extension_shape[1], dtype=d_type)
    extension_bidirectional = Bidirectional(layer=extension_lstm)
    extension_lstm_branch = Dropout(0.33)(extension_bidirectional(extension_input))

    feature_input = Input(shape=(feature_shape[1],), name="feature_input", dtype=d_type)

    joined_features = Concatenate()([line_lstm_branch, variable_lstm_branch, value_lstm_branch, extension_lstm_branch,
                                     feature_input])

    # 3 bidirectional + 2*16 for extension + features
    dense_units = 2 * MlValidator.MAX_LEN + 2 * 2 * ML_HUNK + 32 + feature_shape[1]
    # check after model compilation. Should be matched the combined size.
    dense_a = Dense(units=dense_units, activation='relu', name="dense", dtype=d_type)
    joined_layers = dense_a(joined_features)
    dropout = Dropout(0.33)
    dropout_layer = dropout(joined_layers)
    dense_b = Dense(units=1, activation='sigmoid', name="prediction", dtype=d_type)
    output = dense_b(dropout_layer)

    model: Model = Model(inputs=[line_input, variable_input, value_input, feature_input], outputs=output)

    metrics = [BinaryAccuracy(name="binary_accuracy"), Precision(name="precision"), Recall(name="recall")]
    model.compile(optimizer=Adam(), loss='binary_crossentropy', metrics=metrics)

    model.summary(line_length=120, expand_nested=True, show_trainable=True)

    return model
