from tensorflow.keras.layers import Dense, LSTM, Bidirectional, Input, Concatenate
from tensorflow.keras.models import Model
from tensorflow.python.keras.metrics import BinaryAccuracy, Precision, Recall

DEFAULT_METRICS = [BinaryAccuracy(), Precision(), Recall()]


def get_model(line_shape: tuple,
              value_shape: tuple,
              feature_shape: tuple,
              ) -> Model:
    """Get keras model with string and feature input and single binary out"""
    d_type = "float32"

    line_input = Input(shape=(None, line_shape[2]), name="line_input", dtype=d_type)
    line_lstm = LSTM(units=line_shape[1], dtype=d_type)
    line_bidirectional = Bidirectional(layer=line_lstm)
    line_lstm_branch = line_bidirectional(line_input)

    value_input = Input(shape=(None, value_shape[2]), name="value_input", dtype=d_type)
    value_lstm = LSTM(units=value_shape[1], dtype=d_type)
    value_bidirectional = Bidirectional(layer=value_lstm)
    value_lstm_branch = value_bidirectional(value_input)

    # vv_concat_layer = Concatenate()([variable_lstm_branch, value_lstm_branch])

    feature_input = Input(shape=(feature_shape[1],), name="feature_input", dtype=d_type)

    joined_features = Concatenate()([line_lstm_branch, value_lstm_branch, feature_input])

    dense_units = 1327  # should be known after model compilation
    dense_a = Dense(units=dense_units, activation='relu', name="dense", dtype=d_type)
    joined_layers = dense_a(joined_features)
    dense_b = Dense(units=1, activation='sigmoid', name="prediction", dtype=d_type)
    output = dense_b(joined_layers)

    model = Model(inputs=[line_input, value_input, feature_input], outputs=output)

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=DEFAULT_METRICS)

    model.summary(line_length=120, expand_nested=True, show_trainable=True)

    return model
