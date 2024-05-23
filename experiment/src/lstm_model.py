import tensorflow as tf
from tensorflow.keras.layers import Dense, LSTM, Bidirectional, Input, Concatenate
from tensorflow.keras.models import Model

DEFAULT_METRICS = [tf.keras.metrics.BinaryAccuracy(), tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]


def get_model_string_features(vocab_size: int, feature_size: int) -> Model:
    """Get keras model with string and feature input and single binary out

    Args:
        vocab_size: Datasets vocabulary size
        feature_size: numbers of features used for training

    Return:
        Keras model
    """
    d_type = "float32"
    lstm_input = Input(shape=(None, vocab_size), name="line_input", dtype=d_type)
    bidirectional = Bidirectional(layer=LSTM(units=123, dtype=d_type))
    lstm_branch = bidirectional(lstm_input)

    feature_input = Input(shape=(feature_size, ), name="feature_input", dtype=d_type)

    concatenation = Concatenate()
    joined_features = concatenation([lstm_branch, feature_input])
    dense_a = Dense(units=63, activation='relu', name="dense", dtype=d_type)
    joined_layers = dense_a(joined_features)
    dense_b = Dense(units=1, activation='sigmoid', name="prediction", dtype=d_type)
    output = dense_b(joined_layers)

    model = Model(inputs=[lstm_input, feature_input], outputs=output)

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=DEFAULT_METRICS)

    model.summary()

    return model
