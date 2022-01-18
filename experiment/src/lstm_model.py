import tensorflow as tf
from tensorflow.keras.layers import Dense, LSTM, Bidirectional, Input, Concatenate
from tensorflow.keras.models import Model

DEFAULT_METRICS = ['acc', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]


def get_model_string_features(vocab_size: int, feature_size: int) -> Model:
    """Get keras model with string and feature input and single binary out

    Args:
        vocab_size: Datasets vocabulary size
        feature_size: numbers of features used for training

    Return:
        Keras model
    """
    lstm_input = Input(shape=(None, vocab_size), name="Value_input")
    lstm_branch = Bidirectional(LSTM(30))(lstm_input)

    feature_input = Input(shape=(feature_size, ), name="Features_input")

    joined_features = Concatenate()([lstm_branch, feature_input])
    x = Dense(100, activation='relu', name="Dense_1")(joined_features)
    x = Dense(1, activation='sigmoid', name="Prediction")(x)

    model = Model([lstm_input, feature_input], x)

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=DEFAULT_METRICS)

    model.summary()

    return model
