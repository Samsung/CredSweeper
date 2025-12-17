from typing import List

import numpy as np
from keras import Model  # type: ignore
from sklearn.metrics import f1_score, precision_score, recall_score, log_loss, accuracy_score


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
