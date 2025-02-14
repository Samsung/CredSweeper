from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F

from credsweeper.common.constants import ML_HUNK
from credsweeper import MlValidator

dtype = torch.float32

class MlModel(nn.Module):

    def __init__(
            self,
            line_shape: tuple,
            variable_shape: tuple,
            value_shape: tuple,
            feature_shape: tuple,
            hp=None,
    ):
        super(MlModel, self).__init__()
        if hp is None:
            hp = {}
        value_lstm_dropout_rate = hp.get("value_lstm_dropout_rate", 0.45)
        line_lstm_dropout_rate = hp.get("line_lstm_dropout_rate", 0.45)
        variable_lstm_dropout_rate = hp.get("variable_lstm_dropout_rate", 0.45)
        dense_a_dropout_rate = hp.get("dense_a_lstm_dropout_rate", 0.45)
        dense_b_dropout_rate = hp.get("dense_b_lstm_dropout_rate", 0.45)
        #print(f"Input hyperparameters: {hp}")
        print(f"Run model with parameters: value_lstm_dropout_rate={value_lstm_dropout_rate}, line_lstm_dropout_rate={line_lstm_dropout_rate}, variable_lstm_dropout_rate={variable_lstm_dropout_rate}, dense_a_dropout_rate={dense_a_dropout_rate}, dense_b_dropout_rate={dense_b_dropout_rate}")
        self.d_type = torch.float32

        self.line_lstm = nn.LSTM(input_size=line_shape[2], hidden_size=line_shape[1], batch_first=True, bidirectional=True)
        self.variable_lstm = nn.LSTM(input_size=variable_shape[2], hidden_size=variable_shape[1], batch_first=True, bidirectional=True)
        self.value_lstm = nn.LSTM(input_size=value_shape[2], hidden_size=value_shape[1], batch_first=True, bidirectional=True)

        self.line_dropout = nn.Dropout(line_lstm_dropout_rate)
        self.variable_dropout = nn.Dropout(variable_lstm_dropout_rate)
        self.value_dropout = nn.Dropout(value_lstm_dropout_rate)

        dense_units = 2 * MlValidator.MAX_LEN + 2 * 2 * ML_HUNK + feature_shape[1]

        self.dense_a = nn.Linear(dense_units, dense_units)
        self.dense_b = nn.Linear(dense_units, dense_units)
        self.dense_final = nn.Linear(dense_units, 1)

        self.a_dropout = nn.Dropout(dense_a_dropout_rate)
        self.b_dropout = nn.Dropout(dense_b_dropout_rate)

    def forward(self, line_input, variable_input, value_input, feature_input):
        line_out, _ = self.line_lstm(line_input)
        line_out = self.line_dropout(line_out[:, -1, :])

        variable_out, _ = self.variable_lstm(variable_input)
        variable_out = self.variable_dropout(variable_out[:, -1, :])

        value_out, _ = self.value_lstm(value_input)
        value_out = self.value_dropout(value_out[:, -1, :])

        joined_features = torch.cat((line_out, variable_out, value_out, feature_input), dim=1)

        dense_a = F.relu(self.dense_a(joined_features))
        dense_a = self.a_dropout(dense_a)

        dense_b = F.relu(self.dense_b(dense_a))
        dense_b = self.b_dropout(dense_b)

        output = torch.sigmoid(self.dense_final(dense_b))
        return output


def binary_accuracy(y_pred, y_true):
    y_pred = (y_pred > 0.5).float()
    correct = (y_pred == y_true).float()
    return correct.mean()


def precision(y_pred, y_true):
    y_pred = (y_pred > 0.5).float()
    tp = (y_pred * y_true).sum()
    fp = (y_pred * (1 - y_true)).sum()
    return tp / (tp + fp + 1e-8)


def recall(y_pred, y_true):
    y_pred = (y_pred > 0.5).float()
    tp = (y_pred * y_true).sum()
    fn = ((1 - y_pred) * y_true).sum()
    return tp / (tp + fn + 1e-8)
