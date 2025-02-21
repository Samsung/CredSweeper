from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F

from credsweeper.common.constants import ML_HUNK
from credsweeper import MlValidator

dtype = torch.float32


class MlModel(nn.Module):

    def __init__(self, line_shape: tuple, variable_shape: tuple, value_shape: tuple, feature_shape: tuple, hp=None):
        super(MlModel, self).__init__()
        if hp is None:
            hp = {}
        value_lstm_dropout_rate = self.__get_hyperparam("value_lstm_dropout_rate", hp)
        line_lstm_dropout_rate = self.__get_hyperparam("line_lstm_dropout_rate", hp)
        variable_lstm_dropout_rate = self.__get_hyperparam("variable_lstm_dropout_rate", hp)
        dense_a_dropout_rate = self.__get_hyperparam("dense_a_lstm_dropout_rate", hp)
        dense_b_dropout_rate = self.__get_hyperparam("dense_b_lstm_dropout_rate", hp)

        self.d_type = torch.float32

        self.line_lstm = nn.LSTM(input_size=line_shape[2],
                                 hidden_size=line_shape[1],
                                 batch_first=True,
                                 bidirectional=True)
        self.variable_lstm = nn.LSTM(input_size=variable_shape[2],
                                     hidden_size=variable_shape[1],
                                     batch_first=True,
                                     bidirectional=True)
        self.value_lstm = nn.LSTM(input_size=value_shape[2],
                                  hidden_size=value_shape[1],
                                  batch_first=True,
                                  bidirectional=True)

        self.line_dropout = nn.Dropout(line_lstm_dropout_rate)
        self.variable_dropout = nn.Dropout(variable_lstm_dropout_rate)
        self.value_dropout = nn.Dropout(value_lstm_dropout_rate)

        dense_units = 2 * MlValidator.MAX_LEN + 2 * 2 * ML_HUNK + feature_shape[1]

        self.dense_a = nn.Linear(dense_units, dense_units)
        self.dense_b = nn.Linear(dense_units, dense_units)
        self.dense_final = nn.Linear(dense_units, 1)

        self.a_dropout = nn.Dropout(dense_a_dropout_rate)
        self.b_dropout = nn.Dropout(dense_b_dropout_rate)

    @staticmethod
    def __get_hyperparam(param_name: str, hyperparameters=None) -> Any:
        if param := hyperparameters.get(param_name):
            if isinstance(param, float):
                print(f"'{param_name}' is {param}")
                return param
            else:
                raise ValueError(f"Unexpected '{param_name}': {param}")
        else:
            raise ValueError(f"'{param_name}' was not defined during initialization of the model.")

    def forward(self, line_input: torch.Tensor, variable_input: torch.Tensor, value_input: torch.Tensor,
                feature_input: torch.Tensor):
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
