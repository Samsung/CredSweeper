import base64

import pytest

from credsweeper.filters import ValueGrafanaCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueGrafanaCheck:

    @pytest.mark.parametrize("line", ['{"o":"O","n":"N","k":"K","m":{"r":"0"}}'])
    def test_value_grafana_token_p(self, file_path: pytest.fixture, line: str) -> None:
        payload = base64.b64encode(line.encode('ascii')).decode('ascii')
        line_data = get_line_data(file_path, line=f"glc_{payload}", pattern=LINE_VALUE_PATTERN)
        assert ValueGrafanaCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ['{"k":"K","n":"N","id":1}'])
    def test_value_grafana_key_p(self, file_path: pytest.fixture, line: str) -> None:
        payload = base64.b64encode(line.encode('ascii')).decode('ascii')
        line_data = get_line_data(file_path, line=f"{payload}", pattern=LINE_VALUE_PATTERN)
        assert ValueGrafanaCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ['{"K":"K","n":"N","id":1}', '{"0":"O","W":"N","Y":"K","X":{"r":"0"}}'])
    def test_value_grafana_n(self, file_path: pytest.fixture, line: str) -> None:
        payload = base64.b64encode(line.encode('ascii')).decode('ascii')
        line_data = get_line_data(file_path, line=f"{payload}", pattern=LINE_VALUE_PATTERN)
        assert ValueGrafanaCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
        line_data = get_line_data(file_path, line=f"glc_{payload}", pattern=LINE_VALUE_PATTERN)
        assert ValueGrafanaCheck().run(line_data, DUMMY_ANALYSIS_TARGET) is True
