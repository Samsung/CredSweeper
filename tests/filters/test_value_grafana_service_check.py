import pytest

from credsweeper.filters import ValueGrafanaServiceCheck
from tests.filters.conftest import LINE_VALUE_PATTERN, DUMMY_ANALYSIS_TARGET
from tests.test_utils.dummy_line_data import get_line_data


class TestValueGrafanaServiceCheck:
    @pytest.mark.parametrize("line", ["glsa_DuMmY-T0K3N-f0R-tHe-Te5t-CRC32Ok_770c8cda"])
    def test_value_sgrafana_service_check_p(self, file_path: pytest.fixture, line: str) -> None:
        glsa_line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueGrafanaServiceCheck().run(glsa_line_data, DUMMY_ANALYSIS_TARGET) is False

    @pytest.mark.parametrize("line", ["glpl_DuMmY-T0K3N-f0R-tHe-Te5t-CRC32Ok_770c8CdA"])
    def test_value_sgrafana_service_check_n(self, file_path: pytest.fixture, line: str) -> None:
        glsa_line_data = get_line_data(file_path, line=line, pattern=LINE_VALUE_PATTERN)
        assert ValueGrafanaServiceCheck().run(glsa_line_data, DUMMY_ANALYSIS_TARGET) is True
