import pytest

success_line_list = ["Crackle4421", "passwd = Crackle4421", "passwd = 'Crackle4421'"]


@pytest.fixture(params=success_line_list)
def success_line(request) -> str:
    return request.param
