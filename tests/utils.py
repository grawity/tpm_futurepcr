from unittest.mock import mock_open


def seq_mock_open(contents: list[str]):
    mock_opener = mock_open()
    mock_opener.side_effect = [mock_open(read_data=content).return_value for content in contents]

    return mock_opener


def load_current_pcrs() -> dict[int, str]:
    with open('tests/resources/pcr-sha256') as f:
        return {idx: value for idx, value in enumerate(f.readlines())}
