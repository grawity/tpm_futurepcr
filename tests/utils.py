from unittest.mock import mock_open


def seq_mock_open(contents: list[str | Exception]):
    mock_opener = mock_open()
    t = []
    for content in contents:
        if not isinstance(content, type):
            t.append(mock_open(read_data=content).return_value)
        else:
            t.append(content)

    mock_opener.side_effect = t
    return mock_opener


def load_current_pcrs() -> dict[int, str]:
    with open('tests/fixtures/QEMU/pcr-sha256') as f:
        return {idx: value for idx, value in enumerate(f.readlines())}
