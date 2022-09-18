import unittest
from pathlib import Path
from unittest.mock import patch

from tests.utils import load_current_pcrs, seq_mock_open
from tpm_futurepcr import process_log, compare_pcrs, logging, TpmAlgorithm

logging.basicConfig(level=logging.VERBOSE)


class TestTPM_PredictPCR(unittest.TestCase):
    def setUp(self) -> None:
        self.current_pcrs = load_current_pcrs()

    def test_replay_compare_eventlog_tpm2_BIOS_ROM(self):
        file_mocks = []

        with open('tests/fixtures/tpm_binary_measurements', 'rb') as f:
            file_mocks.append(f.read())

        for i in range(24):
            file_mocks.append(self.current_pcrs[i])

        pcr_list = [0, 1, 2, 3]
        with patch("builtins.open", seq_mock_open(file_mocks)), \
             patch("os.path.exists", side_effect=[True]):
            this_pcrs, next_pcrs, errors = process_log(pcr_list, TpmAlgorithm.SHA256, Path('/unused'), None, False)
            self.assertFalse(compare_pcrs('sha256', this_pcrs, next_pcrs, pcr_list))
