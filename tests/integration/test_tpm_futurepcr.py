import unittest
from unittest.mock import patch

from tests.utils import load_current_pcrs, seq_mock_open
from tpm_futurepcr import create_argparser, postprocess_args, process_log, compare_pcrs, logging

logging.basicConfig(level=logging.VERBOSE)


class TestTPM_PredictPCR(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = create_argparser()
        self.current_pcrs = load_current_pcrs()

    def test_replay_compare_eventlog_tpm2_BIOS_ROM(self):
        file_mocks = []

        with open('tests/fixtures/tpm_binary_measurements', 'rb') as f:
            file_mocks.append(f.read())

        for i in range(24):
            file_mocks.append(self.current_pcrs[i])

        args = self.parser.parse_args("-v -L sha256:0,1,2,3".split())
        args = postprocess_args(args)

        with patch("builtins.open", seq_mock_open(file_mocks)), \
             patch("os.path.exists", side_effect=[True]):
            this_pcrs, next_pcrs, errors = process_log(args, args.pcr_list, args.hash_alg.name.lower())
            self.assertFalse(compare_pcrs(args.hash_alg.name.lower(), this_pcrs, next_pcrs, args.pcr_list))
