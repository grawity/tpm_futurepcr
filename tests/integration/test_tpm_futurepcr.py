import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess as sp

from tests.utils import load_current_pcrs, seq_mock_open
from tpm_futurepcr import process_log, compare_pcrs, logging, TpmAlgorithm

logging.basicConfig(level=logging.VERBOSE)


class TestTPM_FuturePCR(unittest.TestCase):
    def setUp(self) -> None:
        self.current_pcrs = load_current_pcrs()

    def test_CLI_arguments_parsing(self):
        subtests_fail = [
            "-H sha256 -L sha256:24",
            "-H SHA256 -L sha256:0",
            "-H sha1 -L sha256:0",
            "-L sha1:3+sha256:1"
        ]

        subtests_succeed = [
            "-H sha256 -L 0 --log-path /dev/null",
            "-L sha256:0 --log-path /dev/null",
        ]

        for tst in subtests_fail:
            with self.subTest("Test fails", tst=tst):
                cmdline = f"python ./tpm_futurepcr.py {tst}".split()
                with self.assertRaises(sp.CalledProcessError):
                    t = sp.check_output(cmdline, encoding='utf-8')
                    self.assertTrue(t[0].startswith("usage"))

        for tst in subtests_succeed:
            with self.subTest("Test succeeds", tst=tst):
                cmdline = f"python ./tpm_futurepcr.py {tst}".split()
                with self.assertRaises(sp.CalledProcessError):
                    t = sp.check_output(cmdline, encoding='utf-8')
                    self.assertTrue(t[0].startswith("ERROR:tpm_futurepcr:Log contains no entries"))

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
