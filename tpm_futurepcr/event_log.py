from pathlib import Path
from typing import Iterator

from .LogEvent import LogEvent
from .binary_reader import BinaryReader
import tpm_futurepcr.logging as logging

logger = logging.getLogger('event_log')


def enum_log_entries(path: Path = Path("/sys/kernel/security/tpm0/binary_bios_measurements")) -> Iterator[LogEvent]:
    with BinaryReader(path) as fh:
        while True:
            try:
                yield LogEvent(fh)
            except EOFError:
                break


