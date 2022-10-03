from pathlib import Path
from typing import Iterator

from .tpm_constants import TpmEventType, TpmAlgorithm
from .LogEvent import LogEvent
from .binary_reader import BinaryReader
import tpm_futurepcr.logging as logging

logger = logging.getLogger('event_log')


def _parse_efi_tcg2_header_event(data):
    with BinaryReader(data) as fh:
        log = dict()
        log["magic_signature"] = fh.read(16)
        log["platform_class"] = fh.read_u32()
        log["spec_version_minor"] = fh.read_u8()
        log["spec_version_major"] = fh.read_u8()
        log["spec_errata"] = fh.read_u8()
        log["uintn_size"] = fh.read_u8()
        log["num_algorithms"] = fh.read_u32()
        log["digest_sizes"] = []
        log["digest_sizes_dict"] = {}
        for i in range(log["num_algorithms"]):
            ds = dict()  # struct TCG_EfiSpecIdEventAlgorithmSize
            ds["algorithm_id"] = TpmAlgorithm(fh.read_u16())
            ds["digest_size"] = fh.read_u16()
            log["digest_sizes"].append(ds)
            log["digest_sizes_dict"][ds["algorithm_id"]] = ds["digest_size"]
        log["vendor_info_len"] = fh.read_u8()
        log["vendor_info"] = fh.read(log["vendor_info_len"])
    return log


def enum_log_entries(path: Path = Path("/sys/kernel/security/tpm0/binary_bios_measurements")) -> Iterator[LogEvent]:
    tpm_version = 1
    tcg_hdr = None

    with BinaryReader(path) as fh:
        while True:
            try:
                t = LogEvent(fh, tpm_version, tcg_hdr)
                if tpm_version == 1 and t.pcr_idx == 0 and \
                   t.type == TpmEventType.NO_ACTION and t.data[:15] == b"Spec ID Event03":
                    tpm_version = 2
                    tcg_hdr = _parse_efi_tcg2_header_event(t.data)
                yield t
            except EOFError:
                break


