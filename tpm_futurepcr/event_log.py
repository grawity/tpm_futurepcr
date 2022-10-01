from pathlib import Path
from typing import Iterator

from .LogEvent import LogEvent
from .binary_reader import BinaryReader
from .tpm_constants import TpmAlgorithm, TpmEventType
from .binary_reader import ReadFormats as READFMT
import tpm_futurepcr.logging as logging

logger = logging.getLogger('event_log')


def parse_efi_tcg2_header_event(buf):
    with BinaryReader(buf) as buf:
        log = {}
        log["magic_signature"]      = buf.read(16)
        log["platform_class"]       = buf.read(READFMT.U32)
        log["spec_version_minor"]   = buf.read(READFMT.U8)
        log["spec_version_major"]   = buf.read(READFMT.U8)
        log["spec_errata"]          = buf.read(READFMT.U8)
        log["uintn_size"]           = buf.read(READFMT.U8)
        log["num_algorithms"]       = buf.read(READFMT.U32)
        log["digest_sizes"]         = []
        log["digest_sizes_dict"]    = {}
        for i in range(log["num_algorithms"]):
            ds = {} # struct TCG_EfiSpecIdEventAlgorithmSize
            ds["algorithm_id"]  = TpmAlgorithm(buf.read(READFMT.U16))
            ds["digest_size"]   = buf.read(READFMT.U16)
            log["digest_sizes"].append(ds)
            log["digest_sizes_dict"][ds["algorithm_id"]] = ds["digest_size"]
        log["vendor_info_len"]      = buf.read(READFMT.U8)
        log["vendor_info"]          = buf.read(log["vendor_info_len"])
    return log


# ~/src/linux/include/linux/tpm_eventlog.h
# TPMv1: https://sources.debian.org/src/golang-github-coreos-go-tspi/0.1.1-2/tspi/tpm.go/?hl=44#L44
# TPMv2: https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf

def enum_log_entries(path: Path = Path("/sys/kernel/security/tpm0/binary_bios_measurements")) -> Iterator[LogEvent]:
    tpm_ver = 1  # the first entry is always in old format
    tcg_hdr = None
    with BinaryReader(path) as fh:
        while True:
            try:
                pcr_idx = fh.read(READFMT.U32)
                event_type = TpmEventType(fh.read(READFMT.U32))
                pcr_extend_values = dict()
                # same across both formats
                if tpm_ver == 1:
                    # section 5.1, SHA1 Event Log Entry Format
                    pcr_extend_values[TpmAlgorithm.SHA1] = fh.read(20)
                elif tpm_ver == 2:
                    # section 5.2, Crypto Agile Log Entry Format
                    pcr_count = fh.read(READFMT.U32)
                    for i in range(pcr_count):
                        # Spec says it should be safe to just iter over hdr[digest_sizes],
                        # as all entries must have the same algorithms in the same order,
                        # but it does recommend alg_id lookup as the preferred method.
                        alg_id = TpmAlgorithm(fh.read(READFMT.U16))
                        pcr_extend_values[alg_id] = fh.read(tcg_hdr["digest_sizes_dict"][alg_id])
                # same across both formats
                event_size = fh.read(READFMT.U32)
                data = fh.read(event_size)

                # section 5.3, Event Log Header
                if tpm_ver == 1 and pcr_idx == 0 and event_type == TpmEventType.NO_ACTION \
                   and data[:15] == b"Spec ID Event03":
                    tpm_ver = 2
                    tcg_hdr = parse_efi_tcg2_header_event(data)

                yield LogEvent(pcr_idx, event_type, pcr_extend_values, data)
            except EOFError:
                break


