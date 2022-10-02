from dataclasses import dataclass, InitVar, field
from pprint import pformat
from typing import Any, ClassVar

from .device_path import parse_efi_device_path
from .tpm_constants import TpmEventType, TpmAlgorithm
from . import logging
from .util import hexdump, guid_to_UUID
from .binary_reader import ReadFormats as READFMT, BinaryReader

logger = logging.getLogger('log_event')

# Reference
# ~/src/linux/include/linux/tpm_eventlog.h
# TPMv1: https://sources.debian.org/src/golang-github-coreos-go-tspi/0.1.1-2/tspi/tpm.go/?hl=44#L44
# TPMv2: https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf


@dataclass
class EFIBSAData:
    image_location: int
    image_length: int
    image_lt_address: int
    device_path_vec: list[Any]

    def __str__(self):
        return self.__dict__.copy()


@dataclass
class LogEvent:
    binary_reader: InitVar[BinaryReader]
    tpm_version: ClassVar[int] = 1
    tcg_hdr: ClassVar[dict] = field(init=False)
    pcr_idx: int = field(init=False)
    type: TpmEventType = field(init=False)
    pcr_extend_values: dict[TpmAlgorithm, bytes] = field(init=False)
    data: bytes | EFIBSAData = field(init=False)

    @staticmethod
    def _parse_efi_variable_event(data):
        # https://docs.microsoft.com/en-us/windows-hardware/test/hlk/testref/trusted-execution-environment-efi-protocol
        with BinaryReader(data) as fh:
            log = dict()
            log["variable_name_guid"] = fh.read(16)
            log["variable_name_uuid"] = guid_to_UUID(log["variable_name_guid"])
            log["unicode_name_len"] = fh.read(f'{READFMT.U64}')
            log["variable_data_len"] = fh.read(f'{READFMT.U64}')
            log["unicode_name_u16"] = fh.read(log["unicode_name_len"] * 2)
            log["variable_data"] = fh.read(log["variable_data_len"])
            log["unicode_name"] = log["unicode_name_u16"].decode("utf-16le")
        return log

    @staticmethod
    def _parse_efi_tcg2_header_event(data):
        with BinaryReader(data) as fh:
            log = dict()
            log["magic_signature"] = fh.read(16)
            log["platform_class"] = fh.read(READFMT.U32)
            log["spec_version_minor"] = fh.read(READFMT.U8)
            log["spec_version_major"] = fh.read(READFMT.U8)
            log["spec_errata"] = fh.read(READFMT.U8)
            log["uintn_size"] = fh.read(READFMT.U8)
            log["num_algorithms"] = fh.read(READFMT.U32)
            log["digest_sizes"] = []
            log["digest_sizes_dict"] = {}
            for i in range(log["num_algorithms"]):
                ds = dict()  # struct TCG_EfiSpecIdEventAlgorithmSize
                ds["algorithm_id"] = TpmAlgorithm(fh.read(READFMT.U16))
                ds["digest_size"] = fh.read(READFMT.U16)
                log["digest_sizes"].append(ds)
                log["digest_sizes_dict"][ds["algorithm_id"]] = ds["digest_size"]
            log["vendor_info_len"] = fh.read(READFMT.U8)
            log["vendor_info"] = fh.read(log["vendor_info_len"])
        return log

    def show(self):
        logger.verbose("\033[1mPCR %d -- Event <%s>\033[m", self.pcr_idx, self.type.name)
        if self.type == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
            if logger.level == logging.DEBUG:
                for i in hexdump(self.data):
                    logger.debug(i)
                ed = str(self.data)
                logger.debug(pformat(ed))
            else:
                logger.verbose("Path vector:")
                for p in self.data.device_path_vec:
                    type_name = getattr(p["type"], "name", str(p["type"]))
                    subtype_name = getattr(p["subtype"], "name", str(p["subtype"]))
                    file_path = p.get("file_path", p["data"])
                    logger.verbose("  * %-20s %-20s %s", type_name, subtype_name, file_path)
        elif self.type in {TpmEventType.EFI_VARIABLE_AUTHORITY,
                            TpmEventType.EFI_VARIABLE_BOOT,
                            TpmEventType.EFI_VARIABLE_DRIVER_CONFIG}:
            if logger.level == logging.DEBUG:
                for i in hexdump(self.data, 64):
                    logger.debug(i)
                ed = self._parse_efi_variable_event(self.data)
                logger.debug(pformat(ed))
            else:
                ed = self._parse_efi_variable_event(self.data)
                logger.verbose("Variable: %r {%s}", ed["unicode_name"], ed["variable_name_uuid"])
        else:
            for i in hexdump(self.data, 64):
                logger.debug(i)

    def __post_init__(self, binary_reader):
        self.pcr_idx = binary_reader.read(READFMT.U32)
        self.type = TpmEventType(binary_reader.read(READFMT.U32))
        self.pcr_extend_values = dict()
        # same across both formats
        if LogEvent.tpm_version == 1:
            # section 5.1, SHA1 Event Log Entry Format
            self.pcr_extend_values[TpmAlgorithm.SHA1] = binary_reader.read(20)
        elif LogEvent.tpm_version == 2:
            # section 5.2, Crypto Agile Log Entry Format
            pcr_count = binary_reader.read(READFMT.U32)
            for i in range(pcr_count):
                # Spec says it should be safe to just iter over hdr[digest_sizes],
                # as all entries must have the same algorithms in the same order,
                # but it does recommend alg_id lookup as the preferred method.
                _alg = binary_reader.read(READFMT.U16)
                alg_id = TpmAlgorithm(_alg)
                self.pcr_extend_values[alg_id] = binary_reader.read(self.tcg_hdr["digest_sizes_dict"][alg_id])

        # same across both formats
        event_size = binary_reader.read(READFMT.U32)
        if self.type == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
            image_location = binary_reader.read(f'{READFMT.PTR}')     # EFI_PHYSICAL_ADDRESS (pointer)
            image_length = binary_reader.read(f'{READFMT.SIZE}')      # UINTN (u64/u32 depending on arch)
            image_lt_address = binary_reader.read(f'{READFMT.SIZE}')  # UINTN
            device_path_len = binary_reader.read(f'{READFMT.SIZE}')   # UINTN
            device_path_vec = parse_efi_device_path(binary_reader.read(device_path_len))
            self.data = EFIBSAData(image_location, image_length, image_lt_address, device_path_vec)
        else:
            self.data = binary_reader.read(event_size)

            if LogEvent.tpm_version == 1 and self.pcr_idx == 0 and \
               self.type == TpmEventType.NO_ACTION and self.data[:15] == b"Spec ID Event03":
                LogEvent.tpm_version = 2
                LogEvent.tcg_hdr = self._parse_efi_tcg2_header_event(self.data)
