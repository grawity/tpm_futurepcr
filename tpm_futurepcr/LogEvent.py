from dataclasses import dataclass
from pprint import pformat
from typing import Any

from .device_path import parse_efi_device_path
from .tpm_constants import TpmEventType, TpmAlgorithm
from . import logging
from .util import hexdump, guid_to_UUID
from .binary_reader import ReadFormats as READFMT, BinaryReader

logger = logging.getLogger('log_event')


@dataclass
class EFIBSAData:
    image_location: int
    image_length: int
    image_lt_address: int
    device_path_vec: list[Any]


@dataclass
class LogEvent:
    pcr_idx: int
    type: TpmEventType
    pcr_extend_values: dict[TpmAlgorithm, bytes]
    data: bytes | EFIBSAData

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

    def show(self):
        logger.verbose("\033[1mPCR %d -- Event <%s>\033[m", self.pcr_idx, self.type)
        if self.type == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
            if logger.level == logging.DEBUG:
                for i in hexdump(self.data):
                    logger.debug(i)
                ed = self.parse_efi_bsa_event(self.data)
                logger.debug(pformat(ed))
            else:
                ed = self.parse_efi_bsa_event(self.data)
                logger.verbose("Path vector:")
                for p in ed.device_path_vec:
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

    def __post_init__(self):
        if self.type == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
            with BinaryReader(self.data) as data:
                image_location = data.read(f'{READFMT.PTR}')     # EFI_PHYSICAL_ADDRESS (pointer)
                image_length = data.read(f'{READFMT.SIZE}')      # UINTN (u64/u32 depending on arch)
                image_lt_address = data.read(f'{READFMT.SIZE}')  # UINTN
                device_path_len = data.read(f'{READFMT.SIZE}')   # UINTN
                device_path_vec = parse_efi_device_path(data.read(device_path_len))
                self.data = EFIBSAData(image_location, image_length, image_lt_address, device_path_vec)
