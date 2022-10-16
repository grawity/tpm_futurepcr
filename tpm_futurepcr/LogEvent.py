import hashlib
from abc import abstractmethod, ABC
from dataclasses import dataclass, InitVar, field
import dataclasses
from pathlib import Path
from pprint import pformat
from typing import Any

import signify

from .device_path import parse_efi_device_path
from .tpm_constants import TpmEventType, TpmAlgorithm, DevicePathType, MediaDevicePathSubtype
from . import logging
from .util import hexdump, guid_to_UUID, find_mountpoint_by_partuuid
from .binary_reader import BinaryReader

logger = logging.getLogger('log_event')

# Reference
# ~/src/linux/include/linux/tpm_eventlog.h
# TPMv1: https://sources.debian.org/src/golang-github-coreos-go-tspi/0.1.1-2/tspi/tpm.go/?hl=44#L44
# TPMv2: https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf


@dataclass
class BaseEvent(ABC):
    binary_reader: InitVar[BinaryReader]
    tpm_version: InitVar[int]
    tcg_hdr: InitVar[dict | None]
    pcr_idx: int
    type: TpmEventType
    pcr_extend_values: dict[TpmAlgorithm, bytes] = field(init=False)
    data: bytes = field(init=False)

    def __post_init__(self, binary_reader: BinaryReader, tpm_version: int, tcg_hdr: dict | None):
        self.pcr_extend_values = dict()
        # same across both formats
        if tpm_version == 1:
            # section 5.1, SHA1 Event Log Entry Format
            self.pcr_extend_values[TpmAlgorithm.SHA1] = binary_reader.read(20)
        elif tpm_version == 2:
            # section 5.2, Crypto Agile Log Entry Format
            pcr_count = binary_reader.read_u32()
            for i in range(pcr_count):
                # Spec says it should be safe to just iter over hdr[digest_sizes],
                # as all entries must have the same algorithms in the same order,
                # but it does recommend alg_id lookup as the preferred method.
                _alg = binary_reader.read_u16()
                alg_id = TpmAlgorithm(_alg)
                self.pcr_extend_values[alg_id] = binary_reader.read(tcg_hdr["digest_sizes_dict"][alg_id])
        self._read_data(binary_reader)

    @abstractmethod
    def _read_data(self, binary_reader: BinaryReader):
        pass

    @abstractmethod
    def next_extend_value(self, current_extend_value: bytes, hash_alg: str = "sha1") -> bytes:
        pass


@dataclass
class GenericEvent(BaseEvent):

    def __post_init__(self, binary_reader: BinaryReader, tpm_version: int, tcg_hdr: dict | None):
        super().__post_init__(binary_reader, tpm_version, tcg_hdr)

    def _read_data(self, binary_reader: BinaryReader):
        event_size = binary_reader.read_u32()
        self.data = binary_reader.read(event_size)

    def next_extend_value(self, current_extend_value: bytes, hash_alg: str = "sha1") -> bytes:
        return current_extend_value

    @staticmethod
    def _parse_efi_variable_event(data):
        # https://docs.microsoft.com/en-us/windows-hardware/test/hlk/testref/trusted-execution-environment-efi-protocol
        with BinaryReader(data) as fh:
            log = dict()
            log["variable_name_guid"] = fh.read(16)
            log["variable_name_uuid"] = guid_to_UUID(log["variable_name_guid"])
            log["unicode_name_len"] = fh.read_u64()
            log["variable_data_len"] = fh.read_u64()
            log["unicode_name_u16"] = fh.read(log["unicode_name_len"] * 2)
            log["variable_data"] = fh.read(log["variable_data_len"])
            log["unicode_name"] = log["unicode_name_u16"].decode("utf-16le")
        return log

    def show(self):
        logger.verbose("\033[1mPCR %d -- Event <%s>\033[m", self.pcr_idx, self.type.name)
        if self.type in {TpmEventType.EFI_VARIABLE_AUTHORITY,
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


@dataclass(frozen=True)
class _EFIBSAData:
    image_location: int
    image_length: int
    image_lt_address: int
    device_path_vec: list[Any]


@dataclass
class EFIBSAEvent(BaseEvent):
    substitute_bsa_unix_path: dict
    allow_unexpected_bsa: bool
    unix_path: Path = field(init=False, default=None)
    data: _EFIBSAData = field(init=False)

    def __post_init__(self, binary_reader, tpm_version, tcg_hdr):
        super().__post_init__(binary_reader, tpm_version, tcg_hdr)

    def _read_data(self, binary_reader: BinaryReader):
        # the first 4 bytes are always the event size
        binary_reader.read_u32()

        # same across both format
        image_location = binary_reader.read_ptr()     # EFI_PHYSICAL_ADDRESS (pointer)
        image_length = binary_reader.read_size()      # UINTN (u64/u32 depending on arch)
        image_lt_address = binary_reader.read_size()  # UINTN
        device_path_len = binary_reader.read_size()   # UINTN
        device_path_vec = parse_efi_device_path(binary_reader.read(device_path_len))
        self.data = _EFIBSAData(image_location, image_length, image_lt_address, device_path_vec)

        unix_path = self._device_path_to_unix_path()
        if unix_path is None:
            # This might be a firmware item such as the boot menu.
            if not self.allow_unexpected_bsa:
                logger.error("Unexpected boot events found. Binding to these PCR values "
                             "is not advised, as it might be difficult to reproduce this state "
                             "later. Exiting.")
                exit(1)
            logger.warning("couldn't map EfiBootServicesApplication event to a Linux path")
        self.unix_path = self.substitute_bsa_unix_path.get(unix_path, unix_path)

    def _device_path_to_unix_path(self) -> Path | None:
        dir_path = None
        unix_path = None
        for pp in self.data.device_path_vec:
            if pp.type == DevicePathType.MediaDevice:
                if pp.subtype == MediaDevicePathSubtype.HardDrive:
                    dir_path = find_mountpoint_by_partuuid(pp.part_uuid)
                    if not dir_path:
                        raise Exception("could not find mountpoint for partuuid %r" % pp.part_uuid)
                if pp.subtype == MediaDevicePathSubtype.FilePath:
                    unix_path = dir_path / Path(pp.file_path)
            if pp.type == DevicePathType.End:
                break
        return unix_path

    def show(self):
        if logger.level == logging.DEBUG:
            for i in hexdump(self.data):
                logger.debug(i)
            ed = dataclasses.asdict(self.data)
            logger.debug(pformat(ed))
        else:
            logger.verbose("Path vector:")
            for p in self.data.device_path_vec:
                type_name = getattr(p["type"], "name", str(p["type"]))
                subtype_name = getattr(p["subtype"], "name", str(p["subtype"]))
                file_path = p.get("file_path", p["data"])
                logger.verbose("  * %-20s %-20s %s", type_name, subtype_name, file_path)

    def _hash_pecoff(self, hash_alg="sha1"):
        try:
            with open(self.unix_path, "rb") as fh:
                fpr = signify.fingerprinter.AuthenticodeFingerprinter(fh)
                fpr.add_authenticode_hashers(getattr(hashlib, hash_alg))
                return fpr.hash()[hash_alg]
        except FileNotFoundError:
            logger.info("File %s could not be opened. Continuing with the log-provided extend value", self.unix_path)
            raise ValueError

    def next_extend_value(self, current_extend_value: bytes, hash_alg: str = "sha1") -> bytes:
        return self._hash_pecoff(hash_alg)


def logEventFactory(binary_reader, tpm_version, tcg_hdr, substitute_bsa_unix_path, allow_unexpected_bsa):
    pcr_idx = binary_reader.read_u32()
    type = TpmEventType(binary_reader.read_u32())

    if type == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
        return EFIBSAEvent(binary_reader, tpm_version, tcg_hdr, pcr_idx, type, substitute_bsa_unix_path, allow_unexpected_bsa)
    else:
        return GenericEvent(binary_reader, tpm_version, tcg_hdr, pcr_idx, type)
