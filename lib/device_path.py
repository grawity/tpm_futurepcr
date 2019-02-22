# https://github.com/tianocore/edk2/blob/master/MdePkg/Include/Protocol/DevicePath.h
import io
from .binary_reader import *
from .tpm_constants import *
from .util import find_mountpoint_by_partuuid

class Parseable():
    @classmethod
    def parse(self, buf):
        return self().parse_into(buf)

class DevicePathItem(dict, Parseable):
    def __init__(self):
        self.type = None
        self.subtype = None
        self.data = None

    def __getattr__(self, key):
        return self[key]

    def __setattr__(self, key, val):
        self[key] = val

    def parse_into(self, buf):
        self.type       = buf.read_u8()
        self.subtype    = buf.read_u8()
        length          = buf.read_u16_le()
        self.data       = buf.read(length - (1 + 1 + 2))

        self.type = DevicePathType(self.type)

        if self.type == DevicePathType.HardwareDevice:
            self.subtype = HardwareDevicePathSubtype(self.subtype)

        elif self.type == DevicePathType.ACPIDevice:
            self.subtype = ACPIDevicePathSubtype(self.subtype)

        elif self.type == DevicePathType.MessagingDevice:
            self.subtype = MessagingDevicePathSubtype(self.subtype)

        elif self.type == DevicePathType.MediaDevice:
            self.subtype = MediaDevicePathSubtype(self.subtype)

            if self.subtype == MediaDevicePathSubtype.HardDrive:
                import uuid
                self.part_uuid = uuid.UUID(bytes_le=self.data[20:20+16])

            elif self.subtype == MediaDevicePathSubtype.FilePath:
                self.file_path = self.data.decode("utf-16le")

        elif self.type == DevicePathType.BIOSBootDevice:
            self.subtype = BiosBootDevicePathSubtype(self.subtype)

        return self

class DevicePath(list, Parseable):
    def parse_into(self, buf):
        while True:
            try:
                item = DevicePathItem.parse(buf)
            except EOFError:
                break
            self.append(item)
        return self

def parse_efi_device_path(buf):
    buf = BinaryReader(io.BytesIO(buf))
    return DevicePath.parse(buf)

def device_path_to_unix_path(path_vec):
    dir_path = None
    unix_path = None
    for pp in path_vec:
        if pp.type == DevicePathType.MediaDevice:
            if pp.subtype == MediaDevicePathSubtype.HardDrive:
                dir_path = find_mountpoint_by_partuuid(pp.part_uuid)
            if pp.subtype == MediaDevicePathSubtype.FilePath:
                file_path = pp.file_path
                unix_path = dir_path + file_path.replace("\\", "/").rstrip("\0")
        if pp.type == DevicePathType.End:
            return unix_path
