import enum

class TpmEventType(enum.IntEnum):
    POST_CODE                       = 0x00000001
    SEPARATOR                       = 0x00000004
    S_CRTM_CONTENTS                 = 0x00000007
    S_CRTM_VERSION                  = 0x00000008
    CPU_MICROCODE                   = 0x00000009
    TABLE_OF_DEVICES                = 0x0000000B

    EFI_VARIABLE_DRIVER_CONFIG      = 0x80000001
    EFI_VARIABLE_BOOT               = 0x80000002
    EFI_BOOT_SERVICES_APPLICATION   = 0x80000003
    EFI_BOOT_SERVICES_DRIVER        = 0x80000004
    EFI_RUNTIME_SERVICES_DRIVER     = 0x80000005
    EFI_GPT_EVENT                   = 0x80000006
    EFI_ACTION                      = 0x80000007
    EFI_PLATFORM_FIRMWARE_BLOB      = 0x80000008
    EFI_HANDOFF_TABLES              = 0x80000009

class TpmPostCode():
    POST_CODE   = b"POST CODE"
    SMM_CODE    = b"SMM CODE"
    ACPI_DATA   = b"ACPI DATA"
    BIS_CODE    = b"BIS CODE"
    UEFI_PI     = b"UEFI PI"
    OPROM       = b"Embedded Option ROM"

class TpmCallEvent():
    CALLING_EFI_APPLICATION         = b"Calling EFI Application from Boot Option"
    RETURNING_FROM_EFI_APPLICATION  = b"Returning from EFI Application from Boot Option"
    EXIT_BOOT_SERVICES_INVOCATION   = b"Exit Boot Services Invocation"
    EXIT_BOOT_SERVICES_FAILED       = b"Exit Boot Services Returned with Failure"
    EXIT_BOOT_SERVICES_SUCCEEDED    = b"Exit Boot Services Returned with Success"

class DevicePathType(enum.IntEnum):
    HardwareDevice = 0x01
    ACPIDevice = 0x02
    MessagingDevice = 0x03
    MediaDevice = 0x04
    BIOSBootDevice = 0x05
    End = 0x7F

class HardwareDevicePathSubtype(enum.IntEnum):
    PCI = 0x01
    PCCARD = 0x02
    MemoryMapped = 0x03
    Vendor = 0x04
    Controller = 0x05
    BMC = 0x06

class ACPIDevicePathSubtype(enum.IntEnum):
    ACPI = 0x01
    ACPIExtended = 0x02
    ACPI_ADR = 0x03

class MessagingDevicePathSubtype(enum.IntEnum):
    ATAPI               = 0x01
    SCSI                = 0x02
    FibreChannel        = 0x03
    IEEE1394            = 0x04
    USB                 = 0x05
    I2O                 = 0x06
    InfiniBand          = 0x09
    Vendor              = 0x0A
    MACAddress          = 0x0B
    IPv4                = 0x0C
    IPv6                = 0x0D
    UART                = 0x0E
    USBClass            = 0x0F
    USBWWID             = 0x10
    DeviceLUN           = 0x11
    SATA                = 0x12
    iSCSI               = 0x13
    VLAN                = 0x14
    FibreChannelEx      = 0x15
    SASEx               = 0x16
    NVMe                = 0x17
    URI                 = 0x18
    UniversalFlashUFS   = 0x19
    SecureDigital       = 0x1A
    Bluetooth           = 0x1B
    WiFi                = 0x1C
    eMMC                = 0x1D
    BluetoothLE         = 0x1E
    DNS                 = 0x1F

class MediaDevicePathSubtype(enum.IntEnum):
    HardDrive           = 0x01
    CDROM               = 0x02
    Vendor              = 0x03
    FilePath            = 0x04
    MediaProtocol       = 0x05
    PIWGFirmware        = 0x06
    PIWGFirmwareVolume  = 0x07
    RelativeOffsetRange = 0x08
    RAMDisk             = 0x09

class BiosBootDevicePathSubtype(enum.IntEnum):
    BiosBootDevice      = 0x01

class BiosBootDeviceType(enum.IntEnum):
    Floppy              = 0x01
    HardDrive           = 0x02
    CDROM               = 0x03
    PCMCIA              = 0x04
    USB                 = 0x05
    EmbeddedNetwork     = 0x06
    BEV                 = 0x80
    Unknown             = 0xFF
