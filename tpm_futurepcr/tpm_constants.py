import enum

class TpmAlgorithm(enum.IntEnum):
    # https://trustedcomputinggroup.org/resource/tcg-algorithm-registry/
    RSA             = 0x0001
    TDES            = 0x0003
    SHA1            = 0x0004
    HMAC            = 0x0005
    AES             = 0x0006
    MGF1            = 0x0007
    KEYEDHASH       = 0x0008
    XOR             = 0x000A
    SHA256          = 0x000B
    SHA384          = 0x000C
    SHA512          = 0x000D
    NULL            = 0x0010
    SM3_256         = 0x0012
    SM4             = 0x0013
    RSASSA          = 0x0014
    RSAES           = 0x0015
    RSAPSS          = 0x0016
    OAEP            = 0x0017
    ECDSA           = 0x0018
    ECDH            = 0x0019
    ECDAA           = 0x001A
    SM2             = 0x001B
    ECSCHNORR       = 0x001C
    ECMQV           = 0x001D
    KDF1_SP800_56A  = 0x0020
    KDF2            = 0x0021
    KDF1_SP800_108  = 0x0022
    ECC             = 0x0023
    SYMCIPHER       = 0x0025
    CAMELLIA        = 0x0026
    SHA3_256        = 0x0027
    SHA3_384        = 0x0028
    SHA3_512        = 0x0029
    CMAC            = 0x003F
    CTR             = 0x0040
    OFB             = 0x0041
    CBC             = 0x0042
    CFB             = 0x0043
    ECB             = 0x0044

class TpmEventType(enum.IntEnum):
    # BIOS events <https://www.trustedcomputinggroup.org/wp-content/uploads/TCG_PCClientImplementation_1-21_1_00.pdf#page=98>
    PREBOOT_CERT                    = 0x00000000 # deprecated
    POST_CODE                       = 0x00000001
    UNUSED                          = 0x00000002 # reserved
    NO_ACTION                       = 0x00000003 # noextend
    SEPARATOR                       = 0x00000004 # BIOS: extend 0-7
    ACTION                          = 0x00000005
    EVENT_TAG                       = 0x00000006
    S_CRTM_CONTENTS                 = 0x00000007
    S_CRTM_VERSION                  = 0x00000008
    CPU_MICROCODE                   = 0x00000009
    PLATFORM_CONFIG_FLAGS           = 0x0000000A
    TABLE_OF_DEVICES                = 0x0000000B
    COMPACT_HASH                    = 0x0000000C
    IPL                             = 0x0000000D
    IPL_PARTITION_DATA              = 0x0000000E
    NONHOST_CODE                    = 0x0000000F
    NONHOST_CONFIG                  = 0x00000010
    NONHOST_INFO                    = 0x00000011
    OMIT_BOOT_DEVICE_EVENTS         = 0x00000012

    # UEFI events
    # https://trustedcomputinggroup.org/wp-content/uploads/TCG_EFI_Platform_1_22_Final_-v15.pdf#page=32
    # https://github.com/canonical/tcglog-parser/blob/master/constants.go
    EFI_EVENT_BASE                  = 0x80000000
    EFI_VARIABLE_DRIVER_CONFIG      = 0x80000001
    EFI_VARIABLE_BOOT               = 0x80000002
    EFI_BOOT_SERVICES_APPLICATION   = 0x80000003
    EFI_BOOT_SERVICES_DRIVER        = 0x80000004
    EFI_RUNTIME_SERVICES_DRIVER     = 0x80000005
    EFI_GPT_EVENT                   = 0x80000006
    EFI_ACTION                      = 0x80000007
    EFI_PLATFORM_FIRMWARE_BLOB      = 0x80000008
    EFI_HANDOFF_TABLES              = 0x80000009
    EFI_PLATFORM_FIRMWARE_BLOB2     = 0x8000000A
    EFI_HANDOFF_TABLES2             = 0x8000000B
    EFI_VARIABLE_BOOT2              = 0x8000000C
    EFI_HCRTM_EVENT                 = 0x80000010
    EFI_VARIABLE_AUTHORITY          = 0x800000E0
    EFI_SPDM_FIRMWARE_BLOB          = 0x800000E1
    EFI_SPDM_FIRMWARE_CONFIG        = 0x800000E2

class TpmPostCode():
    POST_CODE   = b"POST CODE"
    SMM_CODE    = b"SMM CODE"
    ACPI_DATA   = b"ACPI DATA"
    BIS_CODE    = b"BIS CODE"
    UEFI_PI     = b"UEFI PI"
    OPROM       = b"Embedded Option ROM"

class TpmEfiActionString():
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
