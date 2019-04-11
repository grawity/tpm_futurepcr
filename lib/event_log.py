from .binary_reader import BinaryReader
from .device_path import *
from .util import (to_hex, hexdump)

SHA1_DIGEST_SIZE = 20
SHA512_DIGEST_SIZE = 64

def parse_efi_bsa_event(buf):
    buf = BinaryReader(io.BytesIO(buf))
    log = {}
    log["image_location"]   = buf.read_ptr_le() # EFI_PHYSICAL_ADDRESS (pointer)
    log["image_length"]     = buf.read_size_le() # UINTN (u64/u32 depending on arch)
    log["image_lt_address"] = buf.read_size_le() # UINTN
    log["device_path_len"]  = buf.read_size_le() # UINTN
    log["device_path"]      = buf.read(log["device_path_len"])
    log["device_path_vec"]  = parse_efi_device_path(log["device_path"])
    return log

def show_log_entry(e):
    print("PCR %d: extend %s" % (e["pcr_idx"], to_hex(e["pcr_extend_value"])))
    event_type = e["event_type"]
    event_type_str = TpmEventType(event_type)
    print("Event type: %x <%s>" % (event_type, event_type_str))
    event_data = e["event_data"]
    if event_type == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
        hexdump(event_data)
        ed = parse_efi_bsa_event(event_data)
        #pprint(ed)
    else:
        hexdump(event_data[:32])
        if len(event_data) > 32:
            print("(%d more bytes)" % (len(event_data) - 32))
    print()

# ~/src/linux/include/linux/tpm_eventlog.h
# TPMv1: https://sources.debian.org/src/golang-github-coreos-go-tspi/0.1.1-2/tspi/tpm.go/?hl=44#L44

def enum_log_entries():
    tpm_ver = 1 # Linux always exports v1 SHA1-only events for now
    with open("/sys/kernel/security/tpm0/binary_bios_measurements", "rb") as fh:
        rd = BinaryReader(fh)
        while True:
            event = {}
            try:
                event["pcr_idx"] = rd.read_u32_le()
                event["event_type"] = rd.read_u32_le()
                event["event_type"] = TpmEventType(event["event_type"])
                if tpm_ver == 1:
                    event["pcr_extend_value"] = rd.read(SHA1_DIGEST_SIZE)
                elif tpm_ver == 2:
                    event["pcr_count"] = rd.read_u32_le()
                    num_banks = 3
                    event["pcr_extend_values"] = {}
                    for i in range(num_banks):
                        event["pcr_extend_values"][i] = {}
                        event["pcr_extend_values"][i]["alg_id"] = rd.read_u16_le()
                        event["pcr_extend_values"][i]["digest"] = rd.read(SHA512_DIGEST_SIZE)
                event["event_size"] = rd.read_u32_le()
                event["event_data"] = rd.read(event["event_size"])
                yield event
            except EOFError:
                break
