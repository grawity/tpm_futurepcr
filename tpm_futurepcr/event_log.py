from .binary_reader import BinaryReader
from .device_path import *
from .tpm_constants import TpmAlgorithm
from .util import (to_hex, hexdump)

SHA1_DIGEST_SIZE = 20

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

def parse_efi_tcg2_header_event(buf):
    buf = BinaryReader(io.BytesIO(buf))
    log = {}
    log["magic_signature"]      = buf.read(16)
    log["platform_class"]       = buf.read_u32_le()
    log["spec_version_minor"]   = buf.read_u8()
    log["spec_version_major"]   = buf.read_u8()
    log["spec_errata"]          = buf.read_u8()
    log["uintn_size"]           = buf.read_u8()
    log["num_algorithms"]       = buf.read_u32_le()
    log["digest_sizes"]         = []
    log["digest_sizes_dict"]    = {}
    for i in range(log["num_algorithms"]):
        ds = {} # struct TCG_EfiSpecIdEventAlgorithmSize
        ds["algorithm_id"]  = TpmAlgorithm(buf.read_u16_le())
        ds["digest_size"]   = buf.read_u16_le()
        log["digest_sizes"].append(ds)
        log["digest_sizes_dict"][ds["algorithm_id"]] = ds["digest_size"]
    log["vendor_info_len"]      = buf.read_u8()
    log["vendor_info"]          = buf.read(log["vendor_info_len"])
    return log

def show_log_entry(e):
    print("PCR %d: extend %s" % (e["pcr_idx"], to_hex(e["pcr_extend_value"])))
    event_type = e["event_type"]
    event_type_str = TpmEventType(event_type)
    print("Event type: %08X <%s>" % (event_type, event_type_str))
    event_data = e["event_data"]
    if event_type == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
        hexdump(event_data)
        ed = parse_efi_bsa_event(event_data)
        #pprint(ed)
    else:
        hexdump(event_data, 32)
    print()

# ~/src/linux/include/linux/tpm_eventlog.h
# TPMv1: https://sources.debian.org/src/golang-github-coreos-go-tspi/0.1.1-2/tspi/tpm.go/?hl=44#L44
# TPMv2: https://trustedcomputinggroup.org/wp-content/uploads/EFI-Protocol-Specification-rev13-160330final.pdf

def enum_log_entries(path=None):
    tpm_ver = 1 # the first entry is always in old format
    tcg_hdr = None
    with open(path or "/sys/kernel/security/tpm0/binary_bios_measurements", "rb") as fh:
        rd = BinaryReader(fh)
        while True:
            event = {}
            try:
                # same across both formats
                event["pcr_idx"] = rd.read_u32_le()
                event["event_type"] = rd.read_u32_le()
                event["event_type"] = TpmEventType(event["event_type"])
                if tpm_ver == 1:
                    # section 5.1, SHA1 Event Log Entry Format
                    event["pcr_extend_value"] = rd.read(SHA1_DIGEST_SIZE)
                elif tpm_ver == 2:
                    # section 5.2, Crypto Agile Log Entry Format
                    event["pcr_count"] = rd.read_u32_le()
                    event["pcr_extend_values"] = []
                    event["pcr_extend_values_dict"] = {}
                    for i in range(tcg_hdr["num_algorithms"]):
                        # Spec says it should be safe to just iter over hdr[digest_sizes],
                        # as all entries must have the same algorithms in the same order,
                        # but it does recommend alg_id lookup as the preferred method.
                        pcr_val = {}
                        pcr_val["alg_id"] = TpmAlgorithm(rd.read_u16_le())
                        pcr_val["digest"] = rd.read(tcg_hdr["digest_sizes_dict"][pcr_val["alg_id"]])
                        event["pcr_extend_values"].append(pcr_val)
                        event["pcr_extend_values_dict"][pcr_val["alg_id"]] = pcr_val["digest"]
                        if pcr_val["alg_id"] == TpmAlgorithm.SHA1:
                            event["pcr_extend_value"] = pcr_val["digest"]
                # same across both formats
                event["event_size"] = rd.read_u32_le()
                event["event_data"] = rd.read(event["event_size"])
                yield event
            except EOFError:
                break

            # section 5.3, Event Log Header
            if tpm_ver == 1 \
            and event["pcr_idx"] == 0 \
            and event["event_type"] == TpmEventType.NO_ACTION \
            and event["event_data"][0:15] == b"Spec ID Event03":
                tpm_ver = 2
                tcg_hdr = parse_efi_tcg2_header_event(event["event_data"])
