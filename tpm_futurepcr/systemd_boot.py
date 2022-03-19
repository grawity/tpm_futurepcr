import os
from .util import (
    find_mountpoint_by_partuuid,
    read_efi_variable,
    read_pecoff_section,
)

EFIVAR_GUID_REDHAT = "4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"

def loader_get_esp_partuuid():
    buf = read_efi_variable("LoaderDevicePartUUID", EFIVAR_GUID_REDHAT)
    return buf.decode("utf-16le").rstrip("\0")

def loader_get_current_entry():
    buf = read_efi_variable("LoaderEntrySelected", EFIVAR_GUID_REDHAT)
    return buf.decode("utf-16le").rstrip("\0")

def _to_efi_path(path):
    # kinda match systemd.git:src/boot/efi/util.c:stra_to_path()
    # (except for the utf16 part, that'll be done on the whole cmdline)
    path = path.replace("/", "\\")
    if not path.startswith("\\"):
        path = "\\" + path
    return path

def loader_parse_config(name, esp=None):
    # match systemd.git:src/boot/efi/boot.c:line_get_key_value()
    esp = esp or "/boot"
    path = os.path.join(esp, "loader/entries/%s.conf" % name)
    config = []
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if (not line) or (line[0] == "#"):
                continue
            try:
                key, val = line.split(None, 1)
            except ValueError:
                continue
            if val[0] == "\"" and val[-1] == "\"":
                val = val[1:-1]
            config.append((key, val))
    return config

def loader_get_cmdline(entry, esp=None):
    # match systemd.git:src/boot/efi/boot.c:config_entry_add_from_file()
    config = loader_parse_config(entry, esp)
    initrd = []
    options = []
    for key, val in config:
        if key == "initrd":
            initrd.append("initrd=" + _to_efi_path(val))
        elif key == "options":
            options.append(val)
    return " ".join([*initrd, *options])

def sd_stub_get_cmdline(path):
    """
    Get the .cmdline section from a systemd EFI stub "unified image".
    """
    # Match systemd.git:src/boot/efi/boot.c:config_entry_add_linux()
    cmdline = read_pecoff_section(path, ".cmdline").decode("utf-8")
    # Chomp a single trailing newline
    if cmdline[-1] == "\n":
        cmdline = cmdline[:-1]
    return cmdline

def loader_get_next_cmdline(last_efi_binary=None):
    try:
        sd_stub_present = read_efi_variable("StubInfo", EFIVAR_GUID_REDHAT)
    except FileNotFoundError:
        sd_stub_present = None

    if sd_stub_present:
        # Booted using mksignkernels/systemd-stub, so the cmdline is embedded in
        # the kernel .efi binary. We don't know its path so assume it's the last
        # binary we've seen in the event log.
        if last_efi_binary:
            return sd_stub_get_cmdline(last_efi_binary)
        else:
            raise Exception("systemd-stub is present, but no EFI binary traced")
    else:
        entry = loader_get_current_entry()
        esp = find_mountpoint_by_partuuid(loader_get_esp_partuuid())
        return loader_get_cmdline(entry, esp)

def loader_encode_pcr8(cmdline):
    """
    Encode kernel command line the same way systemd-stub does it before measuring.
    """
    return (cmdline + "\0").encode("utf-16le")

def loader_decode_pcr8(cmdline):
    """
    Reverse the encoding for a kernel command line we've read from EV_IPL.
    """
    assert(cmdline.endswith(b"\0\0"))
    return cmdline.decode("utf-16le")[:-1]
