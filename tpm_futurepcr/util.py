import hashlib
import os
import subprocess as sp
import uuid
from pathlib import Path

from .binary_reader import BinaryReader

import tpm_futurepcr.logging as logging

logger = logging.getLogger('util')


def to_hex(buf):
    import binascii
    return binascii.hexlify(buf).decode()


def hexdump(buf, max_len=None):
    # max_len must be smaller than len(buf), if defined
    max_len = min(max_len or len(buf), len(buf))

    hexdump_contents = []
    # print the hex codes and their ascii representation
    for i in range(0, max_len, 16):
        row = buf[i:i+16]
        hexs = ["  "] * 16 if len(row) < 16 else []
        text = ["  "] * 16 if len(row) < 16 else []
        hexs[:len(row)] = ["%02X" % b for b in row]
        text[:len(row)] = [chr(b) if 0x20 < b < 0x7f else "." for b in row]
        hexdump_contents.append(f'0x{i:08x}: {" ".join(hexs)} |{"".join(text)}|')

    # notify the user in case there were bytes left unprinted
    if len(buf) > max_len:
        hexdump_contents.append(f"({len(buf) - max_len} more bytes)")

    return hexdump_contents


def guid_to_UUID(buf):
    import struct
    import uuid
    buf = struct.pack(">LHH8B", *struct.unpack("<LHH8B", buf))
    return uuid.UUID(bytes=buf)


def hash_bytes(buf, alg="sha1"):
    h = hashlib.new(alg)
    h.update(buf)
    return h.digest()


def hash_file(path, alg="sha1"):
    h = hashlib.new(alg)
    with open(path, "rb") as fh:
        buf = True
        buf_size = 4 * 1024 * 1024
        while buf:
            buf = fh.read(buf_size)
            h.update(buf)
    return h.digest()


def read_pecoff_section(path: Path, section: bytes):
    want_section = section.encode()
    found_size = None
    found_offset = None
    with BinaryReader(path) as br:

        # MS-DOS stub
        dos_stub = br.read(0x3c)
        if dos_stub[0:2] != b"MZ":
            raise ValueError("File does not start with MS-DOS MZ magic")
        pe_offset = br.read_u16()
        br.seek(pe_offset)
        pe_sig = br.read(4)
        if pe_sig != b"PE\0\0":
            raise ValueError("File does not contain PE signature")
        # COFF header
        target_machine = br.read_u16()
        num_sections = br.read_u16()
        time_date = br.read_u32()
        symtab_offset = br.read_u32()
        num_symbols = br.read_u32()
        opthdr_size = br.read_u16()
        characteristics = br.read_u16()
        # Optional PE32 Header
        if opthdr_size:
            br.seek(opthdr_size)
        # Section table
        for i in range(num_sections):
            section_name = br.read(8).rstrip(b"\0")
            virtual_size = br.read_u32()
            virtual_addr = br.read_u32()
            section_size = br.read_u32()
            section_offset = br.read_u32()
            relocs_offset = br.read_u32()
            linenums_offset = br.read_u32()
            num_relocs = br.read_u16()
            num_linenums = br.read_u16()
            characteristics = br.read_u32()
            if section_name == want_section:
                found_size = min(section_size, virtual_size)
                found_offset = section_offset
        if found_size is None:
            raise ValueError("File did not contain a section named %r" % (section_name))
        # The section
        br.seek(found_offset)
        data = br.read(found_size)
        return data


def read_efi_variable(name, guid):
    path = "/sys/firmware/efi/efivars/%s-%s" % (name, guid)
    with open(path, "rb") as fh:
        buf = fh.read()
        return buf[4:]


def is_tpm2():
    return os.path.exists("/dev/tpmrm0")


def in_path(exe):
    for p in os.environ["PATH"].split(":"):
        if p and os.path.exists("%s/%s" % (p, exe)):
            return True
    return False


def find_mountpoint_by_partuuid(partuuid: uuid.UUID) -> Path:
    res = sp.check_output(f"findmnt -S PARTUUID={str(partuuid).lower()} -o TARGET -r -n".split())
    return Path(res.split(maxsplit=1)[0].decode())
