import hashlib
import os
import signify.fingerprinter
import subprocess


import tpm_futurepcr.logging as logging

logger = logging.getLogger('util')


def to_hex(buf):
    import binascii
    return binascii.hexlify(buf).decode()


def hexdump(buf, max_len=None):
    if max_len is None:
        max_len = len(buf)
    else:
        max_len = min(max_len, len(buf))
    for i in range(0, max_len, 16):
        row = buf[i:i+16]
        hexs = ["%02X" % b for b in row] + ["  "] * 16
        text = [chr(b) if 0x20 < b < 0x7f else "." for b in row] + [" "] * 16
        logger.debug("0x%08x: %s |%s|", i, " ".join(hexs[:16]), "".join(text[:16]))
    if len(buf) > max_len:
        logger.debug("(%d more bytes)", len(buf) - max_len)


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


def hash_pecoff(path, alg="sha1"):
    with open(path, "rb") as fh:
        fpr = signify.fingerprinter.AuthenticodeFingerprinter(fh)
        fpr.add_authenticode_hashers(getattr(hashlib, alg))
        return fpr.hash()[alg]
    return None


def read_pecoff_section(path, section):
    from .binary_reader import BinaryReader
    want_section = section.encode()
    found_size = None
    found_offset = None
    with open(path, "rb") as fh:
        br = BinaryReader(fh)
        # MS-DOS stub
        dos_stub = br.read(0x3c)
        if dos_stub[0:2] != b"MZ":
            raise ValueError("File does not start with MS-DOS MZ magic")
        pe_offset = br.read_u16_le()
        br.seek(pe_offset)
        pe_sig = br.read(4)
        if pe_sig != b"PE\0\0":
            raise ValueError("File does not contain PE signature")
        # COFF header
        target_machine = br.read_u16_le()
        num_sections = br.read_u16_le()
        time_date = br.read_u32_le()
        symtab_offset = br.read_u32_le()
        num_symbols = br.read_u32_le()
        opthdr_size = br.read_u16_le()
        characteristics = br.read_u16_le()
        # Optional PE32 Header
        if opthdr_size:
            _ = br.read(opthdr_size)
        # Section table
        for i in range(num_sections):
            section_name = br.read(8).rstrip(b"\0")
            virtual_size = br.read_u32_le()
            virtual_addr = br.read_u32_le()
            section_size = br.read_u32_le()
            section_offset = br.read_u32_le()
            relocs_offset = br.read_u32_le()
            linenums_offset = br.read_u32_le()
            num_relocs = br.read_u16_le()
            num_linenums = br.read_u16_le()
            characteristics = br.read_u32_le()
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


def find_mountpoint_by_partuuid(partuuid):
    res = subprocess.run(["findmnt", "-S", "PARTUUID=" + str(partuuid).lower(),
                                     "-o", "TARGET", "-r", "-n"],
                         stdout=subprocess.PIPE)
    res.check_returncode()
    return res.stdout.splitlines()[0].decode()
