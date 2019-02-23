import os
import struct
import sys

class BinaryReader():
    def __init__(self, fh):
        self.fh = fh
        self._N_size = struct.calcsize("@N")
        self._P_size = struct.calcsize("@P")

    def _debug(self, typ, data):
        if os.environ.get("DEBUG"):
            c_on = "\033[33m" if sys.stdout.isatty() else ""
            c_off = "\033[m" if sys.stdout.isatty() else ""
            print(c_on, "#", typ, repr(data), c_off)
        return data

    def read(self, length):
        buf = self.fh.read(length)
        if len(buf) < length:
            if len(buf) == 0:
                raise EOFError("Hit EOF after 0/%d bytes" % length)
            else:
                raise IOError("Hit EOF after %d/%d bytes" % (len(buf), length))
        return self._debug("raw[%d]" % length, buf)

    def _read_fmt(self, length, fmt, typ):
        buf = self.fh.read(length)
        if len(buf) < length:
            if len(buf) == 0:
                raise EOFError("Hit EOF after 0/%d bytes" % length)
            else:
                raise IOError("Hit EOF after %d/%d bytes" % (len(buf), length))
        data, = struct.unpack(fmt, buf)
        return self._debug(typ, data)

    def read_u8(self):
        return self._read_fmt(1, ">B", "byte")

    def read_u16_le(self):
        return self._read_fmt(2, "<H", "short")

    def read_u32_le(self):
        return self._read_fmt(4, "<L", "long")

    def read_u64_le(self):
        return self._read_fmt(8, "<Q", "quad")

    def read_ptr(self):
        return self._read_fmt(self._P_size, "@P", "ptr")

    def read_size(self):
        return self._read_fmt(self._N_size, "@N", "size")
