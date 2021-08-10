import struct

class BinaryReader():
    def __init__(self, fh):
        self.fh = fh
        self._N_size = struct.calcsize("@N")
        self._P_size = struct.calcsize("@P")

    def seek(self, pos, whence=0):
        return self.fh.seek(pos, whence)

    def read(self, length):
        buf = self.fh.read(length)
        if len(buf) < length:
            if len(buf) == 0:
                raise EOFError("Hit EOF after 0/%d bytes" % length)
            else:
                raise IOError("Hit EOF after %d/%d bytes" % (len(buf), length))
        return buf

    def _read_fmt(self, length, fmt):
        buf = self.fh.read(length)
        if len(buf) < length:
            if len(buf) == 0:
                raise EOFError("Hit EOF after 0/%d bytes" % length)
            else:
                raise IOError("Hit EOF after %d/%d bytes" % (len(buf), length))
        data, = struct.unpack(fmt, buf)
        return data

    def read_u8(self):
        return self._read_fmt(1, ">B")

    def read_u16_le(self):
        return self._read_fmt(2, "<H")

    def read_u32_le(self):
        return self._read_fmt(4, "<L")

    def read_u64_le(self):
        return self._read_fmt(8, "<Q")

    def read_ptr(self):
        return self._read_fmt(self._P_size, "@P")

    def read_size(self):
        return self._read_fmt(self._N_size, "@N")

    def read_ptr_le(self):
        return self._read_fmt(self._P_size, "<Q" if self._P_size == 8 else "<L")

    def read_size_le(self):
        return self._read_fmt(self._N_size, "<Q" if self._N_size == 8 else "<L")
