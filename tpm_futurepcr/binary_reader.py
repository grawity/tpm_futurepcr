import io
import struct
from pathlib import Path
from typing import Any

_NSIZE = struct.calcsize("@N")
_PSIZE = struct.calcsize("@P")


class BinaryReader:
    def __init__(self, fh_buf: bytes | Path):
        self.fh = open(fh_buf, "rb") if isinstance(fh_buf, Path) else io.BytesIO(fh_buf)

    def seek(self, pos: int, whence: int = 0) -> int:
        return self.fh.seek(pos, whence)

    def _read(self, fmt_len: str | int) -> Any:
        length = fmt_len if isinstance(fmt_len, int) else struct.calcsize(fmt_len)
        if length == 0:
            return b''
        buf = self.fh.read(length)

        if len(buf) == 0:
            raise EOFError(f"Hit EOF after 0/{length} bytes")
        elif len(buf) < length:
            raise IOError(f"Hit EOF after {len(buf)}/{length} bytes")

        if isinstance(fmt_len, str):
            data = struct.unpack_from(fmt_len, buf)
            buf = data[0] if len(data) == 1 else data
        return buf

    def read(self, size: int) -> bytes:
        return self._read(size)

    def read_u8(self) -> int:
        return self._read("<B")

    def read_u16(self) -> int:
        return self._read("<H")

    def read_u32(self) -> int:
        return self._read("<L")

    def read_u64(self) -> int:
        return self._read("<Q")

    def read_ptr(self) -> int:
        return self._read("<Q" if _PSIZE == 8 else "<L")

    def read_size(self) -> int:
        return self._read("<Q" if _NSIZE == 8 else "<L")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if isinstance(self.fh, io.IOBase):
            self.fh.close()
