import io
import struct
from pathlib import Path

_NSIZE = struct.calcsize("@N")
_PSIZE = struct.calcsize("@P")


class ReadFormats:
    U8 = "B"
    U16 = "H"
    U32 = "L"
    U64 = "Q"
    PTR = "Q" if _PSIZE == 8 else "L"
    SIZE = "Q" if _NSIZE == 8 else "L"


class BinaryReader:
    def __init__(self, fh_buf: bytes | Path):
        self.fh = open(fh_buf, "rb") if isinstance(fh_buf, Path) else io.BytesIO(fh_buf)

    def seek(self, pos: int, whence: int = 0):
        return self.fh.seek(pos, whence)

    def read(self, fmt_len: str | int) -> bytes | int | tuple | None:
        length = fmt_len if isinstance(fmt_len, int) else struct.calcsize("<"+fmt_len)
        if length == 0:
            return
        buf = self.fh.read(length)

        if len(buf) == 0:
            raise EOFError(f"Hit EOF after 0/{length} bytes")
        elif len(buf) < length:
            raise IOError(f"Hit EOF after {len(buf)}/{length} bytes")

        if isinstance(fmt_len, str):
            data = struct.unpack_from("<"+fmt_len, buf)
            buf = data[0] if len(data) == 1 else data
        return buf

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if isinstance(self.fh, io.IOBase):
            self.fh.close()
