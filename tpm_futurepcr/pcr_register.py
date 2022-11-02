import hashlib

from .tpm_constants import TpmAlgorithm
from .util import to_hex


class PcrRegister:
    def __init__(self, data: bytes, alg=TpmAlgorithm.SHA1):
        self._data = data
        self._alg = alg.name.lower()
        self._count = 0

    @property
    def count(self):
        return self._count

    @property
    def data(self):
        return self._data

    @property
    def alg(self):
        return self._alg

    def __str__(self):
        return to_hex(self._data)

    def __eq__(self, other):
        return self._data == other.data

    def extend_with_hash(self, extend_value):
        self._data = hashlib.new(self._alg, self._data + extend_value).digest()
        self._count = self._count + 1

    def extend_with_data(self, extend_data):
        extend_value = hashlib.new(self._alg, extend_data).digest()
        self.extend_with_hash(extend_value)
