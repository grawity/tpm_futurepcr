import hashlib

from .util import to_hex


class PcrRegister:
    def __init__(self, data: bytes):
        self._data = data
        self._count = 0

    @property
    def count(self):
        return self._count

    @property
    def data(self):
        return self._data

    def __str__(self):
        return to_hex(self._data)

    def __eq__(self, other):
        return self._data == other.data

    def extend_with_hash(self, extend_value, alg="sha1"):
        self._data = hashlib.new(alg, self._data + extend_value).digest()
        self._count = self._count + 1

    def extend_with_data(self, extend_data, alg="sha1"):
        extend_value = hashlib.new(alg, extend_data).digest()
        self.extend_with_hash(extend_value, alg)
