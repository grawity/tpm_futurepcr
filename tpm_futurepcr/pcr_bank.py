import hashlib
import os
import subprocess

from .util import is_tpm2, in_path

NUM_PCRS = 24

def read_current_pcrs(alg="sha1"):
    pcr_size = hashlib.new(alg).digest_size
    if os.path.exists("/sys/class/tpm/tpm0/pcr-%s/0" % alg):
        # New sysfs exports in kernel v5.12
        pcrs = {}
        for idx in range(NUM_PCRS):
            with open("/sys/class/tpm/tpm0/pcr-%s/%d" % (alg, idx), "r") as fh:
                buf = fh.read().strip()
                pcrs[idx] = bytes.fromhex(buf)
        return pcrs
    elif is_tpm2():
        if in_path("tpm2_pcrread"): # tpm2-utils 4.0 or later
            cmd = ["tpm2_pcrread", alg, "-Q", "-o", "/dev/stdout"]
        elif in_path("tpm2_pcrlist"): # tpm2-utils 3.x
            cmd = ["tpm2_pcrlist", "-L", alg, "-Q", "-o", "/dev/stdout"]
        else:
            # TODO: try using IBM TSS tools
            raise Exception("tpm2_pcrread or tpm2_pcrlist not found")
        pcrs = {}
        with subprocess.Popen(cmd, stdout=subprocess.PIPE) as proc:
            if proc.wait() != 0:
                raise subprocess.CalledProcessError(proc.returncode, proc.args)
            for idx in range(NUM_PCRS):
                pcrs[idx] = proc.stdout.read(pcr_size)
        return pcrs
    else:
        if alg != "sha1":
            raise Exception("TPM v1 only supports the SHA1 PCR bank")
        pcrs = {}
        with open("/sys/class/tpm/tpm0/pcrs", "r") as fh:
            for line in fh:
                if line.startswith("PCR-"):
                    idx, buf = line.strip().split(": ")
                    idx = int(idx[4:], 10)
                    pcrs[idx] = bytes.fromhex(buf)
        return pcrs

def extend_pcr_with_hash(pcr_value, extend_value, alg="sha1"):
    pcr_value = hashlib.new(alg, pcr_value + extend_value).digest()
    return pcr_value

def extend_pcr_with_data(pcr_value, extend_data, alg="sha1"):
    extend_value = hashlib.new(alg, extend_data).digest()
    return extend_pcr_with_hash(pcr_value, extend_value)

class PcrBank():
    NUM_PCRS = 24

    def __init__(self, alg="sha1"):
        self.hash_alg = alg
        self.pcr_size = hashlib.new(alg).digest_size
        self.pcrs = {idx: (b"\xFF" if (17 <= idx <= 22) else b"\x00") * self.pcr_size
                     for idx in range(self.NUM_PCRS)}
        self.count = {idx: 0 for idx in range(self.NUM_PCRS)}

    def extend_with_hash(self, idx, extend_value):
        self.pcrs[idx] = extend_pcr_with_hash(self.pcrs[idx], extend_value, self.hash_alg)
        self.count[idx] += 1
        return self.pcrs[idx]

    def extend_with_data(self, idx, extend_data):
        self.pcrs[idx] = extend_pcr_with_data(self.pcrs[idx], extend_data, self.hash_alg)
        self.count[idx] += 1
        return self.pcrs[idx]

    def __getitem__(self, idx):
        return self.pcrs[idx]
