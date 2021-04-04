import hashlib
import subprocess

from .util import is_tpm2, in_path

NUM_PCRS = 24
PCR_SIZE = hashlib.sha1().digest_size

def init_empty_pcrs(alg="sha1"):
    pcr_size = hashlib.new(alg).digest_size
    pcrs = {idx: (b"\xFF" if (17 <= idx <= 22) else b"\x00") * pcr_size
            for idx in range(NUM_PCRS)}
    return pcrs

def read_current_pcrs(alg="sha1"):
    pcr_size = hashlib.new(alg).digest_size
    if is_tpm2():
        if in_path("tpm2_pcrread"): # tpm2-utils 4.0 or later
            cmd = ["tpm2_pcrread", "sha1", "-Q", "-o", "/dev/stdout"]
        elif in_path("tpm2_pcrlist"): # tpm2-utils 3.x
            cmd = ["tpm2_pcrlist", "-L", "sha1", "-Q", "-o", "/dev/stdout"]
        else:
            # TODO: try using IBM TSS tools
            raise Exception("tpm2_pcrread or tpm2_pcrlist not found")
        res = subprocess.run(cmd, stdout=subprocess.PIPE)
        res.check_returncode()
        buf = res.stdout
        assert(len(buf) % pcr_size == 0)
        return {idx: buf[idx*pcr_size:(idx+1)*pcr_size] for idx in range(len(buf) // pcr_size)}
    else:
        if alg != "sha1":
            raise Exception("TPM1 only supports SHA1")
        pcrs = {}
        with open("/sys/class/tpm/tpm0/pcrs", "r") as fh:
            for line in fh:
                if line.startswith("PCR-"):
                    idx, buf = line.strip().split(": ")
                    idx = int(idx[4:], 10)
                    buf = bytes.fromhex(buf)
                    pcrs[idx] = buf
        return pcrs

def extend_pcr_with_hash(pcr_value, extend_value, alg="sha1"):
    pcr_value = hashlib.new(alg, pcr_value + extend_value).digest()
    return pcr_value

def extend_pcr_with_data(pcr_value, extend_data, alg="sha1"):
    extend_value = hashlib.new(alg, extend_data).digest()
    return extend_pcr_with_hash(pcr_value, extend_value)
