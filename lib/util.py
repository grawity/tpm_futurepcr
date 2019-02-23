import hashlib
import signify.fingerprinter
import subprocess

NUM_PCRS = 24
PCR_SIZE = hashlib.sha1().digest_size

def to_hex(buf):
    import binascii
    return binascii.hexlify(buf).decode()

def hexdump(buf):
    for i in range(0, len(buf), 16):
        row = buf[i:i+16]
        offs = "0x%08x:" % i
        hexs = ["%02X" % b for b in row] + ["  "] * 16
        text = [chr(b) if 0x20 < b < 0x7f else "." for b in row] + [" "] * 16
        print(offs, " ".join(hexs[:16]), "|%s|" % "".join(text[:16]))

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

def init_empty_pcrs():
    pcrs = {idx: (b"\xFF" if idx in {17, 18, 19, 20, 21, 22} else b"\x00") * PCR_SIZE
            for idx in range(NUM_PCRS)}
    return pcrs

def read_current_pcr(idx):
    res = subprocess.run(["tpm2_pcrlist", "-L", "sha1:%d" % idx,
                                          "-Q", "-o", "/dev/stdout"],
                         stdout=subprocess.PIPE)
    res.check_returncode()
    return res.stdout

def read_current_pcrs(idxs):
    res = subprocess.run(["tpm2_pcrlist", "-L", "sha1:%s" % ",".join(map(str, idxs)),
                                          "-Q", "-o", "/dev/stdout"],
                         stdout=subprocess.PIPE)
    res.check_returncode()
    buf = res.stdout
    return {idx: buf[n*PCR_SIZE:(n+1)*PCR_SIZE] for (n, idx) in enumerate(idxs)}

def extend_pcr_with_hash(pcr_value, extend_value, alg="sha1"):
    pcr_value = hashlib.new(alg, pcr_value + extend_value).digest()
    return pcr_value

def extend_pcr_with_data(pcr_value, extend_data, alg="sha1"):
    extend_value = hashlib.new(alg, extend_data).digest()
    return extend_pcr_with_hash(pcr_value, extend_value)

def find_mountpoint_by_partuuid(partuuid):
    res = subprocess.run(["findmnt", "-S", "PARTUUID=" + str(partuuid).lower(),
                                     "-o", "TARGET", "-r", "-n"],
                         stdout=subprocess.PIPE)
    res.check_returncode()
    return res.stdout.splitlines()[0].decode()
