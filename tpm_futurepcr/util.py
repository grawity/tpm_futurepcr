import hashlib
import os
import signify.fingerprinter
import subprocess
import tempfile

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
    with tempfile.NamedTemporaryFile() as tmp:
        res = subprocess.run(["objcopy", path, tmp.name,
                                         "--only-section", "I hate objcopy",
                                         "--dump-section", "%s=/dev/stdout" % section],
                             stdout=subprocess.PIPE)
        res.check_returncode()
        return res.stdout

def read_efi_variable(name, guid):
    path = "/sys/firmware/efi/efivars/%s-%s" % (name, guid)
    with open(path, "rb") as fh:
        buf = fh.read()
        return buf[4:]

def init_empty_pcrs():
    pcrs = {idx: (b"\xFF" if idx in {17, 18, 19, 20, 21, 22} else b"\x00") * PCR_SIZE
            for idx in range(NUM_PCRS)}
    return pcrs

def is_tpm2():
    if not os.path.exists("/sys/class/tpm/tpm0/caps"):
        # XXX: the sysfs interface is suddenly gone for TPM 2.0, and mjg says it wasn't
        #      actually meant to be there, and I don't know how to check the version in
        #      any other way so just assume it's 2.0 in that case.
        return True
    with open("/sys/class/tpm/tpm0/caps", "r") as fh:
        for line in fh:
            if line.startswith("TCG version: 2."):
                # XXX: untested
                return True
            if line.startswith("TCG version: 1.2"):
                return False
    return True

def in_path(exe):
    for p in os.environ["PATH"].split(":"):
        if p and os.path.exists("%s/%s" % (p, exe)):
            return True
    return False

def read_current_pcr(idx):
    return read_current_pcrs([idx])[idx]

def read_current_pcrs(idxs):
    if is_tpm2():
        if in_path("tpm2_pcrread"):
            # utils 4.0
            res = subprocess.run(["tpm2_pcrread", "sha1:%s" % ",".join(map(str, idxs)),
                                                  "-Q", "-o", "/dev/stdout"],
                                 stdout=subprocess.PIPE)
        elif in_path("tpm2_pcrlist"):
            res = subprocess.run(["tpm2_pcrlist", "-L", "sha1:%s" % ",".join(map(str, idxs)),
                                                  "-Q", "-o", "/dev/stdout"],
                                 stdout=subprocess.PIPE)
        res.check_returncode()
        buf = res.stdout
        return {idx: buf[n*PCR_SIZE:(n+1)*PCR_SIZE] for (n, idx) in enumerate(idxs)}
    else:
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

def find_mountpoint_by_partuuid(partuuid):
    res = subprocess.run(["findmnt", "-S", "PARTUUID=" + str(partuuid).lower(),
                                     "-o", "TARGET", "-r", "-n"],
                         stdout=subprocess.PIPE)
    res.check_returncode()
    return res.stdout.splitlines()[0].decode()
