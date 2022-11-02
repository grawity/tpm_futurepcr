import hashlib
import os
import subprocess as sp
from typing import Optional
import re
import logging

from .pcr_register import PcrRegister
from .util import is_tpm2, in_path

logger = logging.getLogger('PcrBank')


class PcrBank:
    def __init__(self, alg="sha1", num_pcrs=24, pcr_list: Optional[list[PcrRegister]] = None):
        self.num_pcrs = num_pcrs
        self.hash_alg = alg
        self.pcr_size = hashlib.new(alg).digest_size
        logger.verbose("Instantiated bank with register size %d", self.pcr_size)
        self.pcrs = pcr_list or \
                    [PcrRegister((b"\xFF" if (17 <= idx <= 22) else b"\x00") * self.pcr_size) for idx in range(num_pcrs)]

    @staticmethod
    def from_current_pcrs(num_pcrs=24, alg="sha1") -> 'PcrBank':
        pcrs = []
        if os.path.exists(f"/sys/class/tpm/tpm0/pcr-{alg}/0"):
            # New sysfs exports in kernel v5.12
            for idx in range(num_pcrs):
                with open(f"/sys/class/tpm/tpm0/pcr-{alg}/{idx}") as fh:
                    buf = fh.read().strip()
                    pcrs.append(bytes.fromhex(buf))
        elif is_tpm2():
            if in_path("tpm2_pcrread"):  # tpm2-utils 4.0 or later
                cmd = f"tpm2_pcrread {alg} -Q -o /dev/stdout"
            elif in_path("tpm2_pcrlist"):  # tpm2-utils 3.x
                cmd = f"tpm2_pcrlist -L {alg} -Q -o /dev/stdout"
            else:
                # TODO: try using IBM TSS tools
                raise Exception("neither tpm2_pcrread nor tpm2_pcrlist could be found")

            pcr_size = hashlib.new(alg).digest_size
            for idx in range(num_pcrs):
                pcrs.append(sp.check_output(cmd.split()).read(pcr_size))
        else:
            if alg != "sha1":
                raise Exception("TPM v1 only supports the SHA1 PCR bank")
            with open("/sys/class/tpm/tpm0/pcrs") as fh:
                for line in fh:
                    t = re.match(r"PCR-\d+: ([A-F\d ]+)", line)
                    if t is not None:
                        pcrs.append(bytes.fromhex(t.group(1)))

        return PcrBank(alg, num_pcrs, pcrs)

    def possibly_unused(self) -> bool:
        # The first 8 PCRs always have an EV_SEPARATOR logged to them at the very least,
        # and the first 3 or so will almost always have other boot events. If we never saw
        # anything then the whole bank might be unused (and an all-zeros PCR value is
        # obviously unsafe to bind against).
        return all(x.count != 0 for x in self.pcrs[:8])

    def __eq__(self, other):
        if self.num_pcrs != other.num_pcrs or self.hash_alg != other.hash_alg:
            return False

        return all(pcr1 == pcr2 for pcr1, pcr2 in zip(self.pcrs, other.pcrs))

    def show_compare(self, other: 'PcrBank'):
        logger.info("Number of PCRs: %d / %d", self.num_pcrs, other.num_pcrs)

        logger.info("Hash algorithms: %s / %s", self.hash_alg, other.hash_alg)

        logger.info("PCR values:")
        logger.info("           %-*s | %-*s", self.pcr_size * 2, "REAL", other.pcr_size * 2,  "COMPUTED")
        for idx, pcr in enumerate(self.pcrs):
            status = "+" if pcr == other.pcrs[idx] else "<BAD>"
            logger.info("   PCR %2d: %-*s | %-*s %s", idx, self.pcr_size * 2, pcr, other.pcr_size * 2, other.pcrs[idx], status)
