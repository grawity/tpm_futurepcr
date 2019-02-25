The `tpm2_futurepcr` script allows guessing what the future PCR[4] value will be after a kernel upgrade, before you reboot. This is useful when your rootfs is LUKS-encrypted with a key sealed by the TPM against PCR[4] (among others).

This script only recognizes measurements done by native UEFI LoadImage() – i.e. hashes of PE/COFF executables such as vmlinuz.efi. (Although it does parse the TPM 1.2 event log, it does not (yet) recognize measurements done by TrustedGRUB on BIOS systems, and in fact I'm not entirely sure whether the entire premise of sealing data against user-specified PCR values is even _possible_ in the TPM 1.2 API.)

As an additional hack, this script also recognizes systemd-boot and updates PCR[8] according to the future kernel command line.

This script was only tested on systems which provide the event log in the TPM 1.2 format (which is SHA-1 only), and for that reason only outputs SHA-1 PCRs. It does have _untested_ code for parsing the TPM 2.0 event log format (hash-agile), but I don't have any systems offering it.

### Installation
  
`python setup.py install`

### Usage

Normally sealing data against PCRs starts by creating a "policy" which specifies the PCR values. In the Intel TPM 2.0 stack, this is done with *tpm2_createpolicy*:

    tpm2_createpolicy -P -L sha1:0,2,4,7 -f policy.bin

This automatically uses current PCR values, and can be written to do so explicitly:

    tpm2_pcrlist -L sha1:0,2,4,7 -Q -o pcrvalues.bin
    tpm2_createpolicy -P -L sha1:0,2,4,7 -F pcrvalues.bin -f policy.bin

To do the same with *future* PCR values, use tpm2\_futurepcr:

    tpm2_futurepcr -L 0,2,4,7 -o pcrvalues.bin
    tpm2_createpolicy -P -L sha1:0,2,4,7 -F pcrvalues.bin -f policy.bin
