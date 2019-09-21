The `tpm_futurepcr` script allows guessing what the future PCR[4] value will be after a kernel upgrade, before you reboot. This is useful when your rootfs is LUKS-encrypted with a key sealed by the TPM against PCR[4] (among others).

This script only recognizes measurements done by native UEFI LoadImage() – i.e. hashes of PE/COFF executables such as vmlinuz.efi. (Although it does parse the TPM 1.2 event log, it does not (yet) recognize measurements done by TrustedGRUB on BIOS systems, and in fact I'm not entirely sure whether the entire premise of sealing data against user-specified PCR values is even _possible_ in the TPM 1.2 API.)

As an additional hack, this script also recognizes systemd-boot and updates PCR[8] according to the future kernel command line.

This script will understand the event log in both SHA1-only (TPM 1.2) and Crypto-Agile (TPM 2.0, Linux kernel 5.3+) formats. However, the current version only works with and outputs SHA-1 PCRs. In the future, support for selecting multiple digest algorithms will be added.

### Warning

Neither systemd-boot nor EFISTUB currently measure the initramfs images. It is not safe to rely on PCR[4] _unless_ you are using a combined kernel+initramfs file (such as the one produced by mksignkernels), or you are using a bootloader which measures the initramfs separately.

### Dependencies

 * python-signify (for calculating Authenticode digests)
 * binutils/objcopy (for parsing systemd-stub kernel images)

### Installation
  
`python setup.py install`

### Usage

Normally sealing data against PCRs starts by creating a "policy" which specifies the PCR values. In the Intel TPM 2.0 stack, this is done with *tpm2_createpolicy*:

    tpm2_createpolicy -P -L sha1:0,2,4,7 -f policy.bin

This automatically uses current PCR values, and can be written to do so explicitly:

    tpm2_pcrlist -L sha1:0,2,4,7 -Q -o pcrvalues.bin
    tpm2_createpolicy -P -L sha1:0,2,4,7 -F pcrvalues.bin -f policy.bin

To do the same with *future* PCR values, use tpm\_futurepcr:

    tpm_futurepcr -L 0,2,4,7 -o pcrvalues.bin
    tpm2_createpolicy -P -L sha1:0,2,4,7 -F pcrvalues.bin -f policy.bin
