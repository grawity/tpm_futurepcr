The `tpm_futurepcr` script allows pre-calculating what the future PCR4 value will be after a kernel upgrade, before you reboot. This is useful when your rootfs is LUKS-encrypted with a key sealed by the TPM against PCR4 (among others).

This script only recognizes measurements done by native UEFI LoadImage() – i.e. hashes of PE/COFF executables such as vmlinuz.efi. (Although it does parse the TPM 1.2 event log, it does not (yet) recognize measurements done by TrustedGRUB on BIOS systems, and in fact I'm not entirely sure whether the entire premise of sealing data against user-specified PCR values is even _possible_ in the TPM 1.2 API.)

As an additional hack, this script also recognizes systemd-boot and updates its EV\_IPL event according to the future kernel command line.

This script will understand the event log in both SHA1-only (TPM 1.2) and Crypto-Agile (TPM 2.0, Linux kernel 5.3+) formats.

### Other similar projects

  - <https://github.com/okirch/pcr-oracle>

### Warning

Until Linux 5.17, neither systemd-boot nor EFISTUB measure the loaded initrd images, making it unsafe to rely on PCR4 alone. (Starting with Linux 5.17, the initrd measurements are now stored in PCR9; this script does not yet support pre-calculating it.) Additionally, only systemd-boot measures the _command line_ into PCR8; EFISTUB on its own does not.

It is recommended to use PCR-based sealing (whether it is PCR4 with tpm\_futurepcr or PCR7 with Secure Boot) only with a combined [systemd-stub][] "kernel + initramfs" image, such as the one produced by `mkinitcpio -U`.

[systemd-stub]: https://www.freedesktop.org/software/systemd/man/systemd-stub.html

### Dependencies

  - python-signify (for calculating Authenticode digests)
  - tpm2-tools (for reading current PCR values in kernels older than v5.12)

### Installation
  
`python setup.py install`

### Usage

Normally sealing data against PCRs starts by creating a "policy" which specifies the PCR values. In the Intel TPM 2.0 stack, this is done with *tpm2_createpolicy*:

    tpm2_createpolicy --policy-pcr --pcr-list=sha256:0,2,4,7 --policy=policy.bin

This automatically uses current PCR values, and can be written to do so explicitly:

    tpm2_pcrread sha256:0,2,4,7 -Q -o pcrvalues.bin
    tpm2_createpolicy --policy-pcr --pcr-list=sha256:0,2,4,7 --pcr=pcrvalues.bin --policy=policy.bin

To do the same with *future* PCR values, use tpm\_futurepcr:

    tpm_futurepcr -L 0,2,4,7 -o pcrvalues.bin
    tpm2_createpolicy --policy-pcr --pcr-list=sha256:0,2,4,7 --pcr=pcrvalues.bin --policy=policy.bin
