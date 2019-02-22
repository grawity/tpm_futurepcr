The `tpm_futurepcr` script allows guessing what the future PCR7 value will be after a kernel upgrade, before you reboot.

This is useful when your rootfs is LUKS-encrypted with a key sealed by the TPM against PCR7 (among others).
