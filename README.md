The `tpm_futurepcr` script allows guessing what the future PCR[4] value will be after a kernel upgrade, before you reboot.

This is useful when your rootfs is LUKS-encrypted with a key sealed by the TPM against PCR[4] (among others).
