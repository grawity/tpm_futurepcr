#!/usr/bin/env python3
from pathlib import Path

from .device_path import device_path_to_unix_path
from .event_log import enum_log_entries
from .pcr_bank import PcrBank, read_current_pcrs
from .systemd_boot import loader_encode_pcr8, loader_decode_pcr8, loader_get_next_cmdline
from .tpm_constants import TpmEventType, TpmAlgorithm
import tpm_futurepcr.logging as logging
from .util import hash_pecoff, to_hex, hash_bytes

logger = logging.getLogger('tpm_futurepcr')


def process_log(wanted_pcrs: list[int], hash_alg: TpmAlgorithm, log_path: Path, substitute_bsa_unix_path: dict | None, allow_unexpected_bsa: bool):
    this_pcrs = PcrBank(hash_alg.name.lower())
    next_pcrs = PcrBank(hash_alg.name.lower())
    errors = False
    last_efi_binary = None

    required_pcrs = set(wanted_pcrs)
    if 12 in required_pcrs:
        logger.verbose('Although not requested, PCR 4 is a dependency for PCR 12')
        required_pcrs.add(4)

    for event in enum_log_entries(log_path):
        idx = event.pcr_idx
        if idx not in required_pcrs:
            continue

        _verbose_pcr = logger.level <= logging.VERBOSE
        if _verbose_pcr:
            event.show()

        if idx == 0xFFFFFFFF:
            if _verbose_pcr:
                logger.verbose("event updates Windows virtual PCR[-1], skipping")
            continue

        try:
            this_extend_value = event.pcr_extend_values[hash_alg]
        except KeyError:
            if _verbose_pcr:
                logger.verbose("event does not update the specified PCR bank, skipping")
            continue
        next_extend_value = this_extend_value

        if event.type == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
            try:
                unix_path = device_path_to_unix_path(event.data.device_path_vec)
                if substitute_bsa_unix_path:
                    unix_path = substitute_bsa_unix_path.get(unix_path, unix_path)
            except Exception as e:
                logger.error(e)
                errors = True
                unix_path = None

            if unix_path:
                try:
                    next_extend_value = hash_pecoff(unix_path, hash_alg)
                except FileNotFoundError:
                    logger.info("File %s could not be opened. Continuing with the log-provided extend value", unix_path)
                last_efi_binary = unix_path
                if _verbose_pcr:
                    logger.verbose("-- extending with coff hash --")
                    logger.verbose("file path = %s", unix_path)
                    logger.verbose("file hash = %s", to_hex(next_extend_value))
                    logger.verbose("this event extend value = %s", to_hex(this_extend_value))
                    logger.verbose("guessed extend value = %s", to_hex(next_extend_value))
            else:
                # This might be a firmware item such as the boot menu.
                if not allow_unexpected_bsa:
                    logger.error("Unexpected boot events found. Binding to these PCR values "
                                 "is not advised, as it might be difficult to reproduce this state "
                                 "later. Exiting.")
                    exit(1)
                logger.warning("couldn't map EfiBootServicesApplication event to a Linux path")

        # Handle systemd EFI stub "kernel command line" measurements (found in
        # PCR 8 up to systemd v250, but PCR 12 afterwards).
        if event.type == TpmEventType.IPL and (idx in wanted_pcrs):
            try:
                cmdline = loader_get_next_cmdline(last_efi_binary)
                if logger.level <= logging.VERBOSE:
                    old_cmdline = event.data
                    # 2022-03-19 grawity: In the past, we had to strip away the last \0 byte for
                    # some reason (which I don't remember)... but apparently now we don't? Let's
                    # add a warning so that hopefully I remember why it was necessary.
                    if len(old_cmdline) % 2 != 0:
                        logger.warning("Expecting EV_IPL data to contain UTF-16, but length isn't a multiple of 2")
                        old_cmdline += b'\0'
                    old_cmdline = loader_decode_pcr8(old_cmdline)
                    logger.verbose("-- extending with systemd-boot cmdline --")
                    logger.verbose("this cmdline: %s", old_cmdline)
                    logger.verbose("next cmdline: %s", cmdline)
                cmdline = loader_encode_pcr8(cmdline)
                next_extend_value = hash_bytes(cmdline, hash_alg.name.lower())
            except FileNotFoundError:
                # Either EFI variables, the ESP, or the .conf, are missing.
                # It's probably not a systemd-boot environment, so PCR[8] meaning is undefined.
                logger.verbose("-- not touching non-systemd IPL event --")

        if event.type != TpmEventType.NO_ACTION:
            this_pcrs.extend_with_hash(idx, this_extend_value)
            next_pcrs.extend_with_hash(idx, next_extend_value)

        if _verbose_pcr:
            logger.verbose("--> after this event, PCR %d contains value %s" % (idx, to_hex(this_pcrs[idx])))
            logger.verbose("--> after reboot, PCR %d will contain value %s" % (idx, to_hex(next_pcrs[idx])))

    return this_pcrs, next_pcrs, errors


def compare_pcrs(hash_alg: str, this_pcrs: PcrBank, next_pcrs: PcrBank, wanted_pcrs: list[int]) -> bool:
    logger.info("== Real vs computed PCR values ==")
    real_pcrs = read_current_pcrs(hash_alg)
    errors = False

    logger.info("       %-*s | %-*s", this_pcrs.pcr_size * 2, "REAL", next_pcrs.pcr_size * 2, "COMPUTED")
    for idx in wanted_pcrs:
        if real_pcrs[idx] == this_pcrs[idx]:
            status = "+"
        else:
            errors |= True
            status = "<BAD>"
        logger.info("PCR %2d: %s | %s %s", idx, to_hex(real_pcrs[idx]), to_hex(this_pcrs[idx]), status)

    return errors


def possibly_unused_bank(hash_alg: str, wanted_pcrs: list[int], this_pcrs: list[int]) -> bool:
    for idx in wanted_pcrs:
        if idx <= 7 and this_pcrs.count[idx] == 0:
            # The first 8 PCRs always have an EV_SEPARATOR logged to them at the very least,
            # and the first 3 or so will almost always have other boot events. If we never saw
            # anything then the whole bank might be unused (and an all-zeros PCR value is
            # obviously unsafe to bind against).
            logger.error("Log contains no entries for PCR %d in the %r bank.", idx, hash_alg)
            return True
    return False
