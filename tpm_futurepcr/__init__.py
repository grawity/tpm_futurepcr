#!/usr/bin/env python3
from pathlib import Path

from .LogEvent import EFIBSAEvent, IPLEvent, NoActionEvent
from .event_log import enum_log_entries
from .PcrBank import PcrBank
from .tpm_constants import TpmEventType, TpmAlgorithm
import tpm_futurepcr.logging as logging
from .util import to_hex

logger = logging.getLogger("tpm_futurepcr")


def process_log(wanted_pcrs: list[int], hash_alg: TpmAlgorithm, log_path: Path, substitute_bsa_unix_path: dict | None, allow_unexpected_bsa: bool) -> tuple[PcrBank, PcrBank]:
    this_pcrs = PcrBank(hash_alg.name.lower())
    next_pcrs = PcrBank(hash_alg.name.lower())
    last_efi_binary = None

    # the set of pcrs request might be extended with additional the former depend upon
    required_pcrs = set(wanted_pcrs)
    if 12 in required_pcrs:
        logger.verbose("Although not requested, PCR 4 is a dependency for PCR 12")
        required_pcrs.add(4)

    verbose_pcr = logger.level <= logging.VERBOSE

    # replay the events log
    for event in enum_log_entries(substitute_bsa_unix_path, allow_unexpected_bsa, log_path):
        if event.pcr_idx not in required_pcrs:
            continue

        if verbose_pcr:
            event.show()

        # if this event happens on the virtual PCR just skip it
        if event.pcr_idx == 0xFFFFFFFF:
            if verbose_pcr:
                logger.verbose("event updates Windows virtual PCR[-1], skipping")
            continue

        try:
            this_extend_value = event.pcr_extend_values[hash_alg]
            logger.verbose("this event extend value = %s", to_hex(this_extend_value))
        except KeyError:
            if verbose_pcr:
                logger.verbose("event does not update the specified PCR bank, skipping")
            continue

        if isinstance(event, IPLEvent):
            event.last_efi_binary = last_efi_binary

        if isinstance(event, EFIBSAEvent):
            last_efi_binary = event.unix_path
            logger.verbose("extending with coff hash from path %s", event.unix_path)

        # get the next extended value from the event
        next_extend_value = event.next_extend_value(hash_alg)
        logger.verbose("guessed extend value = %s", to_hex(next_extend_value))

        if not isinstance(event, NoActionEvent):
            this_pcrs.pcrs[event.pcr_idx].extend_with_hash(this_extend_value)
            next_pcrs.pcrs[event.pcr_idx].extend_with_hash(next_extend_value)

        if verbose_pcr:
            logger.verbose("--> after this event, PCR %d contains value %s", event.pcr_idx, this_pcrs.pcrs[event.pcr_idx])
            logger.verbose("--> after reboot, PCR %d will contain value %s", event.pcr_idx, next_pcrs.pcrs[event.pcr_idx])

    return this_pcrs, next_pcrs
