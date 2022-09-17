#!/usr/bin/env python3
from pathlib import Path
import argparse

from .event_log import *
from .pcr_bank import *
from .systemd_boot import (
    loader_encode_pcr8,
    loader_decode_pcr8,
    loader_get_next_cmdline,
)
from .tpm_constants import TpmEventType
from .util import *

import tpm_futurepcr.logging as logging

logger = logging.getLogger('tpm_futurepcr')


def create_argparser() -> argparse.ArgumentParser:
    def _validate_pcrlist(pcr_list: str) -> tuple[list[int], str] | list[int]:
        if "+" in pcr_list:
            raise argparse.ArgumentTypeError("PCR specifier may only contain one bank.")

        try:
            hash_alg, pcr_list = tuple(pcr_list.split(":"))
        except ValueError:
            hash_alg = None
        finally:
            pcr_list = list(map(int, pcr_list.split(",")))

        return pcr_list, hash_alg

    class _KeyValueAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            if getattr(namespace, self.dest, None) is None:
                setattr(namespace, self.dest, dict())
            kvmap = getattr(namespace, self.dest)
            if not isinstance(values, list):
                values = [values]
            kvpairs = [v.split("=", 1) for v in values]
            try:
                kvmap.update(kvpairs)
            except ValueError:
                raise argparse.ArgumentTypeError("Value for option %s malformed: %s" % (self.dest, values))

    parser = argparse.ArgumentParser()
    parser.add_argument("-L", "--pcr-list", type=_validate_pcrlist, default=','.join(list(map(str, range(24)))), help="comma-separated list of PCR registers")
    parser.add_argument("-H", "--hash-alg", help="specify the hash algorithm", choices=['sha1', 'sha256'])
    parser.add_argument("-o", "--output", type=Path, help="write binary PCR values to specified file")
    parser.add_argument("--allow-unexpected-bsa", action="store_true", help="accept BOOT_SERVICES_APPLICATION events with weird paths")
    parser.add_argument("--substitute-bsa-unix-path", action=_KeyValueAction, help="substitute BOOT_SERVICES_APPLICATION path (syntax: <computed unix path>=<new unix path>)")
    parser.add_argument("--compare", action="store_true", help="compare computed PCRs against live values")
    parser.add_argument("--log-path", type=Path, help="read binary log from an alternative path")

    parser.add_argument('-d', '--debug', help="Print lots of debugging statements", action="store_const", dest="loglevel", const=logging.DEBUG, default=logging.INFO)
    parser.add_argument('-v', '--verbose', help="Be verbose", action="store_const", dest="loglevel", const=logging.VERBOSE)

    return parser


def postprocess_args(args: argparse.Namespace) -> argparse.Namespace:
    if (args.hash_alg is None and args.pcr_list[1] is None) or \
       (args.hash_alg is not None and args.pcr_list[1] is not None and args.hash_alg != args.pcr_list[1]):
        raise argparse.ArgumentTypeError("PCR hash algorithm must be explicitly specified either in the pcr list or with the -H flag")

    # populate properly the hash_alg argument
    args.hash_alg = TpmAlgorithm[args.hash_alg or args.pcr_list[1].upper()]
    args.pcr_list = args.pcr_list[0]

    logging.getLogger().setLevel(args.loglevel)

    return args


def process_log(args, wanted_pcrs, hash_alg):
    this_pcrs = PcrBank(hash_alg)
    next_pcrs = PcrBank(hash_alg)
    errors = False
    last_efi_binary = None

    for event in enum_log_entries(args.log_path):
        idx = event["pcr_idx"]
        if idx not in wanted_pcrs:
            continue

        _verbose_pcr = logger.level <= logging.VERBOSE
        if _verbose_pcr:
            show_log_entry(event)

        if idx == 0xFFFFFFFF:
            if _verbose_pcr:
                logger.verbose("event updates Windows virtual PCR[-1], skipping")
            continue

        this_extend_value = event["pcr_extend_values"].get(args.hash_alg)
        next_extend_value = this_extend_value

        if this_extend_value is None:
            if _verbose_pcr:
                logger.verbose("event does not update the specified PCR bank, skipping")
            continue

        if event["event_type"] == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
            event_data = parse_efi_bsa_event(event["event_data"])
            try:
                unix_path = device_path_to_unix_path(event_data["device_path_vec"])
                if args.substitute_bsa_unix_path:
                    unix_path = args.substitute_bsa_unix_path.get(unix_path, unix_path)
            except Exception as e:
                logger.error(e)
                errors = True
                unix_path = None

            if unix_path:
                file_hash = hash_pecoff(unix_path, hash_alg)
                next_extend_value = file_hash
                last_efi_binary = unix_path
                if _verbose_pcr:
                    logger.verbose("-- extending with coff hash --")
                    logger.verbose("file path = %s", unix_path)
                    logger.verbose("file hash = %s", to_hex(file_hash))
                    logger.verbose("this event extend value = %s", to_hex(this_extend_value))
                    logger.verbose("guessed extend value = %s", to_hex(next_extend_value))
            else:
                # This might be a firmware item such as the boot menu.
                if not args.allow_unexpected_bsa:
                    logger.error("Unexpected boot events found. Binding to these PCR values "
                                 "is not advised, as it might be difficult to reproduce this state "
                                 "later. Exiting.")
                    exit(1)
                logger.warning("couldn't map EfiBootServicesApplication event to a Linux path")

        # Handle systemd EFI stub "kernel command line" measurements (found in
        # PCR 8 up to systemd v250, but PCR 12 afterwards).
        if event["event_type"] == TpmEventType.IPL and (idx in wanted_pcrs):
            try:
                cmdline = loader_get_next_cmdline(last_efi_binary)
                if logger.level <= logging.VERBOSE:
                    old_cmdline = event["event_data"]
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
                next_extend_value = hash_bytes(cmdline, hash_alg)
            except FileNotFoundError:
                # Either some of the EFI variables, or the ESP, or the .conf, are missing.
                # It's probably not a systemd-boot environment, so PCR[8] meaning is undefined.
                logger.verbose("-- not touching non-systemd IPL event --")

        if event["event_type"] != TpmEventType.NO_ACTION:
            this_pcrs.extend_with_hash(idx, this_extend_value)
            next_pcrs.extend_with_hash(idx, next_extend_value)

        if _verbose_pcr:
            logger.verbose("--> after this event, PCR %d contains value %s" % (
            idx, to_hex(this_pcrs[idx])))
            logger.verbose("--> after reboot, PCR %d will contain value %s" % (
            idx, to_hex(next_pcrs[idx])))

    return this_pcrs, next_pcrs, errors


def compare_pcrs(hash_alg, this_pcrs, next_pcrs, wanted_pcrs):
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


def possibly_unused_bank(hash_alg, wanted_pcrs, this_pcrs):
    for idx in wanted_pcrs:
        if idx <= 7 and this_pcrs.count[idx] == 0:
            # The first 8 PCRs always have an EV_SEPARATOR logged to them at the very least,
            # and the first 3 or so will almost always have other boot events. If we never saw
            # anything then the whole bank might be unused (and an all-zeros PCR value is
            # obviously unsafe to bind against).
            logger.error("Log contains no entries for PCR %d in the %r bank.", idx, hash_alg)
            return True
    return False
