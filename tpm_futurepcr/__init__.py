#!/usr/bin/env python3
import argparse
import sys

from .event_log import *
from .pcr_bank import *
from .systemd_boot import (
    loader_encode_pcr8,
    loader_get_next_cmdline,
)
from .tpm_constants import TpmEventType
from .util import *

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-L", "--pcr-list",
                        help="limit output to specified PCR indexes")
    parser.add_argument("-H", "--hash-alg",
                        help="specify the hash algorithm (sha1 or sha256)")
    parser.add_argument("-o", "--output",
                        help="write binary PCR values to specified file")
    parser.add_argument("--allow-unexpected-bsa", action="store_true",
                        help="accept BOOT_SERVICES_APPLICATION events with weird paths")
    parser.add_argument("--compare", action="store_true",
                        help="compare computed PCRs against live values")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show verbose information about log parsing")
    parser.add_argument("--log-path",
                        help="read binary log from an alternative path")
    args = parser.parse_args()

    hash_alg = None
    if args.pcr_list:
        verbose_all_pcrs = False
        pcr_list = args.pcr_list
        if "+" in pcr_list:
            raise ValueError("PCR bank specifier may only contain one bank")
        if ":" in pcr_list:
            bank_spec = pcr_list.split(":")
            hash_alg = bank_spec[0]
            pcr_list = bank_spec[1]
        elif not args.hash_alg:
            print("WARNING: PCR list does not specify hash algorithm. This will be an error in the future!",
                  file=sys.stderr)
        wanted_pcrs = [int(idx) for idx in pcr_list.split(",")]
    else:
        verbose_all_pcrs = True
        wanted_pcrs = [*range(NUM_PCRS)]

    if args.hash_alg:
        if not hash_alg:
            hash_alg = args.hash_alg
        elif hash_alg != args.hash_alg:
            raise ValueError("Conflicting PCR hash algorithm specifications given.")

    if not hash_alg:
        raise ValueError("PCR hash algorithm must be explicitly specified and no longer defaults to 'sha1'.")
    elif hash_alg == "sha1":
        tpm_hash_alg = TpmAlgorithm.SHA1
    elif hash_alg == "sha256":
        tpm_hash_alg = TpmAlgorithm.SHA256
    else:
        raise ValueError("Only 'sha1' and 'sha256' PCR banks are supported.")

    this_pcrs = PcrBank(hash_alg)
    next_pcrs = PcrBank(hash_alg)
    last_efi_binary = None
    errors = 0

    for event in enum_log_entries(args.log_path):
        idx = event["pcr_idx"]

        _verbose_pcr = (args.verbose and (verbose_all_pcrs or idx in wanted_pcrs))
        if _verbose_pcr:
            show_log_entry(event)

        if idx == 0xFFFFFFFF:
            if _verbose_pcr:
                print("event updates Windows virtual PCR[-1], skipping")
            continue

        this_extend_value = event["pcr_extend_values_dict"].get(tpm_hash_alg)
        next_extend_value = this_extend_value

        if this_extend_value is None:
            if _verbose_pcr:
                print("event does not update the specified PCR bank, skipping")
            continue

        if event["event_type"] == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
            event_data = parse_efi_bsa_event(event["event_data"])
            try:
                unix_path = device_path_to_unix_path(event_data["device_path_vec"])
            except Exception as e:
                print(e)
                errors = 1
                unix_path = None

            if unix_path:
                file_hash = hash_pecoff(unix_path, hash_alg)
                next_extend_value = file_hash
                last_efi_binary = unix_path
                if _verbose_pcr:
                    print("-- extending with coff hash --")
                    print("file path =", unix_path)
                    print("file hash =", to_hex(file_hash))
                    print("this event extend value =", to_hex(this_extend_value))
                    print("guessed extend value =", to_hex(next_extend_value))
            else:
                # This might be a firmware item such as the boot menu.
                if not args.allow_unexpected_bsa:
                    exit("error: Unexpected boot events found. Binding to these PCR values "
                         "is not advised, as it might be difficult to reproduce this state "
                         "later. Exiting.")
                print("warning: couldn't map EfiBootServicesApplication event to a Linux path",
                      file=sys.stderr)

        if event["event_type"] == TpmEventType.IPL and (idx in wanted_pcrs):
            try:
                cmdline = loader_get_next_cmdline(last_efi_binary)
                if args.verbose:
                    old_cmdline = event["event_data"][:-1].decode("utf-16le")
                    print("-- extending with systemd-boot cmdline --")
                    print("this cmdline:", repr(old_cmdline))
                    print("next cmdline:", repr(cmdline))
                cmdline = loader_encode_pcr8(cmdline)
                next_extend_value = hash_bytes(cmdline, hash_alg)
            except FileNotFoundError:
                # Either some of the EFI variables, or the ESP, or the .conf, are missing.
                # It's probably not a systemd-boot environment, so PCR[8] meaning is undefined.
                if args.verbose:
                    print("-- not touching non-systemd IPL event --")

        if event["event_type"] != TpmEventType.NO_ACTION:
            this_pcrs.extend_with_hash(idx, this_extend_value)
            next_pcrs.extend_with_hash(idx, next_extend_value)

        if _verbose_pcr:
            print("--> after this event, PCR %d contains value %s" % (idx, to_hex(this_pcrs[idx])))
            print("--> after reboot, PCR %d will contain value %s" % (idx, to_hex(next_pcrs[idx])))
            print()

    if args.compare:
        print("== Real vs computed PCR values ==")
        real_pcrs = read_current_pcrs(hash_alg)
        errors = 0
        print(" "*7, "%-*s" % (this_pcrs.pcr_size*2, "REAL"), "|", "%-*s" % (next_pcrs.pcr_size*2, "COMPUTED"))
        for idx in wanted_pcrs:
            if real_pcrs[idx] == this_pcrs[idx]:
                status = "+"
            else:
                errors += 1
                status = "<BAD>"
            print("PCR %2d:" % idx, to_hex(real_pcrs[idx]), "|", to_hex(this_pcrs[idx]), status)
        exit(errors > 0)

    for idx in wanted_pcrs:
        if idx <= 7 and this_pcrs.count[idx] == 0:
            # The first 8 PCRs always have an EV_SEPARATOR logged to them at the very least,
            # and the first 3 or so will almost always have other boot events. If we never saw
            # anything then the whole bank might be unused (and an all-zeros PCR value is
            # obviously unsafe to bind against).
            exit("error: Log contains no entries for PCR %d in the %r bank." % (idx, hash_alg))

    if args.verbose or (not args.output):
        print("== Final computed & predicted PCR values ==")
        print(" "*7, "%-*s" % (this_pcrs.pcr_size*2, "CURRENT"), "|", "%-*s" % (next_pcrs.pcr_size*2, "PREDICTED NEXT"))
        for idx in wanted_pcrs:
            print("PCR %2d:" % idx, to_hex(this_pcrs[idx]), "|", to_hex(next_pcrs[idx]))

    if errors:
        print("fatal errors occured", file=sys.stderr)
        exit(1)

    if args.output:
        with open(args.output, "wb") as fh:
            for idx in wanted_pcrs:
                fh.write(next_pcrs[idx])
