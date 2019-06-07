#!/usr/bin/env python3
import argparse
import sys

from .event_log import *
from .systemd_boot import (
    loader_extend_pcr8,
    loader_get_next_cmdline,
)
from .tpm_constants import TpmEventType
from .util import *

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-L", "--pcr-list",
                        help="limit output to specified PCR indexes")
    parser.add_argument("-o", "--output",
                        help="write binary PCR values to specified file")
    parser.add_argument("--compare", action="store_true",
                        help="compare computed PCRs against live values")
    parser.add_argument("--verbose", action="store_true",
                        help="show verbose information about log parsing")
    args = parser.parse_args()

    if args.pcr_list:
        verbose_all_pcrs = False
        wanted_pcrs = [int(idx) for idx in args.pcr_list.split(",")]
    else:
        verbose_all_pcrs = True
        wanted_pcrs = [*range(NUM_PCRS)]

    this_pcrs = init_empty_pcrs()
    next_pcrs = {**this_pcrs}

    # TODO: Figure out why PCR[5] does not match the computed one.

    for event in enum_log_entries():
        idx = event["pcr_idx"]
        this_extend_value = event["pcr_extend_value"]
        next_extend_value = this_extend_value

        _verbose_pcr = (args.verbose and (verbose_all_pcrs or idx in wanted_pcrs))
        if _verbose_pcr:
            show_log_entry(event)

        if event["event_type"] == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
            event_data = parse_efi_bsa_event(event["event_data"])
            unix_path = device_path_to_unix_path(event_data["device_path_vec"])
            if not unix_path:
                # this might be a firmware item such as the boot menu
                if args.verbose:
                    print("entry didn't map to a Linux path")
                    continue
                else:
                    print("exiting due to unusual boot process events", file=sys.stderr)
                    exit(1)
            file_hash = hash_pecoff(unix_path, "sha1")
            next_extend_value = file_hash
            if _verbose_pcr:
                print("-- extending with coff hash --")
                print("file path =", unix_path)
                print("file hash =", to_hex(file_hash))
                print("this event extend value =", to_hex(this_extend_value))
                print("guessed extend value =", to_hex(next_extend_value))

        if event["event_type"] != TpmEventType.NO_ACTION:
            this_pcrs[idx] = extend_pcr_with_hash(this_pcrs[idx], this_extend_value)
            next_pcrs[idx] = extend_pcr_with_hash(next_pcrs[idx], next_extend_value)

        if _verbose_pcr:
            print("--> after this event, PCR %d contains value %s" % (idx, to_hex(this_pcrs[idx])))
            print("--> after reboot, PCR %d will contain value %s" % (idx, to_hex(next_pcrs[idx])))
            print()


    # HACK: systemd-boot doesn't generate a log entry when extending PCR[8], do it ourselves
    # (not sure why, as it calls HashLogExtendEvent and there should be an EV_IPL(13) event)
    # 2019-06-07: Probably fixed in systemd commit v242-780-gf8e54bf319
    if 8 in wanted_pcrs and this_pcrs[8] == (b"\x00" * PCR_SIZE):
        if args.verbose:
            print("PCR 8: synthesizing kernel cmdline event to match systemd-boot")
        idx = 8
        this_pcrs[idx] = read_current_pcr(idx)
        try:
            cmdline = loader_get_next_cmdline()
            if args.verbose:
                print("guessed next cmdline:", cmdline)
            next_pcrs[idx] = loader_extend_pcr8(next_pcrs[idx], cmdline)
        except FileNotFoundError:
            # Either some of the EFI variables, or the ESP, or the .conf, are missing.
            # It's probably not a systemd-boot environment, so PCR[8] meaning is undefined.
            if args.verbose:
                print("systemd-boot not detected")
            next_pcrs[idx] = this_pcrs[idx]
        if args.verbose:
            print("--> after this event, PCR %d contains value %s" % (idx, to_hex(this_pcrs[idx])))
            print("--> after reboot, PCR %d will contain value %s" % (idx, to_hex(next_pcrs[idx])))
            print()

    if args.compare:
        print("== Real vs computed PCR values ==")
        real_pcrs = read_current_pcrs(wanted_pcrs)
        errors = 0
        print(" "*7, "%-*s" % (PCR_SIZE*2, "REAL"), "|", "%-*s" % (PCR_SIZE*2, "COMPUTED"))
        for idx in wanted_pcrs:
            if real_pcrs[idx] == this_pcrs[idx]:
                status = "+"
            else:
                errors += 1
                status = "<BAD>"
            print("PCR %2d:" % idx, to_hex(real_pcrs[idx]), "|", to_hex(this_pcrs[idx]), status)
        exit(errors > 0)

    if args.verbose or (not args.output):
        print("== Final computed & predicted PCR values ==")
        print(" "*7, "%-*s" % (PCR_SIZE*2, "CURRENT"), "|", "%-*s" % (PCR_SIZE*2, "PREDICTED NEXT"))
        for idx in wanted_pcrs:
            print("PCR %2d:" % idx, to_hex(this_pcrs[idx]), "|", to_hex(next_pcrs[idx]))

    if args.output:
        with open(args.output, "wb") as fh:
            for idx in wanted_pcrs:
                fh.write(next_pcrs[idx])
