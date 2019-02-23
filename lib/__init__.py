#!/usr/bin/env python3
import argparse
import sys
import os
import hashlib
from pprint import pprint

from .event_log import *
from .systemd_boot import loader_get_next_cmdline
from .tpm_constants import TpmEventType
from .util import (
    hash_pecoff,
    init_empty_pcrs,
    read_current_pcr,
    extend_pcr_with_hash,
    extend_pcr_with_data,
    NUM_PCRS,
    PCR_SIZE
)

quiet = False

# h:s16 H:u16 l:s32 L:u32
# TPMv1: https://sources.debian.org/src/golang-github-coreos-go-tspi/0.1.1-2/tspi/tpm.go/?hl=44#L44

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-L", "--pcr-list",
                        help="limit output to specified PCR indexes")
    parser.add_argument("-o", "--output",
                        help="write binary PCR values to specified file")
    parser.add_argument("--verbose", action="store_true",
                        help="show verbose information about log parsing")
    args = parser.parse_args()

    if args.pcr_list:
        wanted_pcrs = [int(x) for x in args.pcr_list.split(",")]
    else:
        wanted_pcrs = [*range(NUM_PCRS)]

    this_pcrs = init_empty_pcrs()
    next_pcrs = {**this_pcrs}

    for event in enum_log_entries():
        if args.verbose:
            show_log_entry(event)

        idx = event["pcr_idx"]
        this_extend_value = event["pcr_extend_value"]
        next_extend_value = this_extend_value

        if event["event_type"] == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
            event_data = parse_efi_bsa_event(event["event_data"])
            unix_path = device_path_to_unix_path(event_data["device_path_vec"])
            file_hash = hash_pecoff(unix_path, "sha1")
            next_extend_value = file_hash
            if args.verbose:
                print("-- extending with coff hash --")
                print("file path =", unix_path)
                print("file hash =", to_hex(file_hash))
                print("this event extend value =", to_hex(this_extend_value))
                print("guessed extend value =", to_hex(next_extend_value))

        this_pcrs[idx] = extend_pcr_with_hash(this_pcrs[idx], this_extend_value)
        next_pcrs[idx] = extend_pcr_with_hash(next_pcrs[idx], next_extend_value)
        if args.verbose:
            print("--> after this event, PCR %d contains value %s" % (idx, to_hex(this_pcrs[idx])))
            print("--> after reboot, PCR %d will contain value %s" % (idx, to_hex(next_pcrs[idx])))
            print()

    # HACK: systemd-boot doesn't generate a log entry when extending PCR[8], do it ourselves
    if 8 in wanted_pcrs and this_pcrs[8] == (b"\x00" * PCR_SIZE):
        idx = 8
        this_pcrs[idx] = read_current_pcr(idx)
        try:
            cmdline = loader_get_next_cmdline()
        except FileNotFoundError:
            # Either some of the EFI variables, or the ESP, or the .conf, are missing.
            # It's probably not a systemd-boot environment, so PCR[8] meaning is undefined.
            pass
        else:
            if args.verbose:
                print("PCR 8: synthesizing kernel cmdline event to match systemd-boot")
                print("guessed next cmdline =", repr(cmdline))
            cmdline = (cmdline + "\0").encode("utf-16le")
            next_pcrs[idx] = extend_pcr_with_data(next_pcrs[idx], cmdline)
        if args.verbose:
            print("--> after this event, PCR %d contains value %s" % (idx, to_hex(this_pcrs[idx])))
            print("--> after reboot, PCR %d will contain value %s" % (idx, to_hex(next_pcrs[idx])))
            print()

    if args.verbose or (not args.output):
        print("== Final PCR values ==")
        for x in wanted_pcrs:
            print("PCR %2d:" % x, to_hex(this_pcrs[x]), "|", to_hex(next_pcrs[x]))

    if args.output:
        with open(args.output, "wb") as fh:
            for x in wanted_pcrs:
                fh.write(next_pcrs[x])
