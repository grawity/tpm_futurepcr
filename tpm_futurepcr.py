#!/usr/bin/env python3
import sys

from tpm_futurepcr import create_argparser, postprocess_args, PcrBank, enum_log_entries, NUM_PCRS, \
    show_log_entry, TpmEventType, parse_efi_bsa_event, device_path_to_unix_path, hash_pecoff, \
    to_hex, loader_get_next_cmdline, loader_decode_pcr8, loader_encode_pcr8, hash_bytes, \
    read_current_pcrs

if __name__ == "__main__":
    parser = create_argparser()
    args = postprocess_args(parser.parse_args())

    wanted_pcrs, hash_alg = args.hash_alg, args.pcr_list
    verbose_all_pcrs = len(args.pcr_list) == NUM_PCRS

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

        this_extend_value = event["pcr_extend_values"].get(args.hash_alg)
        next_extend_value = this_extend_value

        if this_extend_value is None:
            if _verbose_pcr:
                print("event does not update the specified PCR bank, skipping")
            continue

        if event["event_type"] == TpmEventType.EFI_BOOT_SERVICES_APPLICATION:
            event_data = parse_efi_bsa_event(event["event_data"])
            try:
                unix_path = device_path_to_unix_path(event_data["device_path_vec"])
                if args.substitute_bsa_unix_path:
                    unix_path = args.substitute_bsa_unix_path.get(unix_path, unix_path)
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

        # Handle systemd EFI stub "kernel command line" measurements (found in
        # PCR 8 up to systemd v250, but PCR 12 afterwards).
        if event["event_type"] == TpmEventType.IPL and (idx in wanted_pcrs):
            try:
                cmdline = loader_get_next_cmdline(last_efi_binary)
                if args.verbose:
                    old_cmdline = event["event_data"]
                    # 2022-03-19 grawity: In the past, we had to strip away the last \0 byte for
                    # some reason (which I don't remember)... but apparently now we don't? Let's
                    # add a warning so that hopefully I remember why it was necessary.
                    if len(old_cmdline) % 2 != 0:
                        print("warning: Expecting EV_IPL data to contain UTF-16, but length isn't a multiple of 2",
                              file=sys.stderr)
                        old_cmdline += b'\0'
                    old_cmdline = loader_decode_pcr8(old_cmdline)
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

    if errors:
        print("fatal errors occured", file=sys.stderr)
        exit(1)

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

    if args.output:
        with open(args.output, "wb") as fh:
            for idx in wanted_pcrs:
                fh.write(next_pcrs[idx])
