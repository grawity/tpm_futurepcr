#!/usr/bin/env python3
import sys
from pathlib import Path
import argparse
import re

from tpm_futurepcr import process_log, TpmAlgorithm, PcrBank
import tpm_futurepcr.logging as logging

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger("tpm_futurepcr")


_HASH_ALG_CHOICES = ["sha1", "sha256"]
_PCRS_MAX_NUM = 24


def validate_pcrlist(pcr_list: str) -> tuple[list[int], str | None]:
    if "+" in pcr_list:
        raise argparse.ArgumentTypeError("PCR specifier may only contain one bank.")

    pcrs_parsed = re.match(rf"((?P<alg>\w+):)?(?P<pcrs>[\d,]+)", pcr_list)
    if pcrs_parsed is None:
        raise argparse.ArgumentTypeError("PCR specifier must have format '<algorithm>:<num>,<num>,...'")

    hash_alg = pcrs_parsed.group("alg")
    pcr_list = list(set(map(int, pcrs_parsed.group("pcrs").split(","))))

    if not all(x < _PCRS_MAX_NUM for x in pcr_list):
        raise argparse.ArgumentTypeError(f"Max index for PCR is {_PCRS_MAX_NUM-1}")

    if hash_alg is not None and hash_alg not in _HASH_ALG_CHOICES:
        raise argparse.ArgumentTypeError(f"Hash algorithm choices are {','.join(_HASH_ALG_CHOICES)}")

    return pcr_list, hash_alg


class KeyValueAction(argparse.Action):
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


def postprocess_args(args: argparse.Namespace) -> argparse.Namespace:
    # hash_alg can be specified both as a standalone argument and as part of the PCR specifier.
    # in case is not specified on either or is specified in both with different values, print the
    # usage string and the error and exit.
    if (args.hash_alg is None and args.pcr_list[1] is None) or \
       (args.hash_alg is not None and args.pcr_list[1] is not None and args.hash_alg != args.pcr_list[1]):
        parser.print_usage()
        print("tpm_futurepcr.py: error: argument -H/--hash-alg: if specified in multiple places, hash algorithm value must be the same in all of them.")
        sys.exit(2)

    # populate properly the hash_alg argument
    args.hash_alg = TpmAlgorithm[(args.hash_alg or args.pcr_list[1]).upper()]
    args.pcr_list = args.pcr_list[0]

    logging.getLogger().setLevel(args.loglevel)

    return args


if __name__ == "__main__":
    # parse the command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-L", "--pcr-list", type=validate_pcrlist, default=','.join(list(map(str, range(24)))),
                        help="comma-separated list of PCR registers, optionally prepended by '<hash algorithm>:'")
    parser.add_argument("-H", "--hash-alg", help="specify the hash algorithm", choices=_HASH_ALG_CHOICES)
    parser.add_argument("-o", "--output", type=Path, help="write binary PCR values to specified file")
    parser.add_argument("--allow-unexpected-bsa", action="store_true", help="accept BOOT_SERVICES_APPLICATION events with weird paths")
    parser.add_argument("--substitute-bsa-unix-path", action=KeyValueAction, default=dict(), help="substitute BOOT_SERVICES_APPLICATION path (syntax: <computed unix path>=<new unix path>)")
    parser.add_argument("--compare", action="store_true", help="compare computed PCRs against live values")
    parser.add_argument("--log-path", type=Path, help="read binary log from an alternative path")

    # TODO: instead of having -v and -d, maybe enable -vv?
    parser.add_argument("-d", "--debug", help="Print lots of debugging statements", action="store_const",
                        dest="loglevel", const=logging.DEBUG, default=logging.INFO)
    parser.add_argument("-v", "--verbose", help="Be verbose", action="store_const", dest="loglevel",
                        const=logging.VERBOSE)

    # post-process CLI arguments
    args = postprocess_args(parser.parse_args())

    # process the event log
    try:
        this_pcrs, next_pcrs = process_log(args.pcr_list, args.hash_alg, args.log_path, args.substitute_bsa_unix_path, args.allow_unexpected_bsa)
    except ValueError:
        logger.error("Because of previous exceptions, the program is terminating")
        exit(1)

    # check if the contents of the first 8 PCRs might suggest something is off
    if this_pcrs.possibly_unused():
        logger.error("This bank is possibly unused")
        logger.debug("PCR registers with 0 events: %s", ', '.join(str(idx) for idx, x in enumerate(this_pcrs.pcrs) if x.count == 0))
        exit(1)

    # if requested, compare the pcr values to the actual ones and exit if different
    if args.compare:
        logger.info("== Real vs computed PCR values ==")
        current = PcrBank.from_current_pcrs(args.hash_alg)
        if this_pcrs != current:
            this_pcrs.show_compare(current)
            exit(1)

    # if requested, write the output file with the calculated values
    if args.output:
        with open(args.output, "wb") as fh:
            for idx in args.pcr_list:
                fh.write(next_pcrs.pcrs[idx].data)
    else:
        logger.info("== Final computed & predicted PCR values ==")
        logger.info("       %-*s | %-*s", this_pcrs.pcr_size * 2, "CURRENT", next_pcrs.pcr_size * 2, "PREDICTED")
        for idx in args.pcr_list:
            logger.info("PCR %2d: %s | %s", idx, this_pcrs.pcrs[idx], next_pcrs.pcrs[idx])
