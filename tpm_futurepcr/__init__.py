#!/usr/bin/env python3
import sys
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

logging.basicConfig(stream=sys.stdout)
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
