#!/usr/bin/env python3
import sys

from tpm_futurepcr import create_argparser, postprocess_args, to_hex, process_log, compare_pcrs, \
    possibly_unused_bank
import tpm_futurepcr.logging as logging

logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger('tpm_futurepcr')


if __name__ == "__main__":
    parser = create_argparser()
    args = postprocess_args(parser.parse_args())

    # process the event log
    this_pcrs, next_pcrs, errors = process_log(args, args.pcr_list, args.hash_alg)
    if errors:
        logger.error("fatal errors occured")
        exit(1)

    # if requested, compare the pcr values and exist if different
    if args.compare and compare_pcrs(args.hash_alg, this_pcrs, next_pcrs, args.pcr_list):
        exit(1)

    # check if the contents of the first 8 PCRs might suggest something is off
    if possibly_unused_bank(args.hash_alg, args.pcr_list, this_pcrs):
        exit(1)

    # if requested, write the output file with the calculated values
    if args.output:
        with open(args.output, "wb") as fh:
            for idx in args.pcr_list:
                fh.write(next_pcrs[idx])
    else:
        logger.info("== Final computed & predicted PCR values ==")
        logger.info("       %-*s | %-*s", this_pcrs.pcr_size * 2, "CURRENT", next_pcrs.pcr_size * 2, "PREDICTED")
        for idx in args.pcr_list:
            logger.info("PCR %2d: %s | %s", idx, to_hex(this_pcrs[idx]), to_hex(next_pcrs[idx]))
