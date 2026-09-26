# Command line entry point.

import argparse
import json
import sys

from . import __version__
from . import core
from . import report


def build_parser():
    parser = argparse.ArgumentParser(
        prog="incident-timeline",
        description="Correlate a pcap-triage report with an authlog-sessions report by address.")
    parser.add_argument("--pcap", action="append", default=[], metavar="FILE",
                        help="a pcap-triage --json report; repeat for more than one")
    parser.add_argument("--auth", action="append", default=[], metavar="FILE",
                        help="an authlog-sessions --json report; repeat for more than one")
    parser.add_argument("-n", "--top", type=int, default=20,
                        help="addresses to print in full (default: 20)")
    parser.add_argument("--json", action="store_true",
                        help="print the correlation as JSON instead of a report")
    parser.add_argument("--csv", action="store_true",
                        help="print the addresses table as CSV")
    parser.add_argument("--only-correlated", action="store_true",
                        help="print only addresses seen in both sources")
    parser.add_argument("--fail-on-correlated", action="store_true",
                        help="exit 3 when any address appears in both sources, for a pipeline")
    parser.add_argument("--version", action="version",
                        version=f"incident-timeline {__version__}")
    return parser


def _load(paths):
    reports = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                reports.append(json.load(handle))
        except FileNotFoundError:
            print(f"incident-timeline: no such file: {path}", file=sys.stderr)
            raise SystemExit(2)
        except json.JSONDecodeError as error:
            print(f"incident-timeline: {path} is not valid JSON: {error}", file=sys.stderr)
            raise SystemExit(2)
    return reports


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not args.pcap and not args.auth:
        print("incident-timeline: give at least one --pcap or --auth report", file=sys.stderr)
        return 2

    if args.top < 1:
        print("incident-timeline: --top has to be at least 1", file=sys.stderr)
        return 2

    pcap_reports = _load(args.pcap)
    auth_reports = _load(args.auth)

    entities, capture_first, capture_last = core.correlate(pcap_reports, auth_reports)

    if not entities:
        print("incident-timeline: nothing to correlate in those reports", file=sys.stderr)
        return 1

    if args.only_correlated:
        entities = [entity for entity in entities if entity.verdict == "correlated"]
        if not entities:
            print("incident-timeline: nothing was seen in both sources", file=sys.stderr)
            return 1

    correlated = any(entity.verdict == "correlated" for entity in entities)

    if args.csv:
        print(report.as_csv(entities, capture_first, capture_last), end="")
    elif args.json:
        print(json.dumps(report.as_dict(entities, capture_first, capture_last), indent=2))
    else:
        print(report.render(entities, capture_first, capture_last, top=args.top), end="")

    if args.fail_on_correlated and correlated:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
