# Correlates a pcap-triage report with an authlog-sessions report by shared
# address, so an address seen scanning or exfiltrating in a capture and an
# address seen brute forcing or logging in from an auth log are shown as one
# entity instead of two unrelated pages.
#
# This deliberately does not invent a merged timeline finer than either
# source actually supports. pcap-triage reports one window for the whole
# capture, not one per address, so the network side of an address only ever
# gets that whole-capture window. authlog-sessions does track a real window
# per address, so the auth side gets its own first/last. What this tool adds
# is the fact of the overlap, not a fabricated shared clock.

from datetime import datetime, timezone
import re


def _mentions_address(line, address):
    # A whole-token match rather than a substring match: "10.0.0.1" must not
    # match inside "10.0.0.10", and an IPv6 address must not match inside a
    # longer one that happens to share a prefix. re.escape handles the dots
    # and colons an address is built from, and the boundaries either side
    # are checked by hand since \b does not fire around punctuation like a
    # dot the way it does around letters and digits.
    pattern = re.escape(address)
    for match in re.finditer(pattern, line):
        start, end = match.span()
        before = line[start - 1] if start > 0 else " "
        after = line[end] if end < len(line) else " "
        if not (before.isalnum() or before in ".:") and not (after.isalnum() or after in ".:"):
            return True
    return False


def _parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        # A malformed timestamp must not take the whole report down.
        return None


class Correlated:
    # Everything known about one address, from either or both sources.
    def __init__(self, address):
        self.address = address
        self.network = None
        self.auth = None

    @property
    def verdict(self):
        if self.network and self.auth:
            return "correlated"
        if self.network:
            return "network-only"
        return "auth-only"

    @property
    def findings(self):
        # Network findings first: a scan or a leak on the wire is a fact
        # about the wire independent of what the auth log says, and reading
        # it before the login history keeps the report in the order the
        # sibling tools already use, worst first.
        lines = []
        if self.network:
            lines.extend(self.network.get("notable", []))
        if self.auth:
            lines.extend(self.auth.get("notable", []))
        if self.verdict == "correlated":
            lines.append(
                f"{self.address} appears in both the capture and the auth log, "
                "which the underlying tools cannot see on their own")
        return lines

    def overlaps_capture_window(self, capture_first, capture_last):
        # Whether this address's auth activity window falls inside the
        # capture's window. None when either side has no timestamps, since
        # "unknown" is a different answer from "no".
        #
        # pcap-triage reports a real Unix epoch, which is unambiguous, so it
        # is read here with utcfromtimestamp rather than fromtimestamp: the
        # local variant depends on the machine running this comparison,
        # which has nothing to do with where the capture or the log came
        # from. authlog-sessions carries no timezone at all, since a syslog
        # line never has one, so its timestamp is whatever wall clock the
        # machine that wrote the log was set to. When capture and log come
        # from different systems in different zones, an overlap can be
        # missed or invented; that is a real limitation of the inputs and
        # not something this tool can paper over, so it is called out in
        # the report rather than silently assumed away.
        if not self.auth:
            return None
        first = _parse_iso(self.auth.get("first"))
        last = _parse_iso(self.auth.get("last"))
        if not first or not last or not capture_first or not capture_last:
            return None
        cap_first = datetime.fromtimestamp(capture_first, tz=timezone.utc).replace(tzinfo=None)
        cap_last = datetime.fromtimestamp(capture_last, tz=timezone.utc).replace(tzinfo=None)
        return first <= cap_last and last >= cap_first


def merge_pcap_reports(reports):
    # Several pcap-triage JSON reports collapsed into one addresses map,
    # keyed by whichever address the report recorded traffic for. talkers
    # carries both a src and a dst, and either side of a conversation is
    # worth a network entry: the src for what it sent, the dst for what
    # arrived at it.
    addresses = {}
    capture_first = None
    capture_last = None

    for report in reports:
        first = report.get("first_timestamp")
        last = report.get("last_timestamp")
        if first is not None:
            capture_first = first if capture_first is None else min(capture_first, first)
        if last is not None:
            capture_last = last if capture_last is None else max(capture_last, last)

        seen_here = set()
        for talker in report.get("talkers", []):
            seen_here.add(talker["src"])
            seen_here.add(talker["dst"])

        for address in seen_here:
            entry = addresses.setdefault(address, {
                "packets": 0, "bytes": 0, "notable": [],
            })
            for talker in report.get("talkers", []):
                if talker["src"] == address or talker["dst"] == address:
                    entry["packets"] += talker.get("packets", 0)
                    entry["bytes"] += talker.get("bytes", 0)

        for line in report.get("notable", []):
            # Not every notable line opens with the address: most do
            # ("SRC reached N different ports"), but at least one opens
            # with a count instead ("N requests from SRC to DST carried
            # credentials..."), and one names no address at all. So every
            # candidate address is checked, but as a whole word rather than
            # a substring, since a plain "if address in line" credits
            # 10.0.0.1 with a finding that actually names 10.0.0.10.
            for address in seen_here:
                if _mentions_address(line, address) and line not in addresses[address]["notable"]:
                    addresses[address]["notable"].append(line)

    return addresses, capture_first, capture_last


def merge_auth_reports(reports):
    # Several authlog-sessions JSON reports collapsed into one addresses map.
    # A single address across two log exports keeps the wider first/last and
    # sums the event counts, rather than one report silently shadowing the
    # other.
    addresses = {}

    for report in reports:
        by_address = {line.split(" ", 1)[0]: line for line in report.get("findings", [])}
        for source in report.get("sources", []):
            address = source["address"]
            entry = addresses.get(address)
            if entry is None:
                entry = {
                    "first": source.get("first"), "last": source.get("last"),
                    "events": 0, "failures": 0, "successes": 0,
                    "succeeded_as": [], "outcome": source.get("outcome", ""),
                    "notable": [],
                }
                addresses[address] = entry

            entry["events"] += source.get("events", 0)
            entry["failures"] += source.get("failures", 0)
            entry["successes"] += source.get("successes", 0)
            for name in source.get("succeeded_as", []):
                if name not in entry["succeeded_as"]:
                    entry["succeeded_as"].append(name)
            if source.get("first") and (not entry["first"] or source["first"] < entry["first"]):
                entry["first"] = source["first"]
            if source.get("last") and (not entry["last"] or source["last"] > entry["last"]):
                entry["last"] = source["last"]

        for line in report.get("findings", []):
            address = line.split(" ", 1)[0]
            if address in addresses and line not in addresses[address]["notable"]:
                addresses[address]["notable"].append(line)

    return addresses


def correlate(pcap_reports, auth_reports):
    # The full picture: one Correlated per address seen on either side, plus
    # the capture's own window for the overlap check.
    network, capture_first, capture_last = merge_pcap_reports(pcap_reports)
    auth = merge_auth_reports(auth_reports)

    entities = {}
    for address, data in network.items():
        entities.setdefault(address, Correlated(address)).network = data
    for address, data in auth.items():
        entities.setdefault(address, Correlated(address)).auth = data

    ordered = sorted(
        entities.values(),
        key=lambda item: (item.verdict != "correlated", -len(item.findings), item.address),
    )
    return ordered, capture_first, capture_last
