# incident-timeline

Correlate a pcap-triage report with an authlog-sessions report, so an address seen scanning or leaking credentials on the wire and an address seen brute forcing or logging in on the same box show up as one entry instead of two reports you have to cross-reference by hand.

This is a small tool that sits on top of two others rather than a parser of its own: it reads the `--json` output pcap-triage and authlog-sessions already produce, matches addresses across both, and prints what each side knows plus whether the two actually line up in time.

## What it needs

Python 3.8 or newer. Nothing else, no dependencies to install. It reads JSON that [pcap-triage](https://github.com/wyn-cmd/pcap-triage) and [authlog-sessions](https://github.com/wyn-cmd/authlog-sessions) produce, so having those two on hand is how you get real input, but incident-timeline itself does not import or require either.

## Running it

```
python3 -m pcaptriage --json capture.pcap > net.json
python3 -m authlogsessions --json /var/log/auth.log > auth.json
python3 -m incidenttimeline --pcap net.json --auth auth.json
```

Either flag can be repeated to merge more than one report, and either can be omitted, in which case every address falls on the one side that was given.

To try it without real captures or logs:

```
python3 examples/make-sample-reports.py /tmp/net.json /tmp/auth.json
python3 -m incidenttimeline --pcap /tmp/net.json --auth /tmp/auth.json
```

## What the output looks like

Real output from the sample above, not an illustration:

```
2 address(es) total, 1 seen in both sources

203.0.113.9  [correlated]
  network: 55 packet(s), 5,000 byte(s)
  auth: 34 event(s), 31 failure(s), outcome: got in as root after 31 failure(s)
  the auth activity falls inside the capture's window
  - 203.0.113.9 reached 34 different ports on the hosts it talked to
  - 203.0.113.9 failed 31 time(s) and then got in as root
  - 203.0.113.9 appears in both the capture and the auth log, which the underlying tools cannot see on their own

10.0.0.20  [network-only]
  network: 55 packet(s), 5,000 byte(s)
```

## What counts as a correlation

An address is `correlated` when it shows up in both reports, `network-only` when only the capture saw it, and `auth-only` when only the log saw it. Matching is by address string alone: it does not try to resolve NAT, and an address behind a NAT boundary from the machine that wrote the capture will not correlate with the same address as the auth log saw it, since the two would legitimately not be the same string.

## What it deliberately does not do

- **It does not build a per-address network timeline.** pcap-triage reports one window for the whole capture, not one per address, so the network side of every address shares that one window. The auth side does carry a real per-address window, from authlog-sessions, and that is what the overlap check is against.
- **It does not correct for timezone.** A Unix epoch is unambiguous and is read as UTC here, but a syslog line carries no timezone at all, so an auth log's timestamps are whatever wall clock the machine that wrote it was set to. A capture and a log from systems in different zones can show a false negative or a false positive on the overlap check. That is a property of the inputs, not something this tool can paper over, which is why the header calls it an overlap check rather than a claim.
- **It does not decide anything for you.** It shows what each side already flagged, side by side, and whether the addresses and the windows line up. The judgement is yours.

## Options

```
--pcap FILE              a pcap-triage --json report, or - for stdin; repeat for more than one
--auth FILE              an authlog-sessions --json report, or - for stdin; repeat for more than one
-n, --top N              addresses to print in full, default 20
--only-correlated        print only addresses seen in both sources
--min-events N           drop an address with fewer than N network packets plus auth events combined
--csv                    print the addresses table as CSV, unaffected by --top (cannot combine with --json)
--json                   print the correlation as JSON instead of a report (cannot combine with --csv)
--fail-on-correlated     exit 3 when any address appears in both sources, for a pipeline
```

## Exit codes

```
0  a report was printed, nothing was correlated
1  the reports were readable but held no addresses
2  a file could not be read, was not valid JSON, or the options made no sense
3  a report was printed and at least one address correlated (--fail-on-correlated only)
```

## Testing

```
python3 -m unittest discover tests
```

Fourteen tests covering the merge of several reports on each side, the correlation itself, and the overlap check, including the UTC-versus-naive-timestamp case that motivated writing it as its own function rather than inlining the comparison, plus a full command line suite covering the error paths a malformed or wrong-shaped report file can take and stdin support via `-`.

## How the code is laid out

```
incidenttimeline/core.py     merging reports and matching addresses
incidenttimeline/report.py   the text and the JSON of the output
incidenttimeline/cli.py      argument handling and printing
tests/                       the suite
examples/                    a script that writes two correlating reports
```

## License

MIT. See LICENSE.
