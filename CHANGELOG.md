Changes to incident-timeline, oldest first.

0.1.0
first release: correlate a pcap-triage --json report with an authlog-sessions --json report by shared address, --fail-on-correlated for a pipeline, --csv and --json output.

0.2.0
- fixed a substring address match that could credit 10.0.0.1 with a finding that actually named 10.0.0.10
- fixed a crash on a malformed timestamp, a talker missing src or dst, an auth source missing an address, a non-string notable or findings entry, and a talkers/notable/sources/findings field of the wrong JSON type
- fixed a wrong-shaped report file (for example a JSON array instead of an object) crashing instead of giving a clear error
- fixed main() raising SystemExit internally instead of returning an exit code, which broke embedding it as a library call
- added --csv, --only-correlated, --min-events, and - for stdin on --pcap/--auth
- added a clean error when --csv and --json are given together instead of one silently winning
- added tests/test_cli.py, a full command line test suite that did not exist before
