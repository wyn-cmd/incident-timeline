# Writes a --pcap and an --auth JSON report that share one address, so the
# correlation actually has something to find. Point incident-timeline at the
# two files it writes to see a real correlated result.

import json
import sys


def main():
    pcap_path = sys.argv[1] if len(sys.argv) > 1 else "sample-pcap.json"
    auth_path = sys.argv[2] if len(sys.argv) > 2 else "sample-auth.json"

    pcap_report = {
        "packets": 60,
        "bytes": 5200,
        "first_timestamp": 1700000000.0,
        "last_timestamp": 1700003600.0,
        "duration_seconds": 3600.0,
        "talkers": [
            {"src": "203.0.113.9", "dst": "10.0.0.20", "packets": 55, "bytes": 5000},
        ],
        "protocols": {"TCP": 60},
        "services": {"TCP/22": 55, "TCP/443": 5},
        "notable": [
            "203.0.113.9 reached 34 different ports on the hosts it talked to",
        ],
    }

    auth_report = {
        "files": ["/var/log/auth.log"],
        "hosts": ["db02"],
        "sources": [
            {
                "address": "203.0.113.9",
                "first": "2023-11-14T22:15:00",
                "last": "2023-11-14T22:50:00",
                "connections": 1,
                "events": 34,
                "failures": 31,
                "successes": 1,
                "usernames": {"root": 12, "admin": 8},
                "succeeded_as": ["root"],
                "outcome": "got in as root after 31 failure(s)",
                "commands": ["/bin/cat /etc/shadow"],
                "account_changes": [],
            },
        ],
        "findings": [
            "203.0.113.9 failed 31 time(s) and then got in as root",
        ],
    }

    with open(pcap_path, "w", encoding="utf-8") as handle:
        json.dump(pcap_report, handle, indent=2)
    with open(auth_path, "w", encoding="utf-8") as handle:
        json.dump(auth_report, handle, indent=2)

    print(f"wrote {pcap_path} and {auth_path}")
    print(f"read them with: python3 -m incidenttimeline --pcap {pcap_path} --auth {auth_path}")


if __name__ == "__main__":
    main()
