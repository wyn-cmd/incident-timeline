import os
import sys
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from incidenttimeline import core, report  # noqa: E402


class AddressMatchingTests(unittest.TestCase):
    def test_an_address_that_is_a_prefix_of_another_is_not_credited(self):
        pcap = {
            "first_timestamp": 100.0, "last_timestamp": 200.0,
            "talkers": [
                {"src": "10.0.0.1", "dst": "9.9.9.9", "packets": 1, "bytes": 1},
                {"src": "10.0.0.10", "dst": "8.8.8.8", "packets": 1, "bytes": 1},
            ],
            "notable": ["10.0.0.10 reached 30 different ports on the hosts it talked to"],
        }
        addresses, _, _ = core.merge_pcap_reports([pcap])
        self.assertEqual(addresses["10.0.0.1"]["notable"], [])
        self.assertEqual(len(addresses["10.0.0.10"]["notable"]), 1)

    def test_a_line_that_opens_with_a_count_still_attaches_to_both_addresses(self):
        pcap = {
            "first_timestamp": 100.0, "last_timestamp": 200.0,
            "talkers": [{"src": "10.0.0.5", "dst": "93.184.216.34", "packets": 1, "bytes": 1}],
            "notable": ["1 request from 10.0.0.5 to 93.184.216.34 carried "
                       "credentials in the clear (Basic, /admin)"],
        }
        addresses, _, _ = core.merge_pcap_reports([pcap])
        self.assertEqual(len(addresses["10.0.0.5"]["notable"]), 1)
        self.assertEqual(len(addresses["93.184.216.34"]["notable"]), 1)

    def test_a_line_naming_no_address_attaches_nowhere(self):
        pcap = {
            "first_timestamp": 100.0, "last_timestamp": 200.0,
            "talkers": [{"src": "1.2.3.4", "dst": "5.6.7.8", "packets": 1, "bytes": 1}],
            "notable": ["no names were asked for, so this capture may be encrypted "
                       "beyond the handshakes or filtered to IP addresses"],
        }
        addresses, _, _ = core.merge_pcap_reports([pcap])
        self.assertEqual(addresses["1.2.3.4"]["notable"], [])
        self.assertEqual(addresses["5.6.7.8"]["notable"], [])


class CsvReportTests(unittest.TestCase):
    def setUp(self):
        pcap = {
            "first_timestamp": 1700000000.0, "last_timestamp": 1700003600.0,
            "talkers": [{"src": "203.0.113.9", "dst": "10.0.0.20", "packets": 55, "bytes": 5000}],
            "notable": [],
        }
        auth = {
            "sources": [{"address": "203.0.113.9", "first": "2023-11-14T22:15:00",
                        "last": "2023-11-14T22:50:00", "events": 34, "failures": 31,
                        "successes": 1, "succeeded_as": ["root"], "outcome": "got in"}],
            "findings": [],
        }
        self.entities, self.first, self.last = core.correlate([pcap], [auth])

    def test_the_header_row_is_present(self):
        text = report.as_csv(self.entities, self.first, self.last)
        self.assertTrue(text.startswith("address,verdict,"))

    def test_a_correlated_row_carries_both_sides(self):
        text = report.as_csv(self.entities, self.first, self.last)
        rows = [r for r in text.strip().split("\n")[1:] if r]
        by_address = {r.split(",")[0]: r for r in rows}
        self.assertIn("203.0.113.9,correlated,55,5000,34,31,1,True", by_address["203.0.113.9"])

    def test_a_network_only_row_leaves_auth_fields_blank(self):
        text = report.as_csv(self.entities, self.first, self.last)
        rows = [r for r in text.strip().split("\n")[1:] if r]
        by_address = {r.split(",")[0]: r for r in rows}
        self.assertTrue(by_address["10.0.0.20"].startswith("10.0.0.20,network-only,55,5000,,,,"))

    def test_a_field_containing_a_comma_is_quoted(self):
        text = report._csv_field("a, b")
        self.assertEqual(text, '"a, b"')

    def test_a_plain_field_is_not_quoted(self):
        self.assertEqual(report._csv_field("plain"), "plain")


class OnlyCorrelatedFilterTests(unittest.TestCase):
    def test_only_correlated_addresses_survive_the_filter(self):
        pcap = {
            "first_timestamp": 100.0, "last_timestamp": 200.0,
            "talkers": [{"src": "1.1.1.1", "dst": "9.9.9.9", "packets": 1, "bytes": 1}],
            "notable": [],
        }
        auth = {
            "sources": [{"address": "1.1.1.1", "first": None, "last": None, "events": 1,
                        "failures": 1, "successes": 0, "succeeded_as": [], "outcome": "x"}],
            "findings": [],
        }
        entities, _, _ = core.correlate([pcap], [auth])
        only_correlated = [e for e in entities if e.verdict == "correlated"]
        self.assertEqual([e.address for e in only_correlated], ["1.1.1.1"])
        self.assertNotIn("9.9.9.9", [e.address for e in only_correlated])


if __name__ == "__main__":
    unittest.main(verbosity=2)
