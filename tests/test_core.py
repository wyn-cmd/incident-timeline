import os
import sys
import unittest

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from incidenttimeline import core  # noqa: E402


def pcap_report(talkers, notable=None, first=1700000000.0, last=1700003600.0):
    return {"first_timestamp": first, "last_timestamp": last,
            "talkers": talkers, "notable": notable or []}


def auth_report(sources, findings=None):
    return {"sources": sources, "findings": findings or []}


class MergePcapTests(unittest.TestCase):
    def test_both_sides_of_a_conversation_get_an_entry(self):
        report = pcap_report([{"src": "1.1.1.1", "dst": "2.2.2.2", "packets": 5, "bytes": 500}])
        addresses, first, last = core.merge_pcap_reports([report])
        self.assertIn("1.1.1.1", addresses)
        self.assertIn("2.2.2.2", addresses)
        self.assertEqual(addresses["1.1.1.1"]["packets"], 5)

    def test_the_capture_window_is_the_widest_seen(self):
        a = pcap_report([{"src": "1.1.1.1", "dst": "2.2.2.2", "packets": 1, "bytes": 1}],
                         first=100.0, last=200.0)
        b = pcap_report([{"src": "3.3.3.3", "dst": "4.4.4.4", "packets": 1, "bytes": 1}],
                         first=50.0, last=300.0)
        addresses, first, last = core.merge_pcap_reports([a, b])
        self.assertEqual(first, 50.0)
        self.assertEqual(last, 300.0)

    def test_a_notable_line_only_attaches_to_the_address_it_names(self):
        report = pcap_report(
            [{"src": "1.1.1.1", "dst": "2.2.2.2", "packets": 1, "bytes": 1},
             {"src": "9.9.9.9", "dst": "8.8.8.8", "packets": 1, "bytes": 1}],
            notable=["1.1.1.1 reached 30 different ports on the hosts it talked to"])
        addresses, _, _ = core.merge_pcap_reports([report])
        self.assertEqual(addresses["1.1.1.1"]["notable"],
                         ["1.1.1.1 reached 30 different ports on the hosts it talked to"])
        self.assertEqual(addresses["9.9.9.9"]["notable"], [])

    def test_two_reports_for_the_same_pair_sum_their_counts(self):
        a = pcap_report([{"src": "1.1.1.1", "dst": "2.2.2.2", "packets": 5, "bytes": 500}])
        b = pcap_report([{"src": "1.1.1.1", "dst": "2.2.2.2", "packets": 3, "bytes": 300}])
        addresses, _, _ = core.merge_pcap_reports([a, b])
        self.assertEqual(addresses["1.1.1.1"]["packets"], 8)
        self.assertEqual(addresses["1.1.1.1"]["bytes"], 800)

    def test_a_talker_missing_src_or_dst_is_skipped_not_a_crash(self):
        report = {"first_timestamp": 100.0, "last_timestamp": 200.0,
                  "talkers": [{"packets": 1, "bytes": 1},
                              {"src": "1.1.1.1", "dst": "2.2.2.2", "packets": 5, "bytes": 500}],
                  "notable": []}
        addresses, _, _ = core.merge_pcap_reports([report])
        self.assertEqual(addresses["1.1.1.1"]["packets"], 5)
        self.assertEqual(len(addresses), 2)


class MergeAuthTests(unittest.TestCase):
    def test_a_single_source_is_recorded(self):
        report = auth_report([{"address": "1.1.1.1", "first": "2023-01-01T00:00:00",
                               "last": "2023-01-01T01:00:00", "events": 10,
                               "failures": 8, "successes": 1, "succeeded_as": ["root"],
                               "outcome": "got in"}])
        addresses = core.merge_auth_reports([report])
        self.assertEqual(addresses["1.1.1.1"]["events"], 10)

    def test_the_same_address_across_two_reports_widens_the_window(self):
        a = auth_report([{"address": "1.1.1.1", "first": "2023-01-01T00:00:00",
                          "last": "2023-01-01T01:00:00", "events": 5,
                          "failures": 5, "successes": 0, "succeeded_as": [], "outcome": "x"}])
        b = auth_report([{"address": "1.1.1.1", "first": "2023-01-01T02:00:00",
                          "last": "2023-01-01T03:00:00", "events": 5,
                          "failures": 5, "successes": 0, "succeeded_as": [], "outcome": "x"}])
        addresses = core.merge_auth_reports([a, b])
        self.assertEqual(addresses["1.1.1.1"]["first"], "2023-01-01T00:00:00")
        self.assertEqual(addresses["1.1.1.1"]["last"], "2023-01-01T03:00:00")
        self.assertEqual(addresses["1.1.1.1"]["events"], 10)

    def test_succeeded_as_names_are_not_duplicated(self):
        a = auth_report([{"address": "1.1.1.1", "first": None, "last": None, "events": 1,
                          "failures": 0, "successes": 1, "succeeded_as": ["root"], "outcome": "x"}])
        b = auth_report([{"address": "1.1.1.1", "first": None, "last": None, "events": 1,
                          "failures": 0, "successes": 1, "succeeded_as": ["root"], "outcome": "x"}])
        addresses = core.merge_auth_reports([a, b])
        self.assertEqual(addresses["1.1.1.1"]["succeeded_as"], ["root"])

    def test_a_source_missing_an_address_is_skipped_not_a_crash(self):
        report = {"sources": [{"first": "2024-01-01T00:00:00", "last": "2024-01-01T00:01:00",
                              "events": 1, "failures": 0, "successes": 1,
                              "succeeded_as": [], "outcome": "x"}],
                  "findings": []}
        addresses = core.merge_auth_reports([report])
        self.assertEqual(addresses, {})


class CorrelateTests(unittest.TestCase):
    def test_an_address_in_both_sources_is_correlated(self):
        pcap = pcap_report([{"src": "1.1.1.1", "dst": "9.9.9.9", "packets": 1, "bytes": 1}])
        auth = auth_report([{"address": "1.1.1.1", "first": "2023-11-14T22:20:00",
                             "last": "2023-11-14T22:40:00", "events": 1, "failures": 1,
                             "successes": 0, "succeeded_as": [], "outcome": "x"}])
        entities, _, _ = core.correlate([pcap], [auth])
        by_address = {e.address: e for e in entities}
        self.assertEqual(by_address["1.1.1.1"].verdict, "correlated")
        self.assertEqual(by_address["9.9.9.9"].verdict, "network-only")

    def test_correlated_addresses_are_sorted_first(self):
        pcap = pcap_report([{"src": "1.1.1.1", "dst": "9.9.9.9", "packets": 1, "bytes": 1}])
        auth = auth_report([{"address": "1.1.1.1", "first": None, "last": None, "events": 1,
                             "failures": 1, "successes": 0, "succeeded_as": [], "outcome": "x"},
                            {"address": "2.2.2.2", "first": None, "last": None, "events": 1,
                             "failures": 1, "successes": 0, "succeeded_as": [], "outcome": "x"}])
        entities, _, _ = core.correlate([pcap], [auth])
        self.assertEqual(entities[0].address, "1.1.1.1")

    def test_the_overlap_check_uses_utc_for_the_epoch_side(self):
        pcap = pcap_report([{"src": "1.1.1.1", "dst": "9.9.9.9", "packets": 1, "bytes": 1}],
                            first=1700000000.0, last=1700003600.0)
        auth = auth_report([{"address": "1.1.1.1", "first": "2023-11-14T22:20:00",
                             "last": "2023-11-14T22:40:00", "events": 1, "failures": 1,
                             "successes": 0, "succeeded_as": [], "outcome": "x"}])
        entities, cap_first, cap_last = core.correlate([pcap], [auth])
        by_address = {e.address: e for e in entities}
        self.assertTrue(by_address["1.1.1.1"].overlaps_capture_window(cap_first, cap_last))

    def test_a_window_far_outside_the_capture_does_not_overlap(self):
        pcap = pcap_report([{"src": "1.1.1.1", "dst": "9.9.9.9", "packets": 1, "bytes": 1}],
                            first=1700000000.0, last=1700003600.0)
        auth = auth_report([{"address": "1.1.1.1", "first": "1999-01-01T00:00:00",
                             "last": "1999-01-01T01:00:00", "events": 1, "failures": 1,
                             "successes": 0, "succeeded_as": [], "outcome": "x"}])
        entities, cap_first, cap_last = core.correlate([pcap], [auth])
        by_address = {e.address: e for e in entities}
        self.assertFalse(by_address["1.1.1.1"].overlaps_capture_window(cap_first, cap_last))

    def test_missing_timestamps_report_unknown_not_false(self):
        pcap = pcap_report([{"src": "1.1.1.1", "dst": "9.9.9.9", "packets": 1, "bytes": 1}])
        auth = auth_report([{"address": "1.1.1.1", "first": None, "last": None, "events": 1,
                             "failures": 1, "successes": 0, "succeeded_as": [], "outcome": "x"}])
        entities, cap_first, cap_last = core.correlate([pcap], [auth])
        by_address = {e.address: e for e in entities}
        self.assertIsNone(by_address["1.1.1.1"].overlaps_capture_window(cap_first, cap_last))

    def test_a_network_only_address_has_no_auth_findings(self):
        pcap = pcap_report([{"src": "1.1.1.1", "dst": "9.9.9.9", "packets": 1, "bytes": 1}],
                            notable=["1.1.1.1 reached 30 different ports on the hosts it talked to"])
        entities, _, _ = core.correlate([pcap], [])
        by_address = {e.address: e for e in entities}
        self.assertEqual(by_address["1.1.1.1"].findings,
                         ["1.1.1.1 reached 30 different ports on the hosts it talked to"])

    def test_empty_inputs_correlate_to_nothing(self):
        entities, cap_first, cap_last = core.correlate([], [])
        self.assertEqual(entities, [])
        self.assertIsNone(cap_first)
        self.assertIsNone(cap_last)

    def test_a_malformed_timestamp_reports_unknown_not_crash(self):
        pcap = pcap_report([{"src": "1.1.1.1", "dst": "9.9.9.9", "packets": 1, "bytes": 1}])
        auth = auth_report([{"address": "1.1.1.1", "first": "not-a-date",
                             "last": "2023-01-01T00:00:00", "events": 1, "failures": 1,
                             "successes": 0, "succeeded_as": [], "outcome": "x"}])
        entities, cap_first, cap_last = core.correlate([pcap], [auth])
        by_address = {e.address: e for e in entities}
        self.assertIsNone(by_address["1.1.1.1"].overlaps_capture_window(cap_first, cap_last))


if __name__ == "__main__":
    unittest.main(verbosity=2)
