import io
import json
import os
import sys
import tempfile
import unittest

from contextlib import redirect_stdout, redirect_stderr

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from incidenttimeline import cli  # noqa: E402


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class LoadErrorTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="incident-timeline-cli-test-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.work, ignore_errors=True))

    def test_a_missing_file_returns_two_not_a_raise(self):
        missing = os.path.join(self.work, "nope.json")
        code, out, err = run(["--pcap", missing])
        self.assertEqual(code, 2)
        self.assertIn("no such file", err)

    def test_invalid_json_returns_two_not_a_raise(self):
        path = os.path.join(self.work, "bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{not valid json")
        code, out, err = run(["--pcap", path])
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)

    def test_the_wrong_json_shape_names_which_flag_it_came_from(self):
        path = os.path.join(self.work, "list.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump([1, 2, 3], handle)
        code, out, err = run(["--pcap", path])
        self.assertEqual(code, 2)
        self.assertIn("--pcap", err)

    def test_a_wrong_shaped_auth_report_names_auth_not_pcap(self):
        path = os.path.join(self.work, "list.json")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump([1, 2, 3], handle)
        code, out, err = run(["--auth", path])
        self.assertEqual(code, 2)
        self.assertIn("--auth", err)


    def test_a_dash_reads_from_stdin(self):
        payload = json.dumps({"first_timestamp": 1.0, "last_timestamp": 2.0,
                              "talkers": [], "notable": []})
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(payload)
        try:
            code, out, err = run(["--pcap", "-"])
        finally:
            sys.stdin = old_stdin
        # No entities in an empty report is a clean "nothing to correlate",
        # not a crash: the point of this test is that stdin was actually read.
        self.assertEqual(code, 1)
        self.assertIn("nothing to correlate", err)

    def test_dash_twice_for_the_same_flag_is_a_clean_error(self):
        payload = json.dumps({"first_timestamp": 1.0, "last_timestamp": 2.0,
                              "talkers": [], "notable": []})
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(payload)
        try:
            code, out, err = run(["--pcap", "-", "--pcap", "-"])
        finally:
            sys.stdin = old_stdin
        self.assertEqual(code, 2)
        self.assertIn("only be read once", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
