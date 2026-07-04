#!/usr/bin/env python3
"""Headless tests for the Control Panel's non-GUI logic.

The tkinter GUI itself can't run without a display, but every piece of
config/service logic lives in importable helper functions, which this
suite exercises.  Run:  python3 test_gui.py
"""

import os
import shutil
import sys
import tempfile
import unittest

import faithfilter_gui as gui


class PathHelperTests(unittest.TestCase):
    def test_get_and_set_by_path(self):
        cfg = {"dns": {"listen_port": 53, "cache": {"enabled": True}}}
        self.assertEqual(gui.get_by_path(cfg, "dns.listen_port"), 53)
        self.assertTrue(gui.get_by_path(cfg, "dns.cache.enabled"))
        self.assertIsNone(gui.get_by_path(cfg, "dns.missing"))
        self.assertEqual(gui.get_by_path(cfg, "a.b.c", "d"), "d")
        gui.set_by_path(cfg, "dns.listen_port", 5353)
        gui.set_by_path(cfg, "email.smtp_host", "smtp.example.com")
        self.assertEqual(cfg["dns"]["listen_port"], 5353)
        self.assertEqual(cfg["email"]["smtp_host"], "smtp.example.com")

    def test_set_by_path_replaces_non_dict(self):
        cfg = {"a": 1}
        gui.set_by_path(cfg, "a.b", 2)   # "a" was a scalar; must become dict
        self.assertEqual(cfg["a"], {"b": 2})


class ListParsingTests(unittest.TestCase):
    def test_parse_and_format_list(self):
        self.assertEqual(gui.parse_list("1.1.1.1\n8.8.8.8"),
                         ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(gui.parse_list("a, b ,c"), ["a", "b", "c"])
        self.assertEqual(gui.parse_list("  \n  "), [])
        self.assertEqual(gui.format_list(["x", "y"]), "x\ny")
        self.assertEqual(gui.format_list(None), "")


class CurfewParsingTests(unittest.TestCase):
    def test_round_trip(self):
        text = "fri,sat 22:00-07:00\n21:30-06:30"
        parsed = gui.parse_curfews(text)
        self.assertEqual(parsed[0], {"from": "22:00", "to": "07:00",
                                     "days": ["fri", "sat"]})
        self.assertEqual(parsed[1], {"from": "21:30", "to": "06:30"})
        # format then re-parse is stable
        again = gui.parse_curfews(gui.format_curfews(parsed))
        self.assertEqual(again, parsed)

    def test_ignores_malformed(self):
        self.assertEqual(gui.parse_curfews("garbage\n\nmon nope"), [])


class ConfigFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_load_merges_defaults(self):
        path = os.path.join(self.tmp, "config.yaml")
        with open(path, "w") as f:
            f.write("dns:\n  listen_port: 5353\n")
        cfg = gui.load_config(path)
        self.assertEqual(cfg["dns"]["listen_port"], 5353)      # from file
        self.assertEqual(cfg["dns"]["listen_ip"], "0.0.0.0")   # from default
        self.assertIn("safe_search", cfg)

    def test_load_missing_file_is_defaults(self):
        cfg = gui.load_config(os.path.join(self.tmp, "none.yaml"))
        self.assertEqual(cfg["dns"]["listen_port"], 53)

    def test_save_round_trip_strips_runtime_keys(self):
        path = os.path.join(self.tmp, "config.yaml")
        cfg = gui.load_config(path)
        cfg["_config_path"] = "/should/not/persist"
        gui.set_by_path(cfg, "email.username", "me@example.com")
        gui.save_config(path, cfg)
        reloaded = gui.load_config(path)
        self.assertEqual(reloaded["email"]["username"], "me@example.com")
        self.assertNotIn("_config_path", reloaded)

    def test_text_file_helpers(self):
        path = os.path.join(self.tmp, "sub", "blocklist.txt")
        gui.write_text_file(path, "a.com\nb.com")
        self.assertTrue(os.path.exists(path))
        self.assertIn("a.com", gui.read_text_file(path))
        self.assertEqual(gui.read_text_file(os.path.join(self.tmp, "no.txt")), "")


class ServiceCommandTests(unittest.TestCase):
    def test_source_mode_returns_python_invocation(self):
        # In this test environment we run from source, so the script path
        # is used and must point at faithfilter.py.
        base = os.path.dirname(os.path.abspath(gui.__file__))
        cmd = gui.find_service_command(base, "/tmp/config.yaml")
        self.assertIsNotNone(cmd)
        self.assertEqual(cmd[0], sys.executable)
        self.assertTrue(cmd[1].endswith("faithfilter.py"))
        self.assertEqual(cmd[2:], ["--config", "/tmp/config.yaml"])

    def test_missing_script_returns_none(self):
        cmd = gui.find_service_command("/nonexistent/dir", "/tmp/c.yaml")
        self.assertIsNone(cmd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
