#!/usr/bin/env python3
"""Observer regressions; all PM2, /proc and network access is mocked."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import live_observe


class LiveObserveTests(unittest.TestCase):
    def observe_fixture(self, stopped_pid=0):
        apps = [
            {"name": "cypherdex1", "pid": stopped_pid, "pm_id": 8,
             "pm2_env": {"status": "stopped"}},
            {"name": "cyphermine", "pid": 100, "pm_id": 7,
             "pm2_env": {"status": "online"}},
            {"name": "unrelated", "pid": 200, "pm_id": 90,
             "pm2_env": {"status": "online"}},
        ]
        # PID 1 and kernel/root siblings must never become descendants of a
        # stopped app's PM2 sentinel. The active app has a shell and sidecar.
        table = {1: (0, 10, []), 2: (0, 10, []), 20: (1, 15, []),
                 100: (20, 30, []), 101: (100, 31, []), 102: (101, 32, []),
                 200: (20, 40, []), 201: (200, 41, []),
                 301: (300, 50, [])}
        text = {"/root/.pm2/pm2.pid": "20\n",
                "/proc/sys/kernel/random/boot_id": "fixture-boot\n",
                "/proc/meminfo": "MemAvailable: 1000000 kB\n"}
        seen = []

        def process(pid, supplied):
            self.assertIs(supplied, table)
            seen.append(pid)
            return {"pid": pid, "ppid": table[pid][0], "flags": {}}

        with patch.object(live_observe.subprocess, "check_output", return_value=json.dumps(apps).encode()) as pm2, \
                patch.object(live_observe, "processes", return_value=table), \
                patch.object(live_observe, "process", side_effect=process), \
                patch.object(Path, "is_file", lambda p: str(p) == "/root/.pm2/pm2.pid"), \
                patch.object(Path, "is_dir", lambda p: str(p) == "/proc/20"), \
                patch.object(Path, "read_text", lambda p: text[str(p)]), \
                patch.object(live_observe.os, "statvfs", return_value=SimpleNamespace(f_bavail=100, f_frsize=4096)), \
                patch.object(live_observe.urllib.request, "urlopen", side_effect=OSError("fixture unavailable")):
            result = live_observe.observation(Path("/fixture"), include_added_commons=True)
        pm2.assert_called_once_with(["pm2", "jlist"], timeout=15)
        return {a["name"]: a for a in result["apps"]}, seen, result

    def test_stopped_pid_zero_has_no_processes(self):
        apps, seen, result = self.observe_fixture()
        self.assertEqual(apps["cypherdex1"]["processes"], [])
        self.assertEqual([p["pid"] for p in apps["cyphermine"]["processes"]], [100, 101, 102])
        self.assertEqual(seen, [100, 101, 102])
        self.assertEqual(result["other_pm2_app_count"], 1)

    def test_missing_parent_does_not_adopt_orphan_child(self):
        apps, seen, _ = self.observe_fixture(stopped_pid=300)
        self.assertEqual(apps["cypherdex1"]["processes"], [])
        self.assertNotIn(301, seen)

    def test_invalid_root_cannot_select_pid_one_or_a_process_tree(self):
        table = {1: (0, 10, []), 100: (1, 11, [])}
        for pid in (0, -1, None, False, True, "0", "100", 100.0):
            with self.subTest(pid=pid):
                self.assertEqual(live_observe.descendant_pids(pid, table), set())


if __name__ == "__main__":
    unittest.main()
