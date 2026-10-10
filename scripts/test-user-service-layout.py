#!/usr/bin/env python3
"""Offline input-boundary tests; no real service manager is invoked."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "java-agent/user-service-layout.sh"


class LayoutTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "private install"
        self.root.mkdir(mode=0o700)
        self.operator = self.root.parent / "operator"
        self.script = self.root.parent / "layout.sh"
        self.script.write_text(SCRIPT.read_text().replace("$HOME", "$JLSHELL_LINK_TEST_HOME"))

    def invoke(self, directory=None, instance="acceptance", action="status"):
        env = dict(os.environ, JLSHELL_LINK_TEST_HOME=str(self.operator), JLSHELL_LINK_INSTALL_ROOT=str(directory or self.root),
                   JLSHELL_LINK_SERVICE_INSTANCE=instance)
        return subprocess.run(["sh", "-c", 'ACTION=$2; . "$1"; printf "%s\\n" "$APP_DIR" "$UNIT_NAME"',
                               "layout-test", str(self.script), action], env=env, capture_output=True)

    def test_space_path_and_separate_service_name(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.root / "app").encode(), result.stdout)
        self.assertIn(b"jlshell-link-agent-acceptance", result.stdout)

    def test_rejects_shared_root(self):
        self.root.chmod(0o750)
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_rejects_symlink_root(self):
        link = self.root.with_name("alias")
        link.symlink_to(self.root)
        self.assertNotEqual(self.invoke(directory=link).returncode, 0)

    def test_rejects_child_directory_symlink(self):
        (self.root / "state").symlink_to(self.root.parent)
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_rejects_invalid_service_names(self):
        for name in ("", "-agent", "../agent", "name.service", "a" * 33, "a\nother"):
            with self.subTest(name=name):
                self.assertNotEqual(self.invoke(instance=name).returncode, 0)

    def test_rejects_relative_and_control_paths(self):
        for path in ("relative", str(self.root) + "\nother", str(self.root) + "\rother", str(self.root) + "%", str(self.root) + "\\"):
            with self.subTest(path=path):
                self.assertNotEqual(self.invoke(directory=path).returncode, 0)

    def test_install_binds_root_to_one_instance(self):
        self.assertEqual(self.invoke(action="install").returncode, 0)
        marker = self.root / ".service-instance"
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertNotEqual(self.invoke(instance="another").returncode, 0)
        self.assertEqual(self.invoke().returncode, 0)

    def test_rejects_symlink_instance_marker(self):
        (self.root / ".service-instance").symlink_to(self.root.parent / "missing")
        self.assertNotEqual(self.invoke(action="install").returncode, 0)

    def test_rejects_service_name_registered_to_another_root(self):
        unit = self.operator / ".config/systemd/user/jlshell-link-agent-acceptance.service"
        unit.parent.mkdir(parents=True)
        unit.symlink_to(self.root.parent / "another.service")
        self.assertNotEqual(self.invoke(action="install").returncode, 0)
        self.assertFalse((self.root / ".service-instance").exists())

    def test_rejects_launchagent_registered_to_another_root(self):
        plist = self.operator / "Library/LaunchAgents/com.jlshell.link.agent.acceptance.plist"
        plist.parent.mkdir(parents=True)
        plist.write_text("<string>/another/app/run-agent.sh</string>")
        self.assertNotEqual(self.invoke(action="install").returncode, 0)


if __name__ == "__main__":
    unittest.main()
