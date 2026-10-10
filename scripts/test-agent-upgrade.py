#!/usr/bin/env python3
"""Exercise installer file restoration using isolated directories and a fake service manager.

This validates transaction boundaries, not a real systemd/LaunchAgent lifecycle.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class UpgradeTest(unittest.TestCase):
    def exercise(self, fail_start, isolated=False):
        with tempfile.TemporaryDirectory(prefix="agent-upgrade-test-") as temporary:
            root = Path(temporary)
            home = root / "operator"
            package = root / "package"
            scripts = package / "scripts/java-agent"
            scripts.mkdir(parents=True)
            manager = root / "service-manager"
            manager.write_text("""#!/bin/sh
set -eu
case "$*" in
  *'enable --now'*) touch "$JLSHELL_LINK_TEST_HOME/new-start" ;;
  *'is-active'*)
    if [ "$JLSHELL_LINK_TEST_FAIL_START" = true ] && [ -f "$JLSHELL_LINK_TEST_HOME/new-start" ]; then exit 1; fi ;;
  *' start '*) rm -f "$JLSHELL_LINK_TEST_HOME/new-start"; touch "$JLSHELL_LINK_TEST_HOME/old-restored" ;;
esac
""")
            manager.chmod(0o700)
            for name in ["user-service-layout.sh", "upgrade-user-service.sh", "install-user-service.sh", "run-agent.sh", "stop-agent.sh"]:
                source = (ROOT / "scripts/java-agent" / name).read_text()
                # Substitute dependencies only in test copies; never change the real HOME or services.
                source = source.replace("$HOME", "$JLSHELL_LINK_TEST_HOME")
                source = source.replace("systemctl", "'" + str(manager) + "'")
                source = source.replace("$(uname -s)", "Linux").replace("sleep 2", "sleep 0")
                (scripts / name).write_text(source)
            (package / "link-agent.jar").write_bytes(b"new agent")
            runtime = package / "runtime/bin"
            runtime.mkdir(parents=True)
            (runtime / "java").write_text("#!/bin/sh\nexit 0\n")
            (runtime / "java").chmod(0o700)
            app = home / ".local/lib/jlshell-link-agent"
            config = home / ".config/jlshell-link-agent"
            state = home / ".local/state/jlshell-link-agent"
            unit = home / ".config/systemd/user/jlshell-link-agent.service"
            isolated_root = root / "isolated service"
            if isolated:
                isolated_root.mkdir(mode=0o700)
                app, config, state = (isolated_root / name for name in ("app", "config", "state"))
                unit = home / ".config/systemd/user/jlshell-link-agent-acceptance.service"
            for directory in [app, config, state, unit.parent]:
                directory.mkdir(parents=True, exist_ok=True)
            (app / "link-agent.jar").write_bytes(b"previous agent")
            (config / "agent.env").write_bytes(b"previous config")
            (state / "agent.credential").write_bytes(b"fixture only; must remain unchanged")
            if isolated:
                definition = config / "systemd" / unit.name
                definition.parent.mkdir()
                definition.write_bytes(b"previous unit")
                unit.symlink_to(definition)
            else:
                unit.write_bytes(b"previous unit")
            for name in ["identity.p12", "password", "targets", "release.manifest.json", "release.signature.json"]:
                (root / name).write_bytes(b"fixture")
            env = dict(os.environ, JLSHELL_LINK_TEST_HOME=str(home), JLSHELL_LINK_TEST_FAIL_START=str(fail_start).lower())
            if isolated:
                env.update(JLSHELL_LINK_INSTALL_ROOT=str(isolated_root), JLSHELL_LINK_SERVICE_INSTANCE="acceptance")
            command = ["sh", str(scripts / "upgrade-user-service.sh"), "wss://link.example/link/v2/control",
                       str(root / "identity.p12"), str(root / "password"), str(root / "targets"),
                       str(root / "release.manifest.json"), "https://website.example"]
            result = subprocess.run(command, env=env, capture_output=True)
            if fail_start:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((app / "link-agent.jar").read_bytes(), b"previous agent")
                self.assertEqual((config / "agent.env").read_bytes(), b"previous config")
                self.assertEqual(unit.read_bytes(), b"previous unit")
                self.assertTrue((home / "old-restored").exists(), result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((app / "link-agent.jar").read_bytes(), b"new agent")
                self.assertEqual((app / "release.signature.json").read_bytes(), b"fixture")
            self.assertEqual((state / "agent.credential").read_bytes(), b"fixture only; must remain unchanged")
            self.assertFalse((home / ".local/lib/.jlshell-link-upgrade-lock").exists())
            self.assertFalse(list((isolated_root if isolated else home / ".local/lib").glob(".jlshell-link-backup.*")))
            if isolated:
                self.assertFalse((isolated_root / ".upgrade-lock").exists())
                self.assertFalse((home / ".local/lib/jlshell-link-agent").exists())
                if not fail_start:
                    self.assertIn("JLSHELL_LINK_AGENT_CONFIG=", unit.read_text())
                    self.assertIn(str(config / "agent.env"), unit.read_text())

    def test_failed_start_restores_program_config_service_and_preserves_identity(self):
        self.exercise(True)

    def test_isolated_failed_upgrade_restores_only_its_instance(self):
        self.exercise(True, isolated=True)

    def test_isolated_success_uses_explicit_config_and_keeps_default_service_untouched(self):
        self.exercise(False, isolated=True)

    def test_success_retains_signed_metadata_and_preserves_identity(self):
        self.exercise(False)


if __name__ == "__main__":
    unittest.main()
