#!/usr/bin/env python3
"""Publisher signing boundary tests use generated ephemeral keys only."""
import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("signing", Path(__file__).with_name("sign-agent-manifests.py"))
signing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signing)


class SigningTest(unittest.TestCase):
    def test_signs_exact_bytes_and_openssl_rejects_modified_manifest(self):
        with tempfile.TemporaryDirectory(prefix="agent-sign-test-") as temporary:
            root = Path(temporary)
            key = signing.run("openssl", "genpkey", "-algorithm", "Ed25519", "-outform", "DER")
            manifests = []
            for platform in ["linux-x64", "macos-arm64", "windows-x64"]:
                path = root / f"jlshell-link-agent-java-1.2.3-{platform}.manifest.json"
                path.write_bytes(json.dumps({"platform": platform}).encode() + b"\n")
                manifests.append(path)
            key_id = signing.sign(root, base64.b64encode(key).decode())
            self.assertEqual(len(key_id), 64)
            key_file = root / "key.der"
            key_file.write_bytes(key)
            public = root / "public.der"
            public.write_bytes(signing.run("openssl", "pkey", "-inform", "DER", "-in", str(key_file), "-pubout", "-outform", "DER"))
            for manifest in manifests:
                envelope = json.loads(manifest.with_name(manifest.name.replace(".manifest.json", ".signature.json")).read_text())
                self.assertEqual(envelope["keyId"], key_id)
                signature = root / "signature.bin"
                signature.write_bytes(base64.b64decode(envelope["signature"], validate=True))
                command = ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", str(public),
                           "-in", str(manifest), "-sigfile", str(signature)]
                self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
                manifest.write_bytes(manifest.read_bytes().rstrip(b"\n"))
                self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_rejects_missing_platforms_and_non_ed25519_keys(self):
        with tempfile.TemporaryDirectory(prefix="agent-sign-test-") as temporary:
            root = Path(temporary)
            with self.assertRaises(ValueError):
                signing.sign(root, "invalid")
            for platform in ["linux-x64", "macos-arm64", "windows-x64"]:
                (root / f"jlshell-link-agent-java-1.2.3-{platform}.manifest.json").write_bytes(b"{}")
            key = signing.run("openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-outform", "DER")
            with self.assertRaises(ValueError):
                signing.sign(root, base64.b64encode(key).decode())


if __name__ == "__main__":
    unittest.main()
