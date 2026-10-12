import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('package_agent', Path(__file__).with_name('package-java-agent.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class PowerShellEncodingTest(unittest.TestCase):
    def test_adds_single_bom_and_preserves_unicode_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); source = 'Write-Host "服务已移除；身份保留。"\n'
            script = root / 'installer.ps1'; script.write_text(source, encoding='utf-8')
            other = root / 'agent.sh'; other.write_bytes(b'#!/bin/sh\n')
            module.normalize_powershell_encoding(root)
            once = script.read_bytes()
            self.assertTrue(once.startswith(b'\xef\xbb\xbf'))
            self.assertEqual(source, once.decode('utf-8-sig'))
            module.normalize_powershell_encoding(root)
            self.assertEqual(once, script.read_bytes())
            self.assertEqual(b'#!/bin/sh\n', other.read_bytes())

if __name__ == '__main__':
    unittest.main()
