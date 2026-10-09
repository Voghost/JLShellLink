#!/usr/bin/env python3
"""Synthetic gate unit tests; these fixtures are never platform acceptance evidence."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('readiness', Path(__file__).with_name('check-release-readiness.py'))
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)


def fixture():
    measured = {'passed': True, 'evidenceSha256': 'a' * 64}
    report = {'schemaVersion': 1, 'linkSourceRevision': 'b' * 40,
              'platforms': {}, 'business': dict(measured), 'stress': dict(measured),
              'noRustSidecar': dict(measured), 'signedPackages': dict(measured),
              'recovery': dict(measured), 'compatibility': dict(measured)}
    for platform in readiness.PLATFORMS:
        result = dict(measured)
        result.update({k: True for k in ('registration', 'permissions', 'startup', 'loginBoundary', 'stop', 'upgradeRecovery', 'uninstall')})
        report['platforms'][platform] = result
    report['business'].update(distinctPublicExits=True, directSshSftpHttpPostgres=True, relaySshSftpHttpPostgres=True)
    report['stress'].update(attemptedConcurrentFlows=100, acceptedFlows=64, boundedRejectedFlows=36,
                           slowConsumer=True, packetLoss=True, longConnection=True, repeatedRestarts=True, noLeaks=True)
    report['recovery']['registrationBoundaryVerified'] = True
    return report


class ReadinessTest(unittest.TestCase):
    def test_rejects_absent_platform_or_real_business_case(self):
        for mutate in (lambda r: r['platforms'].pop('windows-x64'),
                       lambda r: r['business'].update(distinctPublicExits=False),
                       lambda r: r['business'].update(relaySshSftpHttpPostgres=False),
                       lambda r: r['signedPackages'].pop('evidenceSha256')):
            report = fixture(); mutate(report)
            with self.assertRaises(ValueError): readiness.validate(report, 'qa')

    def test_load_counts_cannot_be_negative_boolean_or_unaccounted(self):
        for accepted, rejected in ((-1, 101), (101, -1), (True, 99), (64, 35)):
            report = fixture(); report['stress'].update(acceptedFlows=accepted, boundedRejectedFlows=rejected)
            with self.assertRaises(ValueError): readiness.validate(report, 'qa')

    def test_tree_match_allows_main_merge_commit_with_identical_content(self):
        outputs = [subprocess.CompletedProcess([], 0),
                   subprocess.CompletedProcess([], 0, 'c' * 40 + '\n'),
                   subprocess.CompletedProcess([], 0, 'c' * 40 + '\n')]
        with patch.object(readiness.subprocess, 'run', side_effect=outputs):
            self.assertEqual(readiness.validate(fixture(), 'release', 'd' * 40), 'b' * 40)

    def test_rejects_changed_release_tree_and_non_main_source(self):
        cases = [[subprocess.CompletedProcess([], 1)],
                 [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, 'c' * 40),
                  subprocess.CompletedProcess([], 0, 'e' * 40)]]
        for outputs in cases:
            with patch.object(readiness.subprocess, 'run', side_effect=outputs):
                with self.assertRaises(ValueError): readiness.validate(fixture(), 'release', 'd' * 40)

    def test_recovery_does_not_reset_consumed_registration(self):
        report = fixture(); report['recovery']['registrationBoundaryVerified'] = False
        with self.assertRaises(ValueError): readiness.validate(report, 'release')

    def test_schema_boolean_is_not_version_one(self):
        report = fixture(); report['schemaVersion'] = True
        with self.assertRaises(ValueError): readiness.validate(report, 'qa')


if __name__ == '__main__':
    unittest.main()
