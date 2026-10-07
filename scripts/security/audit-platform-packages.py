#!/usr/bin/env python3
"""Verify exact platform bundle bytes and scan declared OpenJDK/WinSW CPEs."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

GRYPE_VERSION = '0.120.1'
BINARIES = {('Linux', 'x86_64'): ('linux_amd64', '0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d'),
            ('Darwin', 'arm64'): ('darwin_arm64', 'cf97957fa467d25575ec2cc3228289f391ea51cf88b9cffc5f83dc03d4cbc732')}
WINSW_SHA = '05b82d46ad331cc16bdc00de5c6332c1ef818df8ceefcd49c726553209b3a0da'


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def install(directory):
    name, expected = BINARIES[(platform.system(), platform.machine())]
    url = f'https://github.com/anchore/grype/releases/download/v{GRYPE_VERSION}/grype_{GRYPE_VERSION}_{name}.tar.gz'
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    if checksum(data) != expected:
        raise ValueError('Scanner checksum mismatch')
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        member = archive.getmember('grype')
        if not member.isfile():
            raise ValueError('Scanner is not a regular binary')
        binary = directory / 'grype'; binary.write_bytes(archive.extractfile(member).read()); binary.chmod(0o700)
    return binary


def verify(path):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or not names:
            raise ValueError('Duplicate or empty archive')
        roots = {name.split('/')[0] for name in names}
        if len(roots) != 1:
            raise ValueError('Archive root mismatch')
        prefix = roots.pop() + '/'
        for name in names:
            relative = name[len(prefix):]
            if '\\' in name or name.startswith('/') or '..' in relative.split('/'):
                raise ValueError('Unsafe archive path')
        manifest = json.loads(archive.read(prefix + 'manifest.json'))
        if manifest.get('product') != 'jlshell-link-agent-java' or manifest.get('protocolVersion') != 'jlshell-link-v2':
            raise ValueError('Unexpected bundle product')
        entries = manifest['files']
        declared = {e['path'] for e in entries}
        actual = {n[len(prefix):] for n in names if not n.endswith('/')} - {'manifest.json', 'SHA256SUMS'}
        if len(declared) != len(entries) or actual != declared:
            raise ValueError('Manifest does not cover bundle')
        for entry in entries:
            data = archive.read(prefix + entry['path'])
            if len(data) != entry['sizeBytes'] or checksum(data) != entry['sha256']:
                raise ValueError('Manifest file digest mismatch')
        release = archive.read(prefix + 'runtime/release').decode()
        runtime = re.search(r'^JAVA_RUNTIME_VERSION="([^"]+)"', release, re.M)
        if runtime is None:
            runtime = re.search(r'^JAVA_VERSION="([^"]+)"', release, re.M)
        if runtime is None or not re.fullmatch(r'21\.\d+\.\d+(?:\.\d+)?(?:\+\d+(?:[-.A-Za-z0-9]*)?)?', runtime[1]):
            raise ValueError('Expected a patched Java 21 runtime')
        jar = io.BytesIO(archive.read(prefix + 'link-agent.jar'))
        with zipfile.ZipFile(jar) as classes:
            headers = classes.read('META-INF/MANIFEST.MF').decode().replace('\r\n ', '')
            if 'JLShell-Build-Revision: ' + manifest['sourceRevision'] not in headers.splitlines():
                raise ValueError('Agent JAR source revision does not match bundle')
            if any(n.startswith(('com/sun/jna/', 'org/bitlet/weupnp/')) for n in classes.namelist()):
                raise ValueError('Native loader or UPnP dependency in Java bundle')
        for n in names:
            if re.search(r'(?:jlshell-(?:agent|connector|relay)|libjnidispatch)(?:\.exe|\.dll|\.so|\.dylib)?$',n):
                raise ValueError('Legacy sidecar or native loader in bundle')
        components = [{'type': 'application', 'name': 'openjdk', 'version': runtime[1].split('+')[0],
                       'cpe': f"cpe:2.3:a:oracle:openjdk:{runtime[1].split('+')[0]}:*:*:*:*:*:*:*"}]
        if manifest['platform'] == 'windows':
            if manifest['dependencies'].get('winsw') != '2.12.0' or checksum(archive.read(prefix + 'service/WinSW-x64.exe')) != WINSW_SHA:
                raise ValueError('Unexpected Windows service wrapper')
            components.append({'type': 'application', 'name': 'winsw', 'version': '2.12.0',
                               'cpe': 'cpe:2.3:a:winsw:winsw:2.12.0:*:*:*:*:*:*:*'})
        return manifest, runtime[1], components


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args();args.output.unlink(missing_ok=True)
    packages = sorted(args.directory.glob('*.zip'))
    if len(packages) != 3:
        raise ValueError('Expected exactly three platform ZIP packages')
    checks = []; platforms = set(); revisions = set(); versions = set(); failed = False
    with tempfile.TemporaryDirectory(prefix='link-platform-audit-') as name:
        temporary = Path(name);os.chmod(temporary,0o700)
        binary = install(temporary)
        config = temporary / 'grype.yaml';config.write_text('ignore: []\nmatch:\n  java:\n    using-cpes: true\n')
        for package in packages:
            manifest, runtime, components = verify(package)
            platforms.add((manifest['platform'],manifest['architecture']));revisions.add(manifest['sourceRevision']);versions.add(manifest['version'])
            bom = temporary / 'runtime.json';bom.write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.6','version':1,'components':components}))
            result = subprocess.run([str(binary),'sbom:'+str(bom),'-c',str(config),'-o','json'],capture_output=True)
            if result.returncode:
                raise ValueError('Runtime vulnerability scan failed')
            data = json.loads(result.stdout)
            if not isinstance(data.get('matches'),list):
                raise ValueError('Invalid runtime scanner output')
            findings = [{'id':m['vulnerability']['id'],'severity':m['vulnerability']['severity'],
                         'package':m['artifact']['name'],'version':m['artifact']['version']}
                        for m in data['matches'] if m['vulnerability']['severity'].lower() in ('high','critical')]
            failed |= bool(findings)
            checks.append({'platform':manifest['platform'],'architecture':manifest['architecture'],
                           'runtimeVersion':runtime,'runtimeCpes':[c['cpe'] for c in components],
                           'blockingVulnerabilities':findings})
    if platforms != {('linux','x64'),('macos','arm64'),('windows','x64')} or len(revisions)!=1 or len(versions)!=1:
        raise ValueError('Platform release consistency mismatch')
    report = {'schemaVersion':1,'scanner':f'grype/{GRYPE_VERSION}','sourceRevision':revisions.pop(),
              'version':versions.pop(),'checks':checks,'passed':not failed,
              'coverage':'Declared OpenJDK/WinSW CPEs plus complete file checksums; CPE absence is not proof of no vulnerabilities.'}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n')
    print('Platform package gates: '+('FAIL' if failed else 'PASS'))
    return int(failed)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError,ValueError,KeyError,zipfile.BadZipFile,tarfile.TarError,subprocess.SubprocessError):
        print('Platform package audit failed; publishing is blocked.')
        raise SystemExit(2)
