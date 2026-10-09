#!/usr/bin/env python3
"""Verify real SSH/SFTP/HTTP/PostgreSQL through product-created Link leases."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def private_json(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise ValueError('Expected regular private input')
    if os.name!='nt' and stat.S_IMODE(path.stat().st_mode)&0o077:raise ValueError('Input must be private (0600)')
    return json.loads(path.read_text())


def digest(path):
    with Path(path).open('rb') as stream:
        result=hashlib.sha256()
        for block in iter(lambda:stream.read(1024*1024),b''):result.update(block)
    return result.hexdigest()


def execute(command, *, data=None, environment=None):
    result=subprocess.run(command,input=data,capture_output=True,timeout=90,env=environment)
    if result.returncode:raise ValueError('Business protocol command failed')
    return result.stdout


def ssh_options(configuration, port):
    alias=configuration['hostKeyAlias']
    if not alias or any(c.isspace() for c in alias):raise ValueError('Invalid SSH target alias')
    return ['-F','none','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=15',
            '-o','UserKnownHostsFile='+configuration['knownHostsFile'],'-o','HostKeyAlias='+alias,
            '-o','LogLevel=ERROR']


def probe(case, lease, private):
    port=lease['localPort']; kind=case['protocol']
    if kind=='ssh':
        result=execute(['ssh',*ssh_options(case,port),'-p',str(port),case['username']+'@127.0.0.1','echo JLSHELL_QA_OK'])
        if result.strip()!=b'JLSHELL_QA_OK':raise ValueError('SSH authentication or remote command failed')
    elif kind=='sftp':
        original=private/'upload.bin';received=private/'download.bin';original.write_bytes(secrets.token_bytes(256*1024))
        remote=case['remoteTestDirectory'].rstrip('/')+'/.jlshell-link-qa-'+secrets.token_hex(12)
        if any(c in remote for c in ('\n','\r','"','\\')):raise ValueError('Unsupported SFTP test path')
        batch=f'-put "{original}" "{remote}"\n-get "{remote}" "{received}"\nrm "{remote}"\n'.encode()
        execute(['sftp',*ssh_options(case,port),'-P',str(port),'-b','-',case['username']+'@127.0.0.1'],data=batch)
        if not received.is_file() or digest(original)!=digest(received):raise ValueError('SFTP data integrity failed')
    elif kind=='http':
        path=case.get('requestPath','/')
        if not path.startswith('/') or '\n' in path or '\r' in path:raise ValueError('Invalid HTTP path')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        request=urllib.request.Request(f'http://127.0.0.1:{port}'+path,headers={'Host':case['hostHeader']})
        with opener.open(request,timeout=30) as response:
            data=response.read(1024*1024+1)
            if response.status!=200 or not data or len(data)>1024*1024:raise ValueError('HTTP target check failed')
    elif kind=='postgres':
        password_path=Path(case['passwordFile'])
        if password_path.is_symlink() or not password_path.is_file():raise ValueError('Expected regular database password file')
        if os.name!='nt' and stat.S_IMODE(password_path.stat().st_mode)&0o077:raise ValueError('Database password file must be private')
        password=password_path.read_text().strip()
        if '\n' in password or '\r' in password:raise ValueError('Invalid database password file')
        escaped=password.replace('\\','\\\\').replace(':','\\:')
        pgpass=private/'pgpass';fd=os.open(pgpass,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:stream.write(f'127.0.0.1:{port}:*:*:{escaped}\n')
        environment={**os.environ,'PGPASSFILE':str(pgpass),'PGCONNECT_TIMEOUT':'15','PGSSLMODE':case.get('sslMode','prefer')}
        for variable in ('PGPASSWORD','PGSERVICE','PGSERVICEFILE','PGHOSTADDR'):environment.pop(variable,None)
        result=execute(['psql','-h','127.0.0.1','-p',str(port),'-U',case['username'],'-d',case['database'],
                        '-X','-A','-t','-v','ON_ERROR_STOP=1','-c','SELECT 1'],environment=environment)
        if result.strip()!=b'1':raise ValueError('PostgreSQL query failed')
    else:raise ValueError('Unsupported business protocol')


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();output=Path(args.output);output.unlink(missing_ok=True)
    configuration=private_json(args.config);cases=configuration['cases']
    revision=configuration['linkSourceRevision']
    if len(revision)!=40 or any(c not in '0123456789abcdef' for c in revision):raise ValueError('Bind a real candidate source SHA')
    network=private_json(configuration['networkEvidenceFile'])
    exits=[ipaddress.ip_address(network[k]) for k in ('aStunMappingIp','cStunMappingIp')]
    if not all(ip.is_global for ip in exits) or exits[0]==exits[1]:raise ValueError('Two distinct public exit networks are required')
    required={(path,protocol) for path in ('DIRECT','RELAY') for protocol in ('ssh','sftp','http','postgres')}
    if {(case['path'],case['protocol']) for case in cases}!=required or len(cases)!=8:raise ValueError('Supply all eight business cases')
    results=[]
    for case in cases:
        lease=private_json(case['leaseEvidenceFile'])
        if lease['path']!=case['path'] or lease['localHost']!='127.0.0.1' or type(lease['localPort']) is not int or not 1<=lease['localPort']<=65535:
            raise ValueError('Product lease evidence does not match required path')
        start=time.monotonic();passed=False
        with tempfile.TemporaryDirectory(prefix='link-business-qa-') as name:
            os.chmod(name,0o700)
            try:probe(case,lease,Path(name));passed=True
            except (OSError,ValueError,subprocess.SubprocessError,urllib.error.URLError):pass
        results.append({'protocol':case['protocol'],'path':case['path'],'passed':passed,
                        'elapsedMillis':round((time.monotonic()-start)*1000),
                        'leaseEvidenceSha256':digest(case['leaseEvidenceFile'])})
    report={'schemaVersion':1,'linkSourceRevision':revision,'distinctPublicExits':True,
            'networkEvidenceSha256':digest(configuration['networkEvidenceFile']),
            'cases':results,'passed':all(case['passed'] for case in results),
            'coverage':'Real business checks only; loss/load/lifecycle require separate measured acceptance.'}
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
    print('Business tunnel acceptance: '+('PASS' if report['passed'] else 'FAIL'))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Acceptance inputs are incomplete or invalid; no pass is recorded.') from None
