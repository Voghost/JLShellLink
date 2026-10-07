#!/usr/bin/env python3
"""Provision a dedicated publisher key without printing private bytes or rotating existing keys."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess


def command(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True)
    if result.returncode:
        raise RuntimeError('Publisher provisioning operation failed')
    return result.stdout


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output-directory',type=Path,required=True)
    parser.add_argument('--openssl',default='openssl')
    parser.add_argument('--github-repo')
    parser.add_argument('--ssh-backup-target')
    parser.add_argument('--ssh-backup-directory')
    args=parser.parse_args();root=args.output_directory.resolve()
    repository=Path(command(['git','rev-parse','--show-toplevel']).decode().strip()).resolve()
    if root==repository or repository in root.parents:
        raise ValueError('Private backup must be outside the repository')
    if bool(args.ssh_backup_target)!=bool(args.ssh_backup_directory):
        raise ValueError('Provide both SSH backup options')
    if args.github_repo:
        existing=json.loads(command(['gh','secret','list','--repo',args.github_repo,'--json','name']))
        if any(item['name']=='JLSHELL_AGENT_PUBLISHER_PRIVATE_KEY' for item in existing):
            raise ValueError('Publisher key already provisioned; explicit rotation is required')
    root.mkdir(mode=0o700,parents=True,exist_ok=False)
    os.chmod(root,0o700);private=root/'publisher.pkcs8.der'
    fd=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd)
    command([args.openssl,'genpkey','-algorithm','ED25519','-outform','DER','-out',str(private)])
    public=command([args.openssl,'pkey','-inform','DER','-in',str(private),'-pubout','-outform','DER'])
    if len(public)!=44 or public[:12]!=bytes.fromhex('302a300506032b6570032100'):
        raise ValueError('Expected Ed25519 SPKI')
    encoded=base64.b64encode(public).decode();key_id=hashlib.sha256(public).hexdigest()
    (root/'publisher-public-key.txt').write_text(encoded+'\n')
    (root/'publisher-key-id.txt').write_text(key_id+'\n')
    if args.ssh_backup_target:
        # The target receives key bytes on stdin. Never insert key material into command text.
        import shlex
        remote='python3 -c '+shlex.quote('''import os,pathlib,sys
p=pathlib.Path(sys.argv[1]);p.mkdir(mode=0o700,parents=True,exist_ok=False);p.chmod(0o700)
fd=os.open(p/'publisher.pkcs8.der',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,'wb') as f:f.write(sys.stdin.buffer.read())
''')+' '+shlex.quote(args.ssh_backup_directory)
        command(['ssh','-o','BatchMode=yes',args.ssh_backup_target,remote],private.read_bytes())
    if args.github_repo:
        command(['gh','secret','set','JLSHELL_AGENT_PUBLISHER_PRIVATE_KEY','--repo',args.github_repo],base64.b64encode(private.read_bytes()))
        command(['gh','variable','set','JLSHELL_AGENT_PUBLISHER_PUBLIC_KEYS','--repo',args.github_repo,'--body',encoded])
    print('Dedicated publisher key provisioned; key ID: '+key_id)


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):
        raise SystemExit('Publisher provisioning failed; no private values are logged. Check backup and secret state before retry.') from None
