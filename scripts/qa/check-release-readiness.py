#!/usr/bin/env python3
"""Require measured QA/recovery evidence before release or source retirement."""
import argparse
import datetime
import json
from pathlib import Path
import re
import subprocess

SHA = re.compile(r'^[0-9a-f]{64}$')
REVISION = re.compile(r'^[0-9a-f]{40}$')
PLATFORMS = {'linux-x64','macos-arm64','windows-x64'}


def require(condition, reason):
    if not condition:raise ValueError(reason)


def measured(result):
    return (isinstance(result,dict) and result.get('passed') is True and
            SHA.fullmatch(str(result.get('evidenceSha256',''))) is not None)


def validate(report, phase):
    require(report.get('schemaVersion')==1,'Invalid readiness schema')
    source=report.get('linkSourceRevision','');require(REVISION.fullmatch(source),'Bind the tested Link source revision')
    require(set(report.get('platforms',{}))==PLATFORMS,'All three real platforms are required')
    for platform,result in report['platforms'].items():
        require(measured(result),'Missing real platform acceptance')
        require(all(result.get(k) is True for k in ('registration','permissions','startup','loginBoundary','stop','upgradeRecovery','uninstall')),'Incomplete real platform lifecycle')
    business=report.get('business',{});require(measured(business),'Missing real business acceptance')
    require(business.get('distinctPublicExits') is True,'Two public exit networks are required')
    require(business.get('directSshSftpHttpPostgres') is True and business.get('relaySshSftpHttpPostgres') is True,'Both actual data paths must pass')
    stress=report.get('stress',{});require(measured(stress),'Missing measured stress acceptance')
    require(type(stress.get('attemptedConcurrentFlows')) is int and stress['attemptedConcurrentFlows']>=100,'100 concurrent attempts must be measured')
    require(type(stress.get('acceptedFlows')) is int and type(stress.get('boundedRejectedFlows')) is int
            and stress['acceptedFlows']+stress['boundedRejectedFlows']==stress['attemptedConcurrentFlows'],'Account for every load attempt; bounded rejection is not success')
    require(all(stress.get(k) is True for k in ('slowConsumer','packetLoss','longConnection','repeatedRestarts','noLeaks')),'Incomplete stress cases')
    require(measured(report.get('noRustSidecar',{})),'Missing actual A/B/C no-sidecar startup evidence')
    require(measured(report.get('signedPackages',{})),'Missing signed platform package verification')
    if phase in ('release','retire'):
        require(measured(report.get('recovery',{})),'Missing prior Java artifact/image recovery drill')
        require(report.get('recovery',{}).get('registrationBoundaryVerified') is True,'Recovery must preserve consumed enrollment semantics')
        eligible=subprocess.run(['git','merge-base','--is-ancestor',source,'origin/main'],capture_output=True)
        require(eligible.returncode==0,'Formal release requires tested source already merged into main')
        require(measured(report.get('compatibility',{})),'Missing actual four-product compatibility evidence')
    if phase=='retire':
        require(measured(report.get('production',{})),'Missing formal production health acceptance')
        for key in ('remainingLegacyAgents','remainingActiveLegacyRelays','remainingLiveLegacyGrants','remainingUnexpiredLegacyTickets'):
            require(type(report['production'].get(key)) is int and report['production'][key]==0,'Legacy objects still need handling')
        end=datetime.datetime.fromisoformat(report['production'].get('recoveryWindowEndsAt','').replace('Z','+00:00'))
        require(end.tzinfo is not None and datetime.datetime.now(datetime.timezone.utc)>=end,'Recovery window has not ended')
    return source


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--report',type=Path,required=True);parser.add_argument('--phase',choices=['qa','release','retire'],required=True);args=parser.parse_args()
    try:
        validate(json.loads(args.report.read_text()),args.phase)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Release readiness is incomplete; requested phase is blocked. No private input values are logged.') from None
    print('Release readiness: PASS ('+args.phase+')')
