#!/usr/bin/env python3
"""Independent destination-IP source/output union audit; no DNS/TUN simulation."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import sys
import build


def intervals(networks):
    result=[]
    for lo,hi in sorted((int(n.network_address),int(n.broadcast_address)) for n in networks):
        if result and lo <= result[-1][1]+1:
            result[-1]=(result[-1][0],max(hi,result[-1][1]))
        else: result.append((lo,hi))
    return result


def audit(root=build.ROOT, conf=None, previous=None):
    root=Path(root)
    conf=conf if conf is not None else (root/'dist/Shadowrocket.conf').read_text()
    specs=json.loads((root/'sources/sources.json').read_text())
    manifest=json.loads((root/'dist/manifest.json').read_text())
    # Deliberately do not call build.parse_source/generate/collapse_addresses.
    raw={4:[],6:[]}
    for spec in specs['sources']:
        data=(root/'dist/inputs'/ (spec['id']+'.txt')).read_bytes()
        if hashlib.sha256(data).hexdigest()!=manifest['sources'][spec['id']]['sha256']:
            raise build.BuildError('Audit source hash mismatch')
        version=int(spec['format'][-1])
        for line in data.decode('utf-8-sig').splitlines():
            if not line.strip() or line.startswith('#'): continue
            n=ipaddress.ip_network(line,strict=True)
            if n.version!=version or not n.is_global:
                raise build.BuildError('Invalid audit source network')
            raw[version].append(n)
    block=conf.split('# BEGIN CHINA IP\n')[1].split('# END CHINA IP')[0]
    actual={4:[],6:[]}
    for line in block.splitlines():
        if not line or line.startswith('#'): continue
        fields=line.split(',')
        if len(fields)!=3 or fields[0] not in ('IP-CIDR','IP-CIDR6') or fields[2]!='DIRECT':
            raise build.BuildError('IP routing policy or resolution flag changed')
        n=ipaddress.ip_network(fields[1],strict=True)
        if n.version!=(4 if fields[0]=='IP-CIDR' else 6):
            raise build.BuildError('Wrong IP family')
        actual[n.version].append(n)
    equality={str(v):intervals(raw[v])==intervals(actual[v]) for v in (4,6)}
    if not all(equality.values()): raise build.BuildError('Source/output IP address sets differ')
    validation=build.validate(conf)
    # Exact interval equality covers all IP addresses, including gaps between ranges.
    # Domain tests deliberately hold the destination constant across unrelated names.
    cases=[]
    for host in ('us.ip111.cn','cn.bing.com','claude.ai','gateway.icloud.com.cn','steamcommunity.com','www.baidu.com'):
        for ip,want in [('162.222.90.70','PROXY'),('223.5.5.5','DIRECT'),('2606:4700:4700::1111','PROXY'),('2400:3200::1','DIRECT')]:
            got=build.match_rules(build.rule_lines(conf),host,ip,443)
            if got!=want: raise build.BuildError('Domain changed destination-IP decision')
            cases.append({'host':host,'address':ip,'policy':got})
    return {'config_sha256':hashlib.sha256(conf.encode()).hexdigest(),
        'routing_mode':'destination-ip','ip_union_equal':equality,
        'source_networks':{str(v):len(raw[v]) for v in (4,6)},
        'output_networks':{str(v):len(actual[v]) for v in (4,6)},
        'domain_independence_cases':len(cases),'validation':validation,
        'previous_config_sha256':hashlib.sha256(previous.encode()).hexdigest() if previous else None,
        'previous_business_domain_rules':sum(1 for x in build.rule_lines(previous) if x.startswith(('DOMAIN,','DOMAIN-SUFFIX,','DOMAIN-KEYWORD,')) and x not in build.LOCAL_RULES) if previous else None,
        'scope':'Exact address-set equality, not physical geolocation accuracy or native DNS/TUN proof'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    parser.add_argument('--compare',type=Path)
    args=parser.parse_args()
    try:
        result=audit(previous=args.compare.read_text() if args.compare else None)
        report=json.dumps(result,indent=2,sort_keys=True)+'\n'
        if args.output:
            args.output.parent.mkdir(parents=True,exist_ok=True)
            args.output.write_text(report)
        print('AUDIT_OK:',report)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f:
                f.write('### Destination-IP policy audit\n\n```json\n'+report+'```\n')
    except (build.BuildError,ValueError,KeyError,OSError,IndexError) as exc:
        print('AUDIT FAILED:',exc,file=sys.stderr)
        return 1
    return 0

if __name__=='__main__':
    sys.exit(main())
