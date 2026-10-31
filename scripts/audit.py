#!/usr/bin/env python3
"""Independent domain-boundary and exact IP-union audit of the published snapshot."""
import argparse
import ipaddress
import json
from pathlib import Path
import sys

import build


def domain_sets(rules):
    return ({r.value for r in rules if r.kind == 'DOMAIN'},
            {r.value for r in rules if r.kind == 'DOMAIN-SUFFIX'})


def audit(root=build.ROOT, conf=None):
    root = Path(root)
    conf = conf if conf is not None else (root / 'dist/Shadowrocket.conf').read_text()
    specs = json.loads((root / 'sources/sources.json').read_text())
    inputs, _ = build.offline_inputs(root / 'dist', specs)
    raw = {s['id']: build.parse_source(inputs[s['id']], s)[0] for s in specs['sources']}
    overrides = json.loads((root / 'config/overrides.json').read_text())
    reviewed, protected = build.reviewed_rules(overrides, inputs['direct'])
    proxy = raw['proxy'] | protected
    direct = raw['direct']
    local_exact = {'localhost'} | {r.value for r in reviewed['lan_domains']}
    local_suffix = {'local', 'lan', 'home.arpa', 'in-addr.arpa', 'ip6.arpa'}
    p_exact, p_suffix = domain_sets(proxy)
    d_exact, d_suffix = domain_sets(direct)
    r_exact, r_suffix = domain_sets(reviewed['direct_exceptions'])

    def expected(host):
        ancestors = list(build.parents(host))
        if host in local_exact or any(x in local_suffix for x in ancestors):
            return 'DIRECT'
        if host in r_exact or any(x in r_suffix for x in ancestors):
            return 'DIRECT'
        if host in p_exact or any(x in p_suffix for x in ancestors):
            return 'PROXY'
        if host in d_exact or any(x in d_suffix for x in ancestors):
            return 'DIRECT'
        return 'PROXY'

    # Actual decisions use output order, independently of generate/minimize/conflict code.
    exact, suffix = {}, {}
    for index, line in enumerate(build.rule_lines(conf)):
        parts = line.split(',')
        if parts[0] == 'DOMAIN':
            exact.setdefault(parts[1], (index, parts[2]))
        elif parts[0] == 'DOMAIN-SUFFIX':
            suffix.setdefault(parts[1], (index, parts[2]))

    def actual(host):
        matches = [exact[host]] if host in exact else []
        matches.extend(suffix[x] for x in build.parents(host) if x in suffix)
        return min(matches)[1] if matches else 'PROXY'

    samples = {'never-listed.example.invalid', 'localhost', 'nas.local', 'nas.home.arpa'}
    for rule in proxy | direct | set().union(*reviewed.values()):
        samples.update([rule.value, 'sr-audit-subdomain.' + rule.value,
                        'sr-audit-not' + rule.value, rule.value + '.outside.invalid'])
    failures = []
    for host in sorted(samples):
        want, got = expected(host), actual(host)
        if want != got:
            failures.append({'host': host, 'expected': want, 'actual': got})
    block = conf.split('# BEGIN CHINA IP\n')[1].split('# END CHINA IP')[0]
    ip_equality = {}
    for ident, kind in [('china4', 'IP-CIDR'), ('china6', 'IP-CIDR6')]:
        before = list(ipaddress.collapse_addresses(ipaddress.ip_network(r.value) for r in raw[ident]))
        after = list(ipaddress.collapse_addresses(ipaddress.ip_network(x.split(',')[1])
                     for x in block.splitlines() if x.startswith(kind + ',')))
        ip_equality[ident] = before == after
    if failures or not all(ip_equality.values()):
        raise build.BuildError('Full rule audit failed: ' + json.dumps(
            {'domain_failures': failures[:5], 'ip_union_equal': ip_equality}, sort_keys=True))
    return {'config_sha256': build.sha(conf.encode()), 'domain_boundary_cases': len(samples),
            'domain_failures': 0, 'ip_union_equal': ip_equality,
            'validation': build.validate(conf, overrides),
            'scope': 'Static domain model and exact CIDR union; not native DNS/TUN simulation'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional local audit JSON, not a daily commit')
    args = parser.parse_args()
    try:
        result = audit()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print('AUDIT_OK:', json.dumps(result, sort_keys=True))
    except (build.BuildError, ValueError, KeyError, OSError) as exc:
        print('AUDIT FAILED:', exc, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
