#!/usr/bin/env python3
"""Independent domain-boundary and exact IP-union audit of the published snapshot."""
import argparse
import ipaddress
import json
from pathlib import Path
import sys

import build
import audit_sources


def domain_sets(rules):
    return ({value for kind, value in rules if kind == 'DOMAIN'},
            {value for kind, value in rules if kind == 'DOMAIN-SUFFIX'})


def ancestors(host):
    labels = host.split('.')
    return {'.'.join(labels[index:]) for index in range(len(labels))}


def audit(root=build.ROOT, conf=None):
    root = Path(root)
    conf = conf if conf is not None else (root / 'dist/Shadowrocket.conf').read_text()
    specs = json.loads((root / 'sources/sources.json').read_text())
    raw = audit_sources.read_sources(root, specs)
    overrides = json.loads((root / 'config/overrides.json').read_text())
    reviewed = {section: {(g['type'], audit_sources.hostname(h)) for g in overrides[section]
                          for h in g['domains']} for section in ['lan_domains', 'direct_exceptions']}
    protected = {('DOMAIN-SUFFIX', h) for h in overrides['proxy_suffix']}
    proxy = raw['proxy'] | protected
    direct = {(kind, name) for kind, name in raw['direct'] if not (kind == 'DOMAIN-SUFFIX'
              and ('.' not in name or name in specs['direct_excluded_suffixes']))}
    local_exact = {'localhost'} | {name for _, name in reviewed['lan_domains']}
    local_suffix = {'local', 'lan', 'home.arpa', 'in-addr.arpa', 'ip6.arpa'}
    p_exact, p_suffix = domain_sets(proxy)
    d_exact, d_suffix = domain_sets(direct)
    r_exact, r_suffix = domain_sets(reviewed['direct_exceptions'])

    def expected(host):
        lineage = ancestors(host)
        if host in local_exact or lineage & local_suffix:
            return 'DIRECT'
        if host in r_exact or lineage & r_suffix:
            return 'DIRECT'
        if host in p_exact or lineage & p_suffix:
            return 'PROXY'
        if host in d_exact or lineage & d_suffix:
            return 'DIRECT'
        return 'PROXY'

    # Actual decisions use output order, independently of generate/minimize/conflict code.
    exact, suffix = {}, {}
    rule_block = conf.split('[Rule]\n', 1)[1].split('[Host]', 1)[0]
    for index, line in enumerate(rule_block.splitlines()):
        parts = line.split(',')
        if parts[0] == 'DOMAIN':
            exact.setdefault(parts[1], (index, parts[2]))
        elif parts[0] == 'DOMAIN-SUFFIX':
            suffix.setdefault(parts[1], (index, parts[2]))

    def actual(host):
        matches = [exact[host]] if host in exact else []
        matches.extend(suffix[x] for x in ancestors(host) if x in suffix)
        return min(matches)[1] if matches else 'PROXY'

    samples = {'never-listed.example.invalid', 'localhost', 'nas.local', 'nas.home.arpa'}
    for _, name in proxy | raw['direct'] | set().union(*reviewed.values()):
        samples.update([name, 'sr-audit-subdomain.' + name,
                        'sr-audit-not' + name, name + '.outside.invalid'])
    failures = []
    for host in sorted(samples):
        want, got = expected(host), actual(host)
        if want != got:
            failures.append({'host': host, 'expected': want, 'actual': got})
    block = conf.split('# BEGIN CHINA IP\n')[1].split('# END CHINA IP')[0]
    ip_equality = {}
    for ident, kind in [('china4', 'IP-CIDR'), ('china6', 'IP-CIDR6')]:
        before = list(ipaddress.collapse_addresses(raw[ident]))
        after = list(ipaddress.collapse_addresses(ipaddress.ip_network(x.split(',')[1])
                     for x in block.splitlines() if x.startswith(kind + ',')))
        ip_equality[ident] = before == after
    if failures or not all(ip_equality.values()):
        raise build.BuildError('Full rule audit failed: ' + json.dumps(
            {'domain_failures': failures[:5], 'ip_union_equal': ip_equality}, sort_keys=True))
    return {'config_sha256': build.sha(conf.encode()), 'domain_boundary_cases': len(samples),
            'domain_failures': 0, 'ip_union_equal': ip_equality,
            'validation': build.validate(conf, overrides),
            'scope': 'Independent source decoders and static output model; not upstream truth or native DNS/TUN simulation'}


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
