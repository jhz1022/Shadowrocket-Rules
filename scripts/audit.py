#!/usr/bin/env python3
"""Independent domain-boundary and exact IP-union audit of the published snapshot."""
import argparse
import ipaddress
import json
from pathlib import Path
import sys
import os
from collections import Counter

import build
import audit_sources
import update_guard


def domain_sets(rules):
    return ({value for kind, value in rules if kind == 'DOMAIN'},
            {value for kind, value in rules if kind == 'DOMAIN-SUFFIX'})


def ancestors(host):
    labels = host.split('.')
    return {'.'.join(labels[index:]) for index in range(len(labels))}


def audit(root=build.ROOT, conf=None, previous=None):
    root = Path(root)
    conf = conf if conf is not None else (root / 'dist/Shadowrocket.conf').read_text()
    specs = json.loads((root / 'sources/sources.json').read_text())
    raw = audit_sources.read_sources(root, specs)
    overrides = json.loads((root / 'config/overrides.json').read_text())
    reviewed = {section: {(g['type'], audit_sources.hostname(h)) for g in overrides[section]
                          for h in g['domains']} for section in ['lan_domains', 'direct_exceptions']}
    protected = {('DOMAIN-SUFFIX', h) for h in overrides['proxy_suffix']}
    proxy = raw['proxy']
    allowed = set(specs['direct_allowed_registry_suffixes'])
    if allowed:
        raise build.BuildError('Full rule audit failed: registry-level DIRECT allowance')
    direct = {(kind, name) for kind, name in raw['direct'] | raw['enhanced'] if name in allowed or not (kind == 'DOMAIN-SUFFIX'
              and (audit_sources.registry_suffix(name, raw['registry'])
                   or name in specs['direct_excluded_suffixes']))}
    regional = {(kind, name) for kind, name in raw['regional'] | raw['apple_cn']
                if name in allowed or not (kind == 'DOMAIN-SUFFIX' and
                    audit_sources.registry_suffix(name, raw['registry']))}
    omitted = set(overrides.get('omit_ordinary_direct_suffixes', []))
    direct.difference_update(('DOMAIN-SUFFIX', host) for host in omitted)
    local_exact = {'localhost'} | {name for _, name in reviewed['lan_domains']}
    local_suffix = {'local', 'lan', 'home.arpa', 'in-addr.arpa', 'ip6.arpa'}
    p_exact, p_suffix = domain_sets(proxy)
    d_exact, d_suffix = domain_sets(direct)
    r_exact, r_suffix = domain_sets(reviewed['direct_exceptions'])
    s_exact, s_suffix = domain_sets(regional)
    _, protected_suffix = domain_sets(protected)

    def expected(host):
        lineage = ancestors(host)
        if host in local_exact or lineage & local_suffix:
            return 'DIRECT'
        if lineage & protected_suffix:
            return 'PROXY'
        if host in r_exact or lineage & r_suffix:
            return 'DIRECT'
        if host in s_exact or lineage & s_suffix:
            return 'DIRECT'
        if host in d_exact or lineage & d_suffix:
            return 'DIRECT'
        if host in p_exact or lineage & p_suffix:
            return 'PROXY'
        return 'PROXY'

    # Actual decisions use output order, independently of generate/minimize/conflict code.
    exact, suffix = {}, {}
    rule_block = conf.split('[Rule]\n', 1)[1].split('[Host]', 1)[0]
    for index, line in enumerate(rule_block.splitlines()):
        parts = line.split(',')
        if parts[0] == 'DOMAIN':
            exact.setdefault(parts[1], (index, parts[2]))
        elif parts[0] == 'DOMAIN-SUFFIX':
            if (parts[2] == 'DIRECT' and parts[1] not in local_suffix | {'gov.cn', 'edu.cn'}
                    and audit_sources.registry_suffix(parts[1], raw['registry'])):
                raise build.BuildError('Full rule audit failed: registry-level DIRECT suffix')
            suffix.setdefault(parts[1], (index, parts[2]))

    def actual(host):
        matches = [exact[host]] if host in exact else []
        matches.extend(suffix[x] for x in ancestors(host) if x in suffix)
        return min(matches)[1] if matches else 'PROXY'

    samples = {'never-listed.example.invalid', 'localhost', 'nas.local', 'nas.home.arpa'}
    # Include output-only boundaries too, so an injected rule cannot escape the
    # oracle simply because its hostname is absent from all input lists.
    boundaries = (proxy | protected | raw['direct'] | raw['enhanced'] | regional
                  | set().union(*reviewed.values()) | {('DOMAIN', h) for h in exact}
                  | {('DOMAIN-SUFFIX', h) for h in suffix})
    for _, name in boundaries:
        samples.update([name, 'sr-audit-subdomain.' + name,
                        'sr-audit-not' + name, name + '.outside.invalid'])
    old_exact, old_suffix = {}, {}
    if previous is not None:
        old_block = previous.split('[Rule]\n', 1)[1].split('[Host]', 1)[0]
        for index, line in enumerate(old_block.splitlines()):
            cells = line.split(',')
            if cells[0] in ('DOMAIN', 'DOMAIN-SUFFIX'):
                target = old_exact if cells[0] == 'DOMAIN' else old_suffix
                target.setdefault(cells[1], (index, cells[2]))
                samples.update([cells[1], 'sr-audit-subdomain.' + cells[1]])
    transitions, changed_examples = Counter(), []
    failures = []
    for host in sorted(samples):
        want, got = expected(host), actual(host)
        if want != got:
            failures.append({'host': host, 'expected': want, 'actual': got})
        if previous is not None:
            old_matches = [old_exact[host]] if host in old_exact else []
            old_matches += [old_suffix[h] for h in ancestors(host) if h in old_suffix]
            before = min(old_matches)[1] if old_matches else 'PROXY'
            if before != got:
                transitions[before + ' -> ' + got] += 1
                if len(changed_examples) < 100:
                    changed_examples.append({'host': host, 'before': before, 'after': got})
    block = conf.split('# BEGIN CHINA IP\n')[1].split('# END CHINA IP')[0]
    ip_equality, ip_changes = {}, {}
    for ident, kind in [('china4', 'IP-CIDR'), ('china6', 'IP-CIDR6')]:
        before = list(ipaddress.collapse_addresses(raw[ident]))
        after = list(ipaddress.collapse_addresses(ipaddress.ip_network(x.split(',')[1])
                     for x in block.splitlines() if x.startswith(kind + ',')))
        ip_equality[ident] = before == after
        if previous is not None:
            old_ip_block = previous.split('# BEGIN CHINA IP\n')[1].split('# END CHINA IP')[0]
            old_networks = [ipaddress.ip_network(x.split(',')[1])
                            for x in old_ip_block.splitlines() if x.startswith(kind + ',')]
            ip_changes[ident] = update_guard.ip_delta(old_networks, after)
    if failures or not all(ip_equality.values()):
        raise build.BuildError('Full rule audit failed: ' + json.dumps(
            {'domain_failures': failures[:5], 'ip_union_equal': ip_equality}, sort_keys=True))
    coverage, exceptions = {}, []
    for ident in ('enhanced', 'regional', 'apple_cn'):
        counts = Counter()
        for kind, host in sorted(raw[ident]):
            route = actual(host)
            reason = ('protected-service' if ancestors(host) & protected_suffix else
                      'reviewed-ordinary-suffix-omission' if ident == 'enhanced' and kind == 'DOMAIN-SUFFIX'
                      and host in omitted and route != 'DIRECT' else
                      'registry-filter' if kind == 'DOMAIN-SUFFIX' and host not in allowed
                      and audit_sources.registry_suffix(host, raw['registry']) else
                      'ordinary-proxy-priority' if route == 'PROXY' else 'direct')
            counts[reason] += 1
            if route != 'DIRECT':
                exceptions.append({'source': ident, 'type': kind, 'host': host,
                                   'decision': route, 'reason': reason})
        coverage[ident] = dict(sorted(counts.items()))
    return {'config_sha256': build.sha(conf.encode()), 'domain_boundary_cases': len(samples),
            'previous_config_sha256': build.sha(previous.encode()) if previous is not None else None,
            'boundary_policy_changes': dict(transitions),
            'ip_policy_changes': ip_changes,
            'change_examples_first_100': changed_examples,
            'source_policy_coverage': coverage, 'direct_source_exceptions': exceptions,
            'domain_failures': 0, 'ip_union_equal': ip_equality,
            'validation': build.validate(conf, overrides, raw['registry']),
            'scope': 'Independent source decoders and static output model; not upstream truth or native DNS/TUN simulation'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional local audit JSON, not a daily commit')
    parser.add_argument('--compare', type=Path, help='Previous config for boundary-policy change accounting')
    parser.add_argument('--enforce-changes', action='store_true', help='Block anomalous automatic publication')
    args = parser.parse_args()
    try:
        result = audit(previous=args.compare.read_text() if args.compare else None)
        if args.enforce_changes:
            result['update_guard'] = update_guard.assess(result,
                json.loads((build.ROOT / 'config/update-policy.json').read_text()))
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        label = 'AUDIT_BLOCKED:' if result.get('update_guard', {}).get('passed') is False else 'AUDIT_OK:'
        print(label, json.dumps({k: v for k, v in result.items()
                                      if k not in {'direct_source_exceptions', 'change_examples_first_100'}}, sort_keys=True))
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            summary = {k: result[k] for k in ('config_sha256', 'domain_boundary_cases',
                'domain_failures', 'source_policy_coverage', 'boundary_policy_changes')}
            with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
                stream.write('### Routing policy audit\n\n```json\n' +
                             json.dumps(summary, indent=2) + '\n```\n')
                if 'update_guard' in result:
                    stream.write('\n### Automatic publication guard\n\n```json\n' +
                                 json.dumps(result['update_guard'], indent=2) + '\n```\n')
        if args.enforce_changes and not result['update_guard']['passed']:
            raise build.BuildError('Routing change budget exceeded; keep the published configuration and review the audit artifact')
    except (build.BuildError, ValueError, KeyError, OSError) as exc:
        print('AUDIT FAILED:', exc, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
