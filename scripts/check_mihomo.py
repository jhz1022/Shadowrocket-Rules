#!/usr/bin/env python3
"""Independently check serialized Mihomo artifacts against the published contract.

Requires requirements-test.txt. This checks every ordered rule and the declared
DNS/failure policy; it is not a native packet-routing or real-node certificate.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import yaml
from check_routing_contract import Policy

ROOT = Path(__file__).resolve().parents[1]


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if key in mapping:
            raise ValueError(f'Duplicate YAML key: {key}')
        mapping[key] = loader.construct_object(value_node)
    return mapping


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def load_yaml(path):
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('Oversized generated YAML')
    return yaml.load(path.read_text(), Loader=UniqueLoader)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(root=ROOT, output=None):
    dist = output or root/'dist'
    bundle = dist/'mihomo'
    text = (dist/'Shadowrocket.conf').read_text()
    original = Policy(text)
    manifest = json.loads((bundle/'manifest.json').read_text())
    require(manifest['source_config_sha256'] == sha(text.encode()), 'Mihomo source identity differs')
    root_manifest = json.loads((dist/'manifest.json').read_text())
    require(root_manifest['mihomo_manifest_sha256'] == sha((bundle/'manifest.json').read_bytes()),
            'Root manifest does not authenticate the Mihomo manifest')
    expected_files = {'Mihomo.yaml'}
    require(set(manifest['files']) == expected_files, 'Unexpected/missing bundle files')
    for name, entry in manifest['files'].items():
        data = (bundle/name).read_bytes()
        require(entry == {'sha256': sha(data), 'bytes': len(data)}, f'Artifact integrity failure: {name}')
    config = load_yaml(bundle/'Mihomo.yaml')
    require(config['mode'] == 'rule' and config['ipv6'] is False, 'Routing mode/IPv4 baseline changed')
    require(config['allow-lan'] is False and config['bind-address'] == '127.0.0.1', 'Unexpected standalone exposure')
    require(config['proxies'] == [] and config['proxy-groups'] == [
        {'name': 'PROXY', 'type': 'select', 'proxies': ['REJECT']}], 'Unconfigured profile must explicitly reject')
    order = [('lan', 'DIRECT'), (None, 'REJECT'), ('local-names', 'DIRECT'),
             ('protected', 'PROXY'), ('reviewed-direct', 'DIRECT'), ('regional', 'DIRECT'),
             ('direct', 'DIRECT'), ('proxy', 'PROXY'), ('china-ip', 'DIRECT')]
    expected_top, expanded, providers = [], [], {}
    for name, target in order:
        if name is None:
            expected_top.append('DST-PORT,53,REJECT')
            expanded.append('DST-PORT,53,REJECT')
            continue
        provider = config['rule-providers'][name]
        require(set(provider) == {'type', 'behavior', 'payload'} and provider['type'] == 'inline'
                and provider['behavior'] == 'classical', 'Unexpected provider type/format')
        rows = provider
        require(isinstance(rows['payload'], list) and rows['payload'],
                'Missing provider payload')
        providers[name] = rows['payload']
        for row in rows['payload']:
            fields = row.split(',')
            require(len(fields) == 2 and fields[0] in ('DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR', 'IP-CIDR6'),
                    'Provider contains a policy, extra flag or unreviewed rule')
            expanded.append(row + ',' + target + (',no-resolve' if name == 'lan' and fields[0].startswith('IP-CIDR') else ''))
        expected_top.append(f'RULE-SET,{name},{target}' + (',no-resolve' if name == 'lan' else ''))
        if target == 'PROXY':
            expected_top.append(f'AND,((NETWORK,udp),(RULE-SET,{name})),REJECT')
    expected_top.extend(['MATCH,PROXY', 'MATCH,REJECT'])
    require(config['rules'] == expected_top, 'Routing layer order or UDP/final rejection guard changed')
    expanded.append('FINAL,PROXY')
    require(expanded == [','.join(row) for row in original.rows], 'Full ordered rule/flag equivalence failed')
    require(manifest['source_rules'] == len(expanded), 'Rule-count provenance differs')
    require(set(config['rule-providers']) == set(providers), 'Extra/missing routing providers')
    settings = json.loads((root/'config/mihomo.json').read_text())
    local = settings['direct_dns']
    proxy = ['https://1.1.1.1/dns-query#PROXY', 'https://8.8.8.8/dns-query#PROXY']
    bootstrap = ['https://223.5.5.5/dns-query#DIRECT', 'https://223.6.6.6/dns-query#DIRECT']
    domain_layers = [(n, p) for n, p in order if n and n != 'china-ip']
    expected_policy = [('rule-set:'+n, local if p == 'DIRECT' else proxy) for n, p in domain_layers]
    dns = config['dns']
    require(list(dns['nameserver-policy'].items()) == expected_policy, 'Ordered DNS routing contract changed')
    require(dns['fake-ip-filter'] == [f'RULE-SET,{n},'+('real-ip' if p == 'DIRECT' else 'fake-ip')
                                   for n, p in domain_layers] + ['MATCH,fake-ip'], 'Fake-IP domain order changed')
    require(dns['fake-ip-filter-mode'] == 'rule' and dns['enhanced-mode'] == 'fake-ip', 'Fake-IP policy mode changed')
    require(dns['nameserver'] == proxy and dns['direct-nameserver'] == proxy
            and dns['direct-nameserver-follow-policy'] is True, 'Unknown/proxy DNS may leak to local resolution')
    require(dns['proxy-server-nameserver'] == bootstrap and dns['default-nameserver'] == bootstrap,
            'Node bootstrap depends on the proxy or changed upstream')
    require(dns['respect-rules'] is False and dns['use-system-hosts'] is False
            and dns['ipv6'] is False and 'fallback' not in dns, 'DNS fallback/hosts/IPv6 baseline changed')
    require(dns['listen'] == '127.0.0.1:7874', 'Unexpected default DNS listener')
    # The cases are maintained independently of this converter. Do not derive
    # expected routing decisions or DNS trigger expectations from its output.
    candidate = Policy('[Rule]\n'+'\n'.join(expanded)+'\n')
    results = []
    for case in json.loads((root/'tests/routing_cases.json').read_text()):
        def resolver(_):
            if case.get('dns_error'):
                raise TimeoutError('injected DNS failure')
            return case.get('answers', [])
        result = candidate.decide(case['host'], resolver, case.get('address'), case.get('port', 443))
        require(result['policy'] == case['policy'] and result['routing_dns_requested'] == case['routing_dns_requested'],
                f'Migrated routing contract failed: {case["id"]}')
        results.append({'id': case['id'], **result})
    return {'source_rules': len(expanded), 'ordered_rule_equivalence': 'PASS',
            'routing_cases': len(results), 'routing_failures': 0, 'dns_contract': 'PASS',
            'node_state': 'UNCONFIGURED_REJECT', 'native_real_node_validation': 'NOT_RUN',
            'results': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dist', type=Path, default=ROOT/'dist')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    try:
        result = check(output=args.dist)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
        print(json.dumps({k:v for k,v in result.items() if k != 'results'}, indent=2))
    except (ValueError, OSError, KeyError, yaml.YAMLError) as exc:
        print(f'MIHOMO CHECK FAILED: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
