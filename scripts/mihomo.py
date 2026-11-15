#!/usr/bin/env python3
"""Deterministic Mihomo policy output from the already validated SR policy.

No network, credentials, new upstream lists, or second routing classifier.
The small YAML emitter only serializes JSON-compatible values; independent
PyYAML and native Mihomo checks validate the serialized artifacts.
"""
import hashlib
import ipaddress
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
BLOCKS = (
    ('LAN', 'lan', 'DIRECT'),
    ('DNS GUARD', None, 'REJECT'),
    ('LOCAL NAMES', 'local-names', 'DIRECT'),
    ('PROTECTED', 'protected', 'PROXY'),
    ('REVIEWED DIRECT', 'reviewed-direct', 'DIRECT'),
    ('REGIONAL', 'regional', 'DIRECT'),
    ('DIRECT', 'direct', 'DIRECT'),
    ('PROXY', 'proxy', 'PROXY'),
    ('CHINA IP', 'china-ip', 'DIRECT'),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def yaml_bytes(value):
    """Emit ordinary, alias-free YAML with JSON-escaped string scalars."""
    def scalar(item):
        if not isinstance(item, (str, int, bool, type(None))):
            raise ValueError('Unsupported YAML scalar')
        return json.dumps(item, ensure_ascii=False)

    def key(item):
        return item if re.fullmatch(r'[a-z][a-z0-9_-]*', item) else scalar(item)

    def emit(item, indent=0):
        pad = ' ' * indent
        if isinstance(item, dict):
            for name, val in item.items():
                head = pad + key(name) + ':'
                if isinstance(val, (dict, list)) and val:
                    yield head
                    yield from emit(val, indent + 2)
                else:
                    yield head + ' ' + ('{}' if val == {} else '[]' if val == [] else scalar(val))
        elif isinstance(item, list):
            for val in item:
                if isinstance(val, (dict, list)) and val:
                    yield pad + '-'
                    yield from emit(val, indent + 2)
                else:
                    yield pad + '- ' + ('{}' if val == {} else '[]' if val == [] else scalar(val))
        else:
            raise ValueError('YAML root/container must be a mapping or list')
    return ('# Generated from the reviewed Shadowrocket policy; do not edit dist.\n'
            + '\n'.join(emit(value)) + '\n').encode()


def source_blocks(conf):
    result = {}
    for title, _, action in BLOCKS:
        start, end = f'# BEGIN {title}\n', f'# END {title}'
        if conf.count(start) != 1 or conf.count(end) != 1:
            raise ValueError(f'Missing/repeated policy block: {title}')
        rows = [line.strip() for line in conf.split(start)[1].split(end)[0].splitlines()
                if line.strip() and not line.lstrip().startswith('#')]
        if not rows or any(row.split(',')[2] != action for row in rows):
            raise ValueError(f'Unexpected block policy: {title}')
        result[title] = rows
    return result


def validate_settings(settings):
    if set(settings) != {'schema', 'direct_dns'} or settings['schema'] != 1:
        raise ValueError('Unknown Mihomo deployment-settings schema')
    servers = settings['direct_dns']
    if not isinstance(servers, list) or not servers or len(set(servers)) != len(servers):
        raise ValueError('Missing/duplicate explicit local DNS servers')
    for server in servers:
        match = re.fullmatch(r'udp://([0-9.]+):53#DIRECT', server)
        if not match:
            raise ValueError('Local DNS must be an explicit IPv4 UDP upstream with #DIRECT')
        ip = ipaddress.ip_address(match[1])
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or str(ip) == '192.168.1.99':
            raise ValueError('Local DNS must not loop back to this OpenClash/DNS listener')


def dns_servers(conf, setting, via):
    match = re.search(r'^' + re.escape(setting) + r' = (.+)$', conf, re.M)
    if not match:
        raise ValueError(f'Missing DNS contract: {setting}')
    result = []
    for endpoint in match[1].split(', '):
        # The reviewed input has IP-literal HTTPS endpoints, with #proxy only
        # for proxy/unknown lookups. No implicit system resolver or fallback.
        original, _, tag = endpoint.partition('#')
        if not re.fullmatch(r'https://[0-9.]+/dns-query', original):
            raise ValueError('Unexpected DNS endpoint in reviewed policy')
        if tag != ('proxy' if via == 'PROXY' else ''):
            raise ValueError('Unexpected DNS routing tag')
        result.append(original + '#' + via)
    return result


def generate(conf, settings=None):
    settings = settings if settings is not None else json.loads((ROOT/'config/mihomo.json').read_text())
    validate_settings(settings)
    blocks = source_blocks(conf)
    proxy_dns = dns_servers(conf, 'dns-server', 'PROXY')
    bootstrap = dns_servers(conf, 'proxy-dns-server', 'DIRECT')
    local_dns = settings['direct_dns']
    providers, rules, policy, fake_filter, files, counts = {}, [], {}, [], {}, {}
    for title, name, action in BLOCKS:
        rows = blocks[title]
        if name is None:
            if rows != ['DST-PORT,53,REJECT']:
                raise ValueError('DNS port guard differs from reviewed contract')
            rules.extend(rows)
            continue
        payload = []
        for row in rows:
            kind, value, target, *flags = row.split(',')
            if kind not in ('DOMAIN', 'DOMAIN-SUFFIX', 'IP-CIDR', 'IP-CIDR6'):
                raise ValueError('Unreviewed rule type in Mihomo conversion')
            expected = ['no-resolve'] if title == 'LAN' and kind.startswith('IP-CIDR') else []
            if target != action or flags != expected:
                raise ValueError('Unexpected target or resolution flag')
            payload.append(f'{kind},{value}')
        counts[name] = len(payload)
        # One self-contained policy snapshot: OpenClash updates the entire YAML
        # atomically. Eight independently refreshed URLs could mix generations.
        providers[name] = {'type': 'inline', 'behavior': 'classical', 'payload': payload}
        rules.append(f'RULE-SET,{name},{action}' + (',no-resolve' if title == 'LAN' else ''))
        if action == 'PROXY':
            # Mihomo skips unsupported-UDP outbounds. Do not let a protected
            # domain then hit a later CN-IP DIRECT rule (SR rejects instead).
            rules.append(f'AND,((NETWORK,udp),(RULE-SET,{name})),REJECT')
        if any(row.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,')) for row in rows):
            policy['rule-set:' + name] = local_dns if action == 'DIRECT' else proxy_dns
            fake_filter.append(f'RULE-SET,{name},' + ('real-ip' if action == 'DIRECT' else 'fake-ip'))
    rules.extend(['MATCH,PROXY', 'MATCH,REJECT'])
    fake_filter.append('MATCH,fake-ip')
    config = {
        'mixed-port': 7893, 'allow-lan': False, 'bind-address': '127.0.0.1',
        'mode': 'rule', 'log-level': 'info', 'ipv6': False, 'find-process-mode': 'off',
        'hosts': {'localhost': '127.0.0.1'},
        'proxies': [],
        # This is explicitly unconfigured, not a working/placeholder node.
        # Empty provider/selector defaults must never select DIRECT.
        'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': ['REJECT']}],
        'dns': {
            'enable': True, 'listen': '127.0.0.1:7874', 'ipv6': False,
            'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
            'fake-ip-filter-mode': 'rule', 'fake-ip-filter': fake_filter,
            'use-hosts': True, 'use-system-hosts': False, 'respect-rules': False,
            'default-nameserver': bootstrap, 'proxy-server-nameserver': bootstrap,
            'nameserver': proxy_dns,
            # Re-resolving a CN-IP DIRECT result must not leak the previously
            # unknown domain to local DNS. Known DIRECT names match the policy.
            'direct-nameserver': proxy_dns, 'direct-nameserver-follow-policy': True,
            'nameserver-policy': policy,
        },
        'rule-providers': providers, 'rules': rules,
    }
    files['Mihomo.yaml'] = yaml_bytes(config)
    manifest = {
        'schema': 1, 'source_config_sha256': digest(conf.encode()),
        'generator_sha256': digest(Path(__file__).read_bytes()),
        'settings_sha256': digest(json.dumps(settings, sort_keys=True).encode()),
        'node_state': 'UNCONFIGURED_REJECT', 'source_rules': sum(counts.values()) + 2,
        'blocks': counts, 'unsupported_udp_guards': 2, 'final_reject_guard': True,
        'files': {name: {'sha256': digest(data), 'bytes': len(data)} for name, data in sorted(files.items())},
    }
    files['manifest.json'] = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    return {'mihomo/' + name: data for name, data in files.items()}
