#!/usr/bin/env python3
"""Fail-closed, deterministic Shadowrocket builder. Python 3.9+, stdlib only."""
import argparse
from collections import Counter
from dataclasses import dataclass
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


class BuildError(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode()


@dataclass(frozen=True, order=True)
class Rule:
    kind: str
    value: str
    policy: str

    def line(self):
        extra = ',no-resolve' if self.kind in ('IP-CIDR', 'IP-CIDR6', 'GEOIP') else ''
        return f'{self.kind},{self.value},{self.policy}{extra}'


def domain(value):
    value = value.lower().rstrip('.')
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise BuildError('Invalid IDNA domain') from exc
    if not value or len(value) > 253:
        raise BuildError('Invalid domain length')
    if any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', x)
           for x in value.split('.')):
        raise BuildError(f'Invalid domain: {value!r}')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise BuildError('IP literal in domain source')


def parents(value):
    labels = value.split('.')
    return ('.'.join(labels[i:]) for i in range(len(labels)))


def parse_community_archive(data, entry, attribute=None):
    """Read without extracting; implement upstream includes AND affiliations."""
    lists, includes = {}, {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            for member in archive:
                total += member.size
                if total > 16 * 1024 * 1024 or member.size > 2 * 1024 * 1024:
                    raise BuildError('Domain archive uncompressed limit exceeded')
                match = re.fullmatch(r'[^/]+/data/([a-z0-9_!-]+)', member.name)
                if not match:
                    continue
                if not member.isfile() or member.size > 2 * 1024 * 1024:
                    raise BuildError('Invalid domain archive member')
                name = match[1]
                if name in lists:
                    raise BuildError('Duplicate archive member')
                lists[name] = []
                includes[name] = []
                text = archive.extractfile(member).read().decode('utf-8-sig')
                for index, raw in enumerate(text.splitlines(), 1):
                    line = raw.split('#', 1)[0].strip()
                    if not line:
                        continue
                    fields = line.split()
                    head, tokens = fields[0], fields[1:]
                    if any(not re.fullmatch(r'[@&][a-zA-Z0-9_!-]+', t) for t in tokens):
                        raise BuildError(f'{name}:{index}: invalid attribute/affiliation')
                    attrs = frozenset(t[1:] for t in tokens if t.startswith('@'))
                    affiliates = tuple(t[1:] for t in tokens if t.startswith('&'))
                    if head.startswith('include:'):
                        target = head.split(':', 1)[1]
                        if not re.fullmatch('[a-z0-9_!-]+', target) or affiliates:
                            raise BuildError('Invalid include')
                        includes[name].append((target, attrs))
                    else:
                        kind, sep, value = head.partition(':')
                        if not sep:
                            kind, value = 'domain', head
                        if kind not in ('domain', 'full', 'regexp', 'keyword') or not value:
                            raise BuildError(f'{name}:{index}: unknown domain syntax')
                        lists[name].append((kind, value, attrs, affiliates))
    except (tarfile.TarError, UnicodeError, EOFError) as exc:
        raise BuildError('Invalid domain archive') from exc
    if len(lists) < 1000:
        raise BuildError('Incomplete community archive')
    # Affiliation adds a record to a target list, including targets without files.
    affiliations = [(record, target) for records in lists.values() for record in records for target in record[3]]
    for record, target in affiliations:
        lists.setdefault(target, []).append(record)
    memo = {}

    def expand(name, stack=()):
        if name in memo:
            return memo[name]
        if name in stack or len(stack) > 64 or name not in lists:
            raise BuildError(f'Missing/cyclic/deep domain include: {name}')
        result = {(k, v, attrs) for k, v, attrs, _ in lists[name]}
        for target, filters in includes.get(name, []):
            for record in expand(target, stack + (name,)):
                attrs = record[2]
                if all((f[1:] not in attrs) if f.startswith('-') else (f in attrs) for f in filters):
                    result.add(record)
        memo[name] = result
        return result

    records = expand(entry)
    # Ads are not blocked: they simply follow other routing rules / FINAL.
    # Foreign-marked entries must not enter the DIRECT whitelist.
    lines = []
    for kind, value, attrs in sorted(records, key=lambda r: (r[0], r[1], sorted(r[2]))):
        if 'ads' in attrs or '!cn' in attrs:
            continue
        if attribute and attribute not in attrs:
            continue
        lines.append(f'{kind}:{value}')
    return ('\n'.join(lines) + '\n').encode()


def parse_source(data, spec):
    """Accept only the verified single-quoted payload subset, never arbitrary YAML."""
    if spec['format'] == 'v2fly-archive':
        flattened = parse_community_archive(data, spec['path'].removeprefix('data/'))
        return parse_source(flattened, dict(spec, format='v2ray-direct'))
    try:
        lines = data.decode('utf-8-sig').splitlines()
    except UnicodeError as exc:
        raise BuildError(f'{spec["id"]}: not UTF-8') from exc
    rules = set()
    rows = 0
    omitted = []
    if spec['format'] == 'clash-domain':
        if not lines or lines[0] != 'payload:':
            raise BuildError(f'{spec["id"]}: missing payload header')
        for index, line in enumerate(lines[1:], 2):
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            match = re.fullmatch(r"  - '([^']+)'", line)
            if not match:
                raise BuildError(f'{spec["id"]}:{index}: unexpected domain format')
            value = match[1]
            kind = 'DOMAIN-SUFFIX' if value.startswith('+.') else 'DOMAIN'
            rules.add(Rule(kind, domain(value[2:] if kind == 'DOMAIN-SUFFIX' else value), spec['policy']))
            rows += 1
    elif spec['format'] == 'v2ray-direct':
        if spec['policy'] != 'DIRECT':
            raise BuildError('Regex omission is permitted only in the DIRECT source')
        for index, line in enumerate(lines, 1):
            if not line.strip() or line.startswith('#'):
                continue
            body, _, attributes = line.partition(':@')
            if ':@' in line and not re.fullmatch(r'[a-zA-Z0-9_!-]+(?:,@[a-zA-Z0-9_!-]+)*', attributes):
                raise BuildError(f'{spec["id"]}:{index}: invalid attributes')
            kind, separator, value = body.partition(':')
            if not separator or not value:
                raise BuildError(f'{spec["id"]}:{index}: missing typed value')
            if kind == 'regexp':
                # Shadowrocket has no verified equivalent domain-regex rule.
                # Omitting a DIRECT exception keeps the conservative PROXY default.
                if len(value) > 2048:
                    raise BuildError('Excessively long regular expression')
                omitted.append(line)
            elif kind in ('domain', 'full'):
                rules.add(Rule('DOMAIN-SUFFIX' if kind == 'domain' else 'DOMAIN',
                               domain(value), 'DIRECT'))
            else:
                raise BuildError(f'{spec["id"]}:{index}: unsupported V2Ray record type')
            rows += 1
        if len(omitted) > 100 or len(omitted) > rows * 0.01:
            raise BuildError('Unexpected proportion of omitted DIRECT regex rules')
    elif spec['format'] in ('cidr4', 'cidr6'):
        version = int(spec['format'][-1])
        nets = set()
        for index, line in enumerate(lines, 1):
            if not line.strip() or line.startswith('#'):
                continue
            try:
                net = ipaddress.ip_network(line, strict=True)
            except ValueError as exc:
                raise BuildError(f'{spec["id"]}:{index}: invalid canonical CIDR') from exc
            if '/' not in line or net.version != version or net.prefixlen == 0:
                raise BuildError(f'{spec["id"]}:{index}: incorrect IP family/default route')
            # A new default/supernet must not turn most of the Internet into DIRECT.
            if net.prefixlen < (8 if version == 4 else 16) or not net.is_global:
                raise BuildError(f'{spec["id"]}:{index}: non-public or excessively broad CIDR')
            nets.add(net)
            rows += 1
        kind = 'IP-CIDR' if version == 4 else 'IP-CIDR6'
        rules = {Rule(kind, str(n), spec['policy']) for n in nets}
    else:
        raise BuildError('Unsupported source format')
    count = len(rules)
    if not spec['min_records'] <= count <= spec['max_records']:
        raise BuildError(f'{spec["id"]}: unexpected unique count {count}')
    duplicates = rows - count - len(omitted)
    if rows and duplicates / rows > 0.05:
        raise BuildError(f'{spec["id"]}: more than 5% duplicate input records')
    return rules, {'records': rows, 'unique': count, 'duplicates': duplicates,
                   'omitted_direct_regex': omitted}


def minimize(rules):
    suffixes = {r.value for r in rules if r.kind == 'DOMAIN-SUFFIX'}
    result = set()
    for rule in rules:
        candidates = list(parents(rule.value))
        if rule.kind == 'DOMAIN-SUFFIX':
            candidates = candidates[1:]
        if not any(p in suffixes for p in candidates):
            result.add(rule)
    return result


def precise_direct(rules, config):
    """A TLD/registry suffix is not evidence about an individual business."""
    excluded = set(config['direct_excluded_suffixes'])
    if not {'cn', 'com.cn', 'net.cn', 'org.cn'} <= excluded:
        raise BuildError('Missing registry-level DIRECT exclusions')
    return {r for r in rules if not (r.kind == 'DOMAIN-SUFFIX'
            and ('.' not in r.value or r.value in excluded))}


def resolve_conflicts(proxy, direct):
    """PROXY wins, even a broader suffix vs a more specific DIRECT entry."""
    p_suffix = {r.value: r for r in proxy if r.kind == 'DOMAIN-SUFFIX'}
    p_exact = {r.value: r for r in proxy if r.kind == 'DOMAIN'}
    d_suffix = {r.value: r for r in direct if r.kind == 'DOMAIN-SUFFIX'}
    kept, conflicts = set(), []
    for rule in sorted(direct):
        winner = next((p_suffix[p] for p in parents(rule.value) if p in p_suffix), None)
        if rule.kind == 'DOMAIN' and not winner:
            winner = p_exact.get(rule.value)
        if winner:
            conflicts.append({'direct': rule.line(), 'proxy': winner.line(), 'action': 'drop-direct'})
        else:
            kept.add(rule)
    for rule in sorted(proxy):
        ancestor = next((d_suffix[p] for p in parents(rule.value) if p in d_suffix), None)
        if ancestor and ancestor in kept:
            conflicts.append({'direct': ancestor.line(), 'proxy': rule.line(), 'action': 'proxy-first-exception'})
    return kept, sorted(conflicts, key=lambda x: (x['direct'], x['proxy'], x['action']))


def domain_overlap(a, b):
    """Whether two exact/suffix rules can match at least one common hostname."""
    if a.kind == b.kind == 'DOMAIN':
        return a.value == b.value
    if a.kind == 'DOMAIN':
        return a.value == b.value or a.value.endswith('.' + b.value)
    if b.kind == 'DOMAIN':
        return b.value == a.value or b.value.endswith('.' + a.value)
    return (a.value == b.value or a.value.endswith('.' + b.value)
            or b.value.endswith('.' + a.value))


def reviewed_rules(overrides, archive=None):
    """Local reviewed policy is independent of upstream minimization/classification."""
    if set(overrides) != {'schema', 'proxy_suffix', 'lan_domains', 'direct_exceptions'} or overrides['schema'] != 2:
        raise BuildError('Unknown reviewed-policy schema')
    if not isinstance(overrides['proxy_suffix'], list) or not overrides['proxy_suffix']:
        raise BuildError('Missing protected proxy domains')
    protected = {Rule('DOMAIN-SUFFIX', domain(x), 'PROXY') for x in overrides['proxy_suffix']}
    if len(protected) != len(overrides['proxy_suffix']):
        raise BuildError('Duplicate protected proxy domain')
    result, ids, seen, evidence_cache = {}, set(), set(), {}
    broad = {'cn', 'com', 'net', 'org', 'com.cn', 'net.cn', 'org.cn', 'co.uk',
             'apple.com', 'microsoft.com', 'cloudflare.net',
             'cloudflare.com', 'akadns.net', 'akamaiedge.net', 'akamaihd.net', 'cloudfront.net'}
    for section in ('lan_domains', 'direct_exceptions'):
        groups = overrides[section]
        if not isinstance(groups, list) or not groups:
            raise BuildError('Missing reviewed-policy groups')
        entries = {}
        for group in groups:
            required = {'id', 'type', 'domains', 'reason', 'evidence'}
            if not isinstance(group, dict) or not required <= set(group) or set(group) - required - {'community_check'}:
                raise BuildError('Invalid reviewed group fields')
            ident = group['id']
            if not isinstance(ident, str) or not re.fullmatch('[a-z0-9-]+', ident) or ident in ids:
                raise BuildError('Invalid/duplicate reviewed group ID')
            ids.add(ident)
            kind = group['type']
            if kind not in ('DOMAIN', 'DOMAIN-SUFFIX') or (section == 'lan_domains' and kind != 'DOMAIN'):
                raise BuildError('Reviewed rules must be exact or approved domain families')
            if not isinstance(group['reason'], str) or not group['reason'].strip() or '\n' in group['reason']:
                raise BuildError('Missing reviewed-policy rationale')
            evidence = group['evidence']
            if (not isinstance(evidence, list) or not evidence
                    or any(not isinstance(u, str) or not re.fullmatch(r'https://[^\s]+', u) for u in evidence)):
                raise BuildError('Missing HTTPS policy evidence')
            values = group['domains']
            if not isinstance(values, list) or not values or len(values) > 100:
                raise BuildError('Invalid reviewed domain list')
            witness = None
            if 'community_check' in group:
                check = group['community_check']
                if (not isinstance(check, dict) or set(check) - {'entry', 'attribute'}
                        or not re.fullmatch('[a-z0-9_!-]+', check.get('entry', ''))
                        or ('attribute' in check and check['attribute'] != 'cn')):
                    raise BuildError('Invalid community evidence selector')
                if archive is not None:
                    key = (check['entry'], check.get('attribute'))
                    if key not in evidence_cache:
                        data = parse_community_archive(archive, *key)
                        evidence_cache[key], _ = parse_source(data, {'id': ident, 'format': 'v2ray-direct',
                            'policy': 'DIRECT', 'min_records': 1, 'max_records': 50000})
                    witness = evidence_cache[key]
            for value in values:
                if not isinstance(value, str) or domain(value) != value or '.' not in value or value in broad:
                    raise BuildError('Unsafe broad/noncanonical reviewed domain')
                rule = Rule(kind, value, 'DIRECT')
                if rule in seen:
                    raise BuildError('Duplicate reviewed rule')
                seen.add(rule)
                if any(domain_overlap(rule, p) for p in protected):
                    raise BuildError(f'Reviewed DIRECT intersects protected proxy: {value}')
                if witness is not None and not any(
                        (w.kind == 'DOMAIN-SUFFIX' and (value == w.value or value.endswith('.' + w.value)))
                        or (w.kind == kind == 'DOMAIN' and value == w.value) for w in witness):
                    raise BuildError(f'Reviewed domain lost its upstream evidence: {value}')
                entries[rule] = ident
        result[section] = entries
    if len(seen) > 250:
        raise BuildError('Reviewed policy exceeds small-list budget')
    return result, protected


def match_rules(rules, host, address=None, port=None):
    """Textual first-match model. Does not simulate Shadowrocket's DNS/TUN."""
    host = host.lower().rstrip('.')
    ip = ipaddress.ip_address(address) if address else None
    for line in rules:
        parts = line.split(',')
        kind = parts[0]
        if kind == 'FINAL':
            return parts[1]
        value, policy = parts[1:3]
        if kind == 'DST-PORT' and port is not None and int(value) == port:
            return policy
        if kind == 'DOMAIN' and host == value:
            return policy
        if kind == 'DOMAIN-SUFFIX' and (host == value or host.endswith('.' + value)):
            return policy
        if kind == 'DOMAIN-KEYWORD' and value in host:
            return policy
        if kind in ('IP-CIDR', 'IP-CIDR6') and ip:
            net = ipaddress.ip_network(value)
            if ip.version == net.version and ip in net:
                return policy
    raise BuildError('No FINAL rule')


def rule_lines(conf):
    section, result = None, []
    for raw in conf.splitlines():
        line = raw.strip()
        if line.startswith('['):
            section = line
        elif section == '[Rule]' and line and not line.startswith('#'):
            result.append(line)
    return result


def validate(conf, overrides=None):
    if overrides is None:
        overrides = json.loads((ROOT / 'config/overrides.json').read_text())
    reviewed, _ = reviewed_rules(overrides)
    sections = re.findall(r'^\[([^\]]+)\]$', conf, flags=re.M)
    if sections != ['General', 'Rule', 'Host'] or '{{' in conf or '\r' in conf:
        raise BuildError('Unexpected sections, template token, or encoding')
    general = conf.split('[General]\n', 1)[1].split('[Rule]', 1)[0]
    settings = {}
    for line in general.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        if ' = ' not in line:
            raise BuildError('Malformed General setting')
        key, value = line.split(' = ', 1)
        if key in settings:
            raise BuildError('Duplicate General setting')
        settings[key] = value
    required = {
        'dns-server': 'https://1.1.1.1/dns-query#proxy, https://8.8.8.8/dns-query#proxy',
        'fallback-dns-server': 'https://8.8.8.8/dns-query#proxy',
        'proxy-dns-server': 'https://223.5.5.5/dns-query, https://223.6.6.6/dns-query',
        'dns-fallback': 'false', 'dns-direct-system': 'true',
        'dns-direct-fallback-proxy': 'false', 'always-ip-address': 'false',
        'use-local-host-item-for-proxy': 'false', 'ipv6': 'false',
        'prefer-ipv6': 'false',
        'hijack-dns': '*:53',
        'bypass-system': 'false', 'udp-policy-not-supported-behaviour': 'REJECT'
    }
    if any(settings.get(k) != v for k, v in required.items()):
        raise BuildError('DNS/routing baseline changed: update the design and validator together')
    if 'dns-fallback-system' in settings or 'direct-dns-server' in settings:
        raise BuildError('Unexpected DNS override')
    markers = ['# BEGIN LAN', '# END LAN', '# BEGIN DNS GUARD', '# END DNS GUARD',
               '# BEGIN LOCAL NAMES', '# END LOCAL NAMES', '# BEGIN REVIEWED DIRECT', '# END REVIEWED DIRECT',
               '# BEGIN PROXY', '# END PROXY',
               '# BEGIN DIRECT', '# END DIRECT', '# BEGIN CHINA IP', '# END CHINA IP', 'FINAL,PROXY']
    offsets = [conf.index(m) for m in markers]
    if offsets != sorted(offsets) or any(conf.count(m) != 1 for m in markers):
        raise BuildError('Wrong routing block order')
    rules = rule_lines(conf)
    if not rules or rules[-1] != 'FINAL,PROXY' or len(rules) != len(set(rules)):
        raise BuildError('Duplicate rules or incorrect FINAL')
    guard = conf.split('# BEGIN DNS GUARD\n')[1].split('# END DNS GUARD')[0]
    guard_rules = [x for x in guard.splitlines() if x and not x.startswith('#')]
    if guard_rules != ['DST-PORT,53,REJECT']:
        raise BuildError('Missing or weakened port-53 DNS guard')
    for section, marker in [('lan_domains', 'LOCAL NAMES'), ('direct_exceptions', 'REVIEWED DIRECT')]:
        actual = conf.split(f'# BEGIN {marker}\n')[1].split(f'# END {marker}')[0]
        actual = [x for x in actual.splitlines() if x and not x.startswith('#')]
        if set(actual) != {r.line() for r in reviewed[section]} or len(actual) != len(set(actual)):
            raise BuildError(f'Reviewed block differs from approved policy: {marker}')
    for line in rules[:-1]:
        # This single security guard is the only permitted REJECT rule.
        # Upstream domain/IP data still cannot inject blocking policies.
        if line == 'DST-PORT,53,REJECT':
            continue
        parts = line.split(',')
        if len(parts) not in (3, 4) or parts[2] not in ('DIRECT', 'PROXY'):
            raise BuildError('Unexpected rule/policy')
        if parts[0] in ('DOMAIN', 'DOMAIN-SUFFIX'):
            if len(parts) != 3 or domain(parts[1]) != parts[1]:
                raise BuildError('Malformed domain rule')
            excluded = {'cn', 'com.cn', 'net.cn', 'org.cn', 'ac.cn', 'edu.cn', 'gov.cn', 'mil.cn'}
            if parts[2] == 'DIRECT' and parts[0] == 'DOMAIN-SUFFIX' and (
                    ('.' not in parts[1] and parts[1] not in {'local', 'lan'}) or parts[1] in excluded):
                raise BuildError('Registry-level DIRECT rule is forbidden')
        elif parts[0] in ('IP-CIDR', 'IP-CIDR6'):
            if len(parts) != 4 or parts[3] != 'no-resolve':
                raise BuildError('IP rule without no-resolve')
            net = ipaddress.ip_network(parts[1], strict=True)
            if net.version != (4 if parts[0] == 'IP-CIDR' else 6):
                raise BuildError('Incorrect rule IP family')
        else:
            raise BuildError('Unsupported rule type (no remote sets, scripts or GEOIP)')
    # Validate policy inside each dynamic block, not only the canary endpoints.
    for block, policy in [('PROXY', 'PROXY'), ('DIRECT', 'DIRECT'), ('CHINA IP', 'DIRECT')]:
        content = conf.split(f'# BEGIN {block}\n')[1].split(f'# END {block}')[0]
        if not content.strip() or any(x.split(',')[2] != policy for x in content.splitlines()):
            raise BuildError(f'Invalid {block} block')
    canaries = [('www.baidu.com', None, 'DIRECT'), ('www.taobao.com', None, 'DIRECT'),
                ('www.qq.com', None, 'DIRECT'),
                ('short.weixin.qq.com', None, 'DIRECT'),
                ('long.weixin.qq.com', None, 'DIRECT'),
                ('wx.qlogo.cn', None, 'DIRECT'), ('mmbiz.qpic.cn', None, 'DIRECT'),
                ('www.google.com', None, 'PROXY'),
                ('github.com', None, 'PROXY'), ('chatgpt.com', None, 'PROXY'),
                ('api.openai.com', None, 'PROXY'), ('www.google.cn', None, 'PROXY'),
                ('fresh-unlisted.invalid', None, 'PROXY'),
                ('fresh-unlisted.cn', None, 'PROXY'),
                ('fresh-unlisted.com.cn', None, 'PROXY'),
                ('fresh-unlisted.xn--fiqs8s', None, 'PROXY'),
                ('printer.local', None, 'DIRECT'), ('nas.home.arpa', None, 'DIRECT'),
                ('', '192.168.1.1', 'DIRECT'), ('', '223.5.5.5', 'DIRECT'),
                ('', '2400:3200::1', 'DIRECT'), ('', '1.1.1.1', 'PROXY'),
                ('', '2606:4700:4700::1111', 'PROXY')]
    for host, ip, expected in canaries:
        if match_rules(rules, host, ip) != expected:
            raise BuildError(f'Routing canary failed: {host or ip}')
    dns_canaries = [('223.5.5.5', 'REJECT'), ('119.29.29.29', 'REJECT'),
                    ('9.9.9.9', 'REJECT'), ('2606:4700:4700::1111', 'REJECT'),
                    ('192.168.1.1', 'DIRECT'), ('fe80::1', 'DIRECT')]
    for address, expected in dns_canaries:
        if match_rules(rules, '', address, port=53) != expected:
            raise BuildError(f'DNS fallback rule failed: {address}')
    for section, entries in reviewed.items():
        for rule in entries:
            host = rule.value
            if match_rules(rules, host, port=443) != 'DIRECT':
                raise BuildError(f'Reviewed route failed: {host}')
            if match_rules(rules, host, port=53) != 'REJECT':
                raise BuildError(f'Reviewed route bypasses DNS guard: {host}')
    return {'rules': len(rules), 'types': dict(sorted(Counter(x.split(',')[0] for x in rules).items())),
            'routing_canaries': len(canaries), 'dns_port_canaries': len(dns_canaries),
            'reviewed_route_canaries': sum(len(x) for x in reviewed.values())}


def download(url, limit=8388608, token=None, attempts=3):
    if not url.startswith('https://'):
        raise BuildError('HTTPS required')
    for attempt in range(attempts):
        try:
            headers = {'User-Agent': 'Shadowrocket-Rules-builder/1'}
            if token and url.startswith('https://api.github.com/'):
                headers['Authorization'] = f'Bearer {token}'
            request = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(request, timeout=30) as response:
                if not response.geturl().startswith('https://'):
                    raise BuildError('Insecure download redirect')
                data = response.read(limit + 1)
                if not data or len(data) > limit:
                    raise BuildError('Empty or oversized download')
                return data
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt + 1 == attempts:
                # Do not print tokens or URLs supplied by external error bodies.
                raise BuildError(f'Download failed after {attempts} attempts: {url}') from exc
            time.sleep(2 ** attempt)


def fetch_inputs(config):
    revisions, inputs, metadata = {}, {}, {}
    for spec in config['sources']:
        repo, ref = spec['repository'], spec['ref']
        key = (repo, ref)
        if key not in revisions:
            url = f'https://api.github.com/repos/{repo}/git/ref/heads/{ref}'
            obj = json.loads(download(url, token=os.environ.get('GH_TOKEN')))['object']
            if obj['type'] != 'commit' or not re.fullmatch('[a-f0-9]{40}', obj['sha']):
                raise BuildError('Invalid upstream revision')
            revisions[key] = obj['sha']
        revision = revisions[key]
        url = (f'https://codeload.github.com/{repo}/tar.gz/{revision}' if spec.get('format') == 'v2fly-archive'
               else f'https://raw.githubusercontent.com/{repo}/{revision}/{spec["path"]}')
        inputs[spec['id']] = download(url, limit=config['max_bytes'])
        metadata[spec['id']] = {'revision': revision, 'url': url}
    return inputs, metadata


def offline_inputs(output, config):
    manifest = json.loads((output / 'manifest.json').read_text())
    inputs, metadata = {}, {}
    for spec in config['sources']:
        ident = spec['id']
        data = (output / 'inputs' / snapshot_name(spec)).read_bytes()
        if sha(data) != manifest['sources'][ident]['sha256']:
            raise BuildError(f'{ident}: offline snapshot hash mismatch')
        inputs[ident] = data
        metadata[ident] = {k: manifest['sources'][ident][k] for k in ('revision', 'url')}
    return inputs, metadata


def snapshot_name(spec):
    return spec['id'] + ('.tar.gz' if spec['format'] == 'v2fly-archive' else '.txt')


def generate(config, template, overrides, inputs, metadata, baseline=None):
    all_rules, sources = {}, {}
    for spec in config['sources']:
        ident = spec['id']
        data = inputs[ident]
        if not data or len(data) > config['max_bytes']:
            raise BuildError(f'{ident}: empty or oversized input')
        rules, stats = parse_source(data, spec)
        if baseline:
            old = baseline['sources'][ident]['unique']
            ratio = stats['unique'] / old
            if not config['min_ratio'] <= ratio <= config['max_ratio']:
                raise BuildError(f'{ident}: abnormal change {old} -> {stats["unique"]}')
        all_rules[ident] = rules
        sources[ident] = {**stats, **metadata[ident], 'sha256': sha(data),
                          'bytes': len(data), 'license': spec['license']}
    reviewed, protected = reviewed_rules(overrides, inputs['direct'])
    proxy = all_rules['proxy'] | protected
    proxy, direct = minimize(proxy), minimize(precise_direct(all_rules['direct'], config))
    direct, conflicts = resolve_conflicts(proxy, direct)
    for item in conflicts:
        item['stage'] = 'ordinary-sources'
    # Explicit local policy remains separate, so .cn minimization cannot erase it.
    explicit = set().union(*reviewed.values())
    proxy = {r for r in proxy if not (r.kind == 'DOMAIN' and Rule(r.kind, r.value, 'DIRECT') in explicit)}
    direct -= explicit
    for section, entries in reviewed.items():
        for rule, ident in sorted(entries.items()):
            for p in sorted(proxy):
                if domain_overlap(rule, p):
                    conflicts.append({'action': 'reviewed-direct-override', 'stage': 'reviewed-policy', 'group': ident,
                                      'direct': rule.line(), 'proxy': p.line()})
    # Never let an upstream entry duplicate or shadow reserved local namespaces.
    reserved = {'local', 'lan', 'home.arpa', 'in-addr.arpa', 'ip6.arpa', 'localhost'}
    for rule in proxy | direct:
        if any(p in reserved for p in parents(rule.value)):
            raise BuildError('Upstream intrudes into reserved local namespace')
    ip_rules = set()
    coverage = {}
    for ident in ('china4', 'china6'):
        nets = [ipaddress.ip_network(r.value) for r in all_rules[ident]]
        nets = list(ipaddress.collapse_addresses(nets))
        coverage[ident] = sum(n.num_addresses for n in nets)
        if baseline:
            old = baseline['ip_coverage'][ident]
            ratio = coverage[ident] / old
            if not config['min_ratio'] <= ratio <= config['max_ratio']:
                raise BuildError(f'{ident}: abnormal covered address change')
        kind = 'IP-CIDR' if ident == 'china4' else 'IP-CIDR6'
        ip_rules.update(Rule(kind, str(net), 'DIRECT') for net in nets)
    content = template
    for marker, rules in [('LOCAL_NAME_RULES', reviewed['lan_domains']),
                          ('REVIEWED_DIRECT_RULES', reviewed['direct_exceptions']),
                          ('PROXY_RULES', proxy), ('DIRECT_RULES', direct), ('IP_RULES', ip_rules)]:
        token = '{{' + marker + '}}'
        if content.count(token) != 1:
            raise BuildError('Missing or repeated template token')
        ordered = sorted(rules, key=lambda r: (r.kind, r.value))
        content = content.replace(token, '\n'.join(r.line() for r in ordered))
    stats = validate(content, overrides)
    if stats['rules'] > config['max_output_rules'] or len(content.encode()) > config['max_output_bytes']:
        raise BuildError('Output exceeds reviewed client size budget')
    manifest = {'schema': 1, 'sources': sources, 'ip_coverage': coverage,
                'excluded_registry_direct': sorted(r.line() for r in all_rules['direct']
                    - precise_direct(all_rules['direct'], config)),
                'config_sha256': sha(content.encode()),
                'generator_sha256': sha(Path(__file__).read_bytes()),
                'template_sha256': sha(template.encode()),
                'sources_spec_sha256': sha(json_bytes(config)),
                'overrides_sha256': sha(json_bytes(overrides)),
                'output': stats, 'conflicts': len(conflicts)}
    files = {'Shadowrocket.conf': content.encode(), 'manifest.json': json_bytes(manifest),
             'conflicts.json': json_bytes(conflicts)}
    files.update({f'inputs/{snapshot_name(spec)}': inputs[spec['id']] for spec in config['sources']})
    return files


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def run(root=ROOT, output=None, offline=False, check=False):
    output = output or root / 'dist'
    config = json.loads((root / 'sources/sources.json').read_text())
    template = (root / 'config/template.conf').read_text()
    overrides = json.loads((root / 'config/overrides.json').read_text())
    old_manifest = output / 'manifest.json'
    baseline = json.loads(old_manifest.read_text()) if old_manifest.exists() else None
    inputs, metadata = offline_inputs(output, config) if offline else fetch_inputs(config)
    files = generate(config, template, overrides, inputs, metadata, baseline)
    conf_path = output / 'Shadowrocket.conf'
    unchanged = conf_path.exists() and conf_path.read_bytes() == files['Shadowrocket.conf']
    if check:
        # --check proves exact reproducibility including audit files and input hashes.
        if any(not (output / name).exists() or (output / name).read_bytes() != data
               for name, data in files.items()):
            raise BuildError('Generated files differ; rebuild before publishing')
        print('CHECK_OK: complete configuration and provenance reproduce exactly')
        return False
    # Revision-only changes are not publications. Keep the last published provenance.
    if unchanged and baseline and all(baseline.get(k) == json.loads(files['manifest.json']).get(k)
                                      for k in ('generator_sha256', 'template_sha256', 'sources_spec_sha256', 'overrides_sha256')):
        print('NO_CHANGE: keeping published configuration and its source snapshots')
        return False
    # No mutation occurs before ALL downloads, parsing, gates and canaries pass.
    # Config is replaced last and atomically; a Git commit publishes the whole set.
    for name, data in files.items():
        if name != 'Shadowrocket.conf':
            atomic_write(output / name, data)
    atomic_write(conf_path, files['Shadowrocket.conf'])
    stats = json.loads(files['manifest.json'])['output']
    print('BUILT:', json.dumps(stats, sort_keys=True))
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true', help='Use verified dist/inputs snapshots')
    parser.add_argument('--check', action='store_true', help='Compare, never write (normally with --offline)')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    try:
        run(output=args.output, offline=args.offline, check=args.check)
    except (BuildError, OSError, KeyError, ValueError) as exc:
        print(f'BUILD FAILED: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
