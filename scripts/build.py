#!/usr/bin/env python3
"""Deterministic destination-IP routing builder. Python 3.9+, stdlib only."""
from collections import Counter
from functools import lru_cache
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
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


LOCAL_RULES = (
    'DOMAIN,localhost,DIRECT',
    *('DOMAIN-SUFFIX,' + h + ',DIRECT' for h in ('local', 'lan', 'home.arpa', 'in-addr.arpa', 'ip6.arpa')),
    *('IP-CIDR,' + n + ',DIRECT,no-resolve' for n in (
        '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
        '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4', '255.255.255.255/32')),
    *('IP-CIDR6,' + n + ',DIRECT,no-resolve' for n in ('::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8')),
)
REQUIRED_SETTINGS = {
    'dns-server': 'https://1.1.1.1/dns-query#proxy, https://8.8.8.8/dns-query#proxy',
    'fallback-dns-server': 'https://8.8.8.8/dns-query#proxy',
    'proxy-dns-server': 'https://223.5.5.5/dns-query, https://223.6.6.6/dns-query',
    'dns-fallback': 'false', 'dns-direct-system': 'false',
    'dns-direct-fallback-proxy': 'false', 'always-ip-address': 'true',
    'use-local-host-item-for-proxy': 'true', 'ipv6': 'false', 'prefer-ipv6': 'false',
    'hijack-dns': '*:53', 'bypass-system': 'false', 'private-ip-answer': 'true',
    'udp-policy-not-supported-behaviour': 'REJECT',
    'skip-proxy': 'localhost, *.local, *.lan, *.home.arpa, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16',
    'tun-excluded-routes': '10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32, ::1/128, fc00::/7, fe80::/10, ff00::/8',
}


def parse_source(data, spec):
    if spec['format'] not in ('cidr4', 'cidr6') or spec['policy'] != 'DIRECT':
        raise BuildError('Only mainland destination-IP sources are supported')
    try:
        lines = data.decode('utf-8-sig').splitlines()
    except UnicodeError as exc:
        raise BuildError('Source is not UTF-8') from exc
    nets, rows = set(), 0
    version = int(spec['format'][-1])
    for line in lines:
        if not line.strip() or line.startswith('#'):
            continue
        try:
            net = ipaddress.ip_network(line, strict=True)
        except ValueError as exc:
            raise BuildError('Invalid canonical CIDR') from exc
        if '/' not in line or net.version != version or net.prefixlen < (8 if version == 4 else 16) or not net.is_global:
            raise BuildError('Incorrect family, non-public or excessively broad CIDR')
        nets.add(net)
        rows += 1
    if not spec['min_records'] <= len(nets) <= spec['max_records']:
        raise BuildError('Unexpected unique source count')
    if rows and (rows-len(nets))/rows > .05:
        raise BuildError('More than 5% duplicate input records')
    return nets, {'records': rows, 'unique': len(nets), 'duplicates': rows-len(nets)}


@lru_cache(maxsize=40000)
def network(value):
    return ipaddress.ip_network(value)


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
            net = network(value)
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


def block(conf, name):
    start, end = '# BEGIN '+name+'\n', '# END '+name
    if conf.count(start) != 1 or conf.count(end) != 1:
        raise BuildError('Missing or duplicate rule block')
    return [x for x in conf.split(start)[1].split(end)[0].splitlines() if x and not x.startswith('#')]


def validate(conf):
    if re.findall(r'^\[([^\]]+)\]$', conf, re.M) != ['General', 'Rule', 'Host'] or '{{' in conf or '\r' in conf:
        raise BuildError('Unexpected sections or unexpanded template')
    settings = {}
    for line in conf.split('[General]\n')[1].split('[Rule]')[0].splitlines():
        if not line.strip() or line.startswith('#'): continue
        if ' = ' not in line: raise BuildError('Malformed setting')
        key, value = line.split(' = ', 1)
        if key in settings: raise BuildError('Duplicate setting')
        settings[key] = value
    if settings != REQUIRED_SETTINGS:
        raise BuildError('Destination-IP DNS/routing baseline changed')
    if conf.split('[Host]\n')[1].strip() != 'localhost = 127.0.0.1':
        raise BuildError('Unexpected host mapping')
    lan, guard, ips = (block(conf, n) for n in ['LAN', 'DNS GUARD', 'CHINA IP'])
    if lan != list(LOCAL_RULES) or guard != ['DST-PORT,53,REJECT'] or not ips:
        raise BuildError('Unexpected local/DNS/IP rules')
    rules = rule_lines(conf)
    if rules != lan + guard + ips + ['FINAL,PROXY'] or len(set(rules)) != len(rules):
        raise BuildError('Wrong order, duplicates or extra routing rules')
    for line in ips:
        cells = line.split(',')
        if len(cells) != 3 or cells[0] not in ('IP-CIDR', 'IP-CIDR6') or cells[2] != 'DIRECT':
            raise BuildError('Public routes must resolve destination IP, without domain overrides')
        net = ipaddress.ip_network(cells[1], strict=True)
        if net.version != (4 if cells[0]=='IP-CIDR' else 6) or not net.is_global or net.prefixlen < (8 if net.version==4 else 16):
            raise BuildError('Invalid public IP rule')
    for host in ('us.ip111.cn', 'cn.bing.com', 'claude.ai', 'www.baidu.com', 'cdn.steamcontent.com'):
        for address, policy in [('223.5.5.5','DIRECT'), ('162.222.90.70','PROXY'), ('2400:3200::1','DIRECT'), ('2606:4700:4700::1111','PROXY')]:
            if match_rules(rules, host, address, 443) != policy:
                raise BuildError('Destination IP must determine routing independently of domain')
    return {'rules':len(rules), 'types':dict(sorted(Counter(x.split(',')[0] for x in rules).items())),
            'policy':'destination-ip', 'domain_business_overrides':0}


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
    revisions, inputs, metadata, downloads = {}, {}, {}, {}
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
        url = f'https://raw.githubusercontent.com/{repo}/{revision}/{spec["path"]}'
        if url not in downloads:
            downloads[url] = download(url, limit=config['max_bytes'])
        inputs[spec['id']] = downloads[url]
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
    return spec['id'] + '.txt'


def generate(config, template, inputs, metadata, baseline=None):
    if config.get('routing_mode') != 'destination-ip' or {s['id'] for s in config['sources']} != {'china4', 'china6'} or len(config['sources']) != 2:
        raise BuildError('Only destination-IP routing sources are permitted')
    sources, coverage, lines = {}, {}, []
    for spec in config['sources']:
        ident = spec['id']
        data = inputs[ident]
        if not data or len(data) > config['max_bytes']: raise BuildError('Empty or oversized input')
        nets, stats = parse_source(data, spec)
        merged = list(ipaddress.collapse_addresses(nets))
        coverage[ident] = sum(n.num_addresses for n in merged)
        if baseline and ident in baseline['sources']:
            for new, old in [(stats['unique'], baseline['sources'][ident]['unique']),
                             (coverage[ident], baseline['ip_coverage'][ident])]:
                if not config['min_ratio'] <= new/old <= config['max_ratio']:
                    raise BuildError('Abnormal source count or IP coverage change')
        kind = 'IP-CIDR' if ident=='china4' else 'IP-CIDR6'
        if spec['format'] != ('cidr4' if ident=='china4' else 'cidr6'):
            raise BuildError('Source family does not match source ID')
        lines += [f'{kind},{n},DIRECT' for n in merged]
        sources[ident] = {**stats, **metadata[ident], 'sha256':sha(data), 'bytes':len(data), 'license':spec['license']}
    if template.count('{{IP_RULES}}') != 1: raise BuildError('Missing/repeated IP template token')
    content = template.replace('{{IP_RULES}}', '\n'.join(lines))
    stats = validate(content)
    if stats['rules'] > config['max_output_rules'] or len(content.encode()) > config['max_output_bytes']:
        raise BuildError('Output exceeds reviewed client size budget')
    manifest = {'schema':2, 'routing_mode':'destination-ip', 'sources':sources, 'ip_coverage':coverage,
        'config_sha256':sha(content.encode()), 'generator_sha256':sha(Path(__file__).read_bytes()),
        'template_sha256':sha(template.encode()), 'sources_spec_sha256':sha(json_bytes(config)), 'output':stats}
    files = {'Shadowrocket.conf':content.encode(), 'manifest.json':json_bytes(manifest)}
    files.update({f'inputs/{snapshot_name(s)}':inputs[s['id']] for s in config['sources']})
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
    old_manifest = output / 'manifest.json'
    baseline = json.loads(old_manifest.read_text()) if old_manifest.exists() else None
    inputs, metadata = offline_inputs(output, config) if offline else fetch_inputs(config)
    files = generate(config, template, inputs, metadata, baseline)
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
                                      for k in ('generator_sha256', 'template_sha256', 'sources_spec_sha256')):
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
