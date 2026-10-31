"""Independent source decoder for audit.py; never calls the build decoder.

This checks conversion agreement, not the truth of upstream classifications.
The explicit-source subset is deliberately small; unknown syntax fails.
"""
import hashlib
import io
import ipaddress
import json
import re
import tarfile


def hostname(text):
    value = text.rstrip('.').encode('idna').decode('ascii').lower()
    if not value or len(value) > 253 or any(
            not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', label)
            for label in value.split('.')):
        raise ValueError('Audit: invalid hostname')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('Audit: hostname is an IP')


def community(data, entry, attribute=None):
    records, edges = {}, {}
    size = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for item in archive:
            size += item.size
            if size > 16 * 1024 * 1024 or item.size > 2 * 1024 * 1024:
                raise ValueError('Audit: excessive archive size')
            parts = item.name.split('/')
            if len(parts) != 3 or parts[1] != 'data':
                continue
            name = parts[2]
            if not re.fullmatch('[a-z0-9_!-]+', name) or not item.isfile() or name in edges:
                raise ValueError('Audit: invalid or repeated list')
            records.setdefault(name, set())
            edges[name] = []
            for raw in archive.extractfile(item).read().decode('utf-8-sig').splitlines():
                words = raw.partition('#')[0].split()
                if not words:
                    continue
                head, tags = words[0], words[1:]
                if any(not re.fullmatch('[@&][A-Za-z0-9_!-]+', tag) for tag in tags):
                    raise ValueError('Audit: unsupported annotation')
                attrs = frozenset(tag[1:] for tag in tags if tag[0] == '@')
                targets = [tag[1:] for tag in tags if tag[0] == '&']
                kind, sep, value = head.partition(':')
                if not sep:
                    kind, value = 'domain', kind
                if kind == 'include':
                    if targets or not re.fullmatch('[a-z0-9_!-]+', value):
                        raise ValueError('Audit: invalid include')
                    edges[name].append((value, attrs))
                elif kind in {'domain', 'full', 'regexp', 'keyword'} and value:
                    row = (kind, value, attrs)
                    for destination in [name] + targets:
                        records.setdefault(destination, set()).add(row)
                else:
                    raise ValueError('Audit: unsupported source record')

    # Iterate to a fixed point; detect cycles independently with a DFS first.
    visited, active = set(), set()
    def visit(name):
        if name not in records or name in active or len(active) > 64:
            raise ValueError('Audit: missing, cyclic or deep include')
        if name in visited:
            return
        active.add(name)
        for target, _ in edges.get(name, []):
            visit(target)
        active.remove(name)
        visited.add(name)
    visit(entry)
    resolved = {name: set(records[name]) for name in visited}
    while True:
        changed = False
        for name in visited:
            for target, filters in edges.get(name, []):
                addition = {row for row in resolved[target] if all(
                    (tag[1:] not in row[2]) if tag.startswith('-') else tag in row[2]
                    for tag in filters)}
                before = len(resolved[name])
                resolved[name].update(addition)
                changed |= before != len(resolved[name])
        if not changed:
            break
    result = set()
    for kind, value, attrs in resolved[entry]:
        if {'ads', '!cn'} & attrs or (attribute and attribute not in attrs) or kind == 'regexp':
            continue
        if kind == 'keyword':
            raise ValueError('Audit: unsupported direct keyword')
        result.add(('DOMAIN' if kind == 'full' else 'DOMAIN-SUFFIX', hostname(value)))
    return result


def read_sources(root, specs):
    manifest = json.loads((root / 'dist/manifest.json').read_text())
    result = {}
    for spec in specs['sources']:
        ident, fmt = spec['id'], spec['format']
        data = (root / 'dist/inputs' / (ident + ('.tar.gz' if fmt == 'v2fly-archive' else '.txt'))).read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest['sources'][ident]['sha256']:
            raise ValueError('Audit: source snapshot checksum mismatch')
        if fmt == 'v2fly-archive':
            result[ident] = community(data, spec['path'].split('/')[-1])
        elif fmt == 'clash-domain':
            lines = data.decode('utf-8-sig').splitlines()
            if not lines or lines[0] != 'payload:':
                raise ValueError('Audit: missing payload header')
            rows = set()
            for line in lines[1:]:
                if not line.strip() or line.lstrip().startswith('#'):
                    continue
                match = re.fullmatch("  - '([^']+)'", line)
                if not match:
                    raise ValueError('Audit: invalid Clash record')
                name = match[1]
                rows.add(('DOMAIN-SUFFIX', hostname(name[2:])) if name.startswith('+.')
                         else ('DOMAIN', hostname(name)))
            result[ident] = rows
        elif fmt in {'cidr4', 'cidr6'}:
            nets = {ipaddress.ip_network(x, strict=True) for x in data.decode().splitlines()
                    if x.strip() and not x.startswith('#')}
            if any(n.version != int(fmt[-1]) for n in nets):
                raise ValueError('Audit: wrong IP family')
            result[ident] = nets
        else:
            raise ValueError('Audit: unknown source format')
    return result
