#!/usr/bin/env python3
"""Read-only precondition for live probes; not proof of VPN or egress behavior."""
import argparse
import hashlib
import ipaddress
import plistlib
from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
DATABASE = Path.home() / 'Library/Containers/com.liguangming.Shadowrocket/Data/Documents/Databases/Shadowrocket.db'
PREFERENCES = Path.home() / 'Library/Group Containers/group.com.liguangming.Shadowrocket/Library/Preferences/group.com.liguangming.Shadowrocket.plist'


class ClientConfigMismatch(ValueError):
    pass


def normalize_rule(cells):
    kind = cells[0].upper()
    if kind == 'FINAL':
        return ('FINAL', cells[1])
    value = cells[1]
    if kind in ('IP-CIDR', 'IP-CIDR6'):
        value = str(ipaddress.ip_network(value))
    elif kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
        value = value.lower().rstrip('.')
    return tuple([kind, value] + cells[2:])


def selected_database(preferences=PREFERENCES):
    try:
        name = plistlib.loads(Path(preferences).read_bytes())['group.com.liguangming.CurrentRuleFileName']
        if not isinstance(name, str) or Path(name).name != name or not name.endswith('.db'):
            raise ValueError('Invalid selected profile name')
        return DATABASE.parent / name
    except (OSError, ValueError, KeyError, plistlib.InvalidFileException) as exc:
        raise ClientConfigMismatch('Cannot identify the selected native profile; refusing to guess from a fixed filename.') from exc


def require_active_config(conf, database=None):
    database = selected_database() if database is None else database
    rules, general, section = [], {}, None
    for raw in conf.splitlines():
        line = raw.strip()
        if line.startswith('['):
            section = line
        elif line and not line.startswith('#'):
            if section == '[Rule]':
                rules.append(normalize_rule([v.strip() for v in line.split(',')]))
            elif section == '[General]':
                key, value = line.split('=', 1)
                general[key.strip().lower()] = ''.join(value.split())
    try:
        with sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True) as conn:
            actual = []
            for kind, value, policy, extra in conn.execute(
                    "select name,value,option,ext from config where lower(section)='rule' "
                    "and name!='COMMENT' order by docid"):
                cells = ['FINAL', policy] if kind == 'FINAL' else [kind, value, policy]
                if extra:
                    cells.append(extra)
                actual.append(normalize_rule(cells))
            settings = {k.lower(): ''.join((v or '').split()) for k, v in conn.execute(
                "select name,value from config where lower(section)='general'")}
    except (sqlite3.Error, OSError) as exc:
        raise ClientConfigMismatch('Cannot read the native client configuration; no live acceptance result.') from exc
    if actual != rules:
        raise ClientConfigMismatch('Native client rules differ from the candidate; refusing to label old-client traffic as candidate validation.')
    if any(settings.get(k) != v for k, v in general.items()):
        raise ClientConfigMismatch('Native General settings differ from the candidate; DNS/TUN probes must not be attributed to it.')
    return {'candidate_sha256': hashlib.sha256(conf.encode()).hexdigest(),
            'native_rules_and_general_match': True,
            'scope': 'Read-only database comparison; VPN state and actual routing still require logs.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'dist/Shadowrocket.conf')
    args = parser.parse_args()
    try:
        print(require_active_config(args.config.read_text()))
    except (ClientConfigMismatch, OSError, ValueError) as exc:
        print('CLIENT_NOT_VERIFIED:', exc)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
