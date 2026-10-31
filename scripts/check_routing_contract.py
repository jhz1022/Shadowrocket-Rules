#!/usr/bin/env python3
"""Check candidate routing/DNS-trigger contracts without changing any client.

This is an independent text-rule interpreter with injected DNS answers, NOT a
Shadowrocket emulator. It cannot certify native DNS, TUN, egress or app usability.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Policy:
    def __init__(self, text):
        self.rows = []
        self.exact, self.suffix = {}, {}
        active = False
        for raw in text.splitlines():
            line = raw.strip()
            if line.startswith('['):
                active = line == '[Rule]'
            if not active or not line or line.startswith(('#', '[')):
                continue
            cells = line.split(',')
            index = len(self.rows)
            self.rows.append(cells)
            if cells[0] in ('DOMAIN', 'DOMAIN-SUFFIX'):
                target = self.exact if cells[0] == 'DOMAIN' else self.suffix
                target.setdefault(cells[1], (index, cells))
        self.ip_rules = [(i, r, ipaddress.ip_network(r[1]))
                         for i, r in enumerate(self.rows) if r[0] in ('IP-CIDR', 'IP-CIDR6')]
        self.port_rules = [(i, r) for i, r in enumerate(self.rows) if r[0] == 'DST-PORT']
        self.final = next((i, r) for i, r in enumerate(self.rows) if r[0] == 'FINAL')

    def decide(self, host, resolver, address=None, port=443):
        host = host.lower().rstrip('.')
        matches = [self.exact[host]] if host in self.exact else []
        labels = host.split('.')
        matches += [self.suffix[h] for n in range(len(labels))
                    if (h := '.'.join(labels[n:])) in self.suffix]
        matches += [(i, r) for i, r in self.port_rules if int(r[1]) == port]
        limit, winner = min(matches, default=self.final)
        answers = [ipaddress.ip_address(address)] if address else []
        queried = False
        for index, rule, network in self.ip_rules:
            if index >= limit:
                break
            if not answers and not queried and host and 'no-resolve' not in rule:
                queried = True
                # Empty answers and failures have the same policy-level contract:
                # never make an unresolved public name DIRECT.
                try:
                    answers = [ipaddress.ip_address(a) for a in resolver(host)]
                except OSError:
                    answers = []
            if any(a.version == network.version and a in network for a in answers):
                winner = rule
                break
        return {'policy': winner[1] if winner[0] == 'FINAL' else winner[2],
                'rule': ','.join(winner), 'routing_dns_requested': queried}


def check(text, cases):
    policy = Policy(text)
    results = []
    for case in cases:
        answers = case.get('answers', [])
        def resolver(host):
            if case.get('dns_error'):
                raise OSError('injected DNS failure')
            return answers
        result = policy.decide(case['host'], resolver, case.get('address'), case.get('port', 443))
        passed = (result['policy'] == case['policy'] and
                  result['routing_dns_requested'] == case['routing_dns_requested'])
        results.append({'id': case['id'], 'host': case['host'], 'passed': passed, **result})
    return {'config_sha256': hashlib.sha256(text.encode()).hexdigest(),
            'cases': len(results), 'failures': sum(not r['passed'] for r in results),
            'native_client_validation': 'NOT_RUN', 'results': results,
            'scope': __doc__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=ROOT / 'dist/Shadowrocket.conf')
    parser.add_argument('--cases', type=Path, default=ROOT / 'tests/routing_cases.json')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = check(args.config.read_text(), json.loads(args.cases.read_text()))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k not in ('results', 'scope')}, indent=2))
    for row in result['results']:
        if not row['passed']:
            print('FAIL', row)
    return int(bool(result['failures']))


if __name__ == '__main__':
    raise SystemExit(main())
