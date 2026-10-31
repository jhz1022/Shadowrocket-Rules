#!/usr/bin/env python3
"""Optional live test: requires dig and an active Shadowrocket configuration.

Run on the client Mac, never as an unattended GitHub Actions test. This verifies
Fake-IP responses and fail-closed outcomes; correlate denials with native logs
to distinguish a rule rejection from an unreachable resolver.
"""
import argparse
import concurrent.futures
import ipaddress
import json
import re
from pathlib import Path
import subprocess
import time
import uuid


def resolution_probe(expect='success', query=None):
    """TXT avoids synthetic A answers. Use a nonce for negative/outage probes.

    Positive probes must follow a profile reload and be correlated with a new
    native DNS log entry, otherwise a cache hit cannot prove failover.
    """
    query = query or ('example.com' if expect == 'success' else 'sr-' + uuid.uuid4().hex + '.com')
    if len(query) > 253 or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]*\.[A-Za-z0-9-]+', query):
        raise ValueError('Invalid public DNS control name')
    start = time.monotonic()
    result = subprocess.run(['dig', '@8.8.8.8', query, 'TXT', '+time=8', '+tries=1',
                             '+bufsize=4096', '+noall', '+comments', '+answer', '+authority'],
                            capture_output=True, text=True, timeout=11)
    response = '->>HEADER<<-' in result.stdout
    negative = response and 'status: NXDOMAIN' in result.stdout and '\tSOA\t' in result.stdout
    positive = response and 'status: NOERROR' in result.stdout and '\tTXT\t' in result.stdout
    passed = (positive if expect == 'success' else negative if expect == 'negative'
              else not response and result.returncode != 0)
    return {'query': query, 'type': 'TXT', 'expected': expect, 'passed': passed,
            'elapsed_seconds': round(time.monotonic() - start, 3),
            'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
            'scope': 'Correlate the queried name in native DNS logs; a reply alone does not identify the egress.'}

CASES = [('udp', x, 'fake-ip') for x in
         ['8.8.8.8', '223.5.5.5', '119.29.29.29', '9.9.9.9', '114.114.114.114']]
CASES += [('tcp', x, 'no-answer') for x in ['8.8.8.8', '223.5.5.5', '119.29.29.29']]
CASES += [('udp', x, 'no-answer') for x in ['2606:4700:4700::1111', '2001:4860:4860::8888']]


def probe(case):
    transport, resolver, expected = case
    command = ['dig', '@' + resolver, 'www.google.com', 'A',
               '+time=2', '+tries=1', '+noall', '+answer', '+comments']
    if transport == 'tcp':
        command.append('+tcp')
    result = subprocess.run(command, capture_output=True, text=True, timeout=8)
    answers = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[-2] == 'A':
            answers.append(fields[-1])
    if expected == 'fake-ip':
        passed = bool(answers) and all(ipaddress.ip_address(a) in ipaddress.ip_network('198.18.0.0/15')
                                      for a in answers)
    else:
        # A genuine upstream DNS response (even NXDOMAIN/SERVFAIL) is a failure
        # for this known-existing name: only refusal/timeout/close is expected.
        passed = not answers and '->>HEADER<<-' not in result.stdout
    return {'transport': transport, 'resolver': resolver, 'expected': expected,
            'answers': answers, 'exit_code': result.returncode, 'passed': passed,
            'stdout': result.stdout, 'stderr': result.stderr}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='Optional local JSON report; do not publish personal logs')
    parser.add_argument('--resolution', choices=['success', 'negative', 'no-answer'],
                        help='Only probe fresh TXT resolution, including controlled DNS outage tests')
    parser.add_argument('--query', help='Public TXT name for a positive control; default example.com')
    args = parser.parse_args()
    if args.resolution:
        result = resolution_probe(args.resolution, args.query)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result, indent=2))
        return 0 if result['passed'] else 1
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            rows = list(executor.map(probe, CASES))
    except (OSError, subprocess.TimeoutExpired) as exc:
        print('Probe could not complete:', exc)
        return 2
    for row in rows:
        print('PASS' if row['passed'] else 'FAIL', row['transport'], row['resolver'],
              row['expected'], ','.join(row['answers']) or 'no answer')
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(rows, indent=2) + '\n')
    print('Denial alone is not proof of a rule: verify DST-PORT,53,REJECT in native connection logs.')
    return 0 if all(row['passed'] for row in rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
