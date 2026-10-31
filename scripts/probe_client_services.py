#!/usr/bin/env python3
"""Optional Mac live probes. Requires active Shadowrocket; never changes the clock.

HTTP exchanges to CDN root paths are protocol checks, not full download/login
certification. Verify policy in native connection logs; this script's policy
column comes from the published text model. Results stay local unless shared.
"""
import argparse
import concurrent.futures
import datetime as dt
import json
from pathlib import Path
import socket
import struct
import subprocess
import time

import build
from verify_client_config import require_active_config, ClientConfigMismatch

HTTP = ['http://captive.apple.com/hotspot-detect.html', 'https://apps.apple.com/cn/',
        'http://swcdn.apple.com/', 'https://www.hsbc.com.cn/',
        'https://www.hsbcinsurance.com.cn/', 'https://www.hsbcqh.com.cn/',
        'https://account-cn.alibabacloud.com/', 'http://download.windowsupdate.com/',
        'http://dl.delivery.mp.microsoft.com/', 'http://officecdn.microsoft.com/',
        'https://www.baidu.com/', 'https://www.google.com/generate_204', 'https://github.com/']
NTP = ['cn.pool.ntp.org'] + [f'{i}.cn.pool.ntp.org' for i in range(4)] + ['time.apple.com']


def ntp_probe(host):
    row = {'host': host, 'protocol': 'UDP/123', 'clock_modified': False}
    try:
        peer = socket.getaddrinfo(host, 123, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
        request = bytearray(48)
        request[0] = 0x23  # NTPv4 client mode
        request[40:48] = struct.pack('!Q', int((time.time() + 2208988800) * (2 ** 32)))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.connect(peer)
            start = time.monotonic()
            sock.send(request)
            response = sock.recv(1024)
        valid = (len(response) >= 48 and response[0] & 7 == 4
                 and (response[0] >> 3) & 7 in (3, 4) and response[0] >> 6 != 3
                 and 1 <= response[1] <= 15 and response[24:32] == request[40:48]
                 and any(response[40:48]))
        row.update(valid_ntp_response=valid, rtt_ms=round((time.monotonic() - start) * 1000, 2),
                   stratum=response[1] if len(response) >= 2 else None)
    except (OSError, OverflowError) as exc:
        row.update(valid_ntp_response=False, error=str(exc))
    return row


def http_probe(url):
    command = ['curl', '--proxy', '', '--noproxy', '*', '--silent', '--show-error',
               '--location', '--max-redirs', '4', '--connect-timeout', '5', '--max-time', '15',
               '--max-filesize', '2097152', '--output', '/dev/null', '--write-out', '%{json}', url]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    try:
        m = json.loads(result.stdout)
    except ValueError:
        m = {}
    return {'url': url, 'curl_exit': result.returncode, 'error': result.stderr,
            **{k: m.get(k) for k in ['http_code', 'ssl_verify_result', 'time_appconnect',
                                    'time_starttransfer', 'time_total']}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    conf = (build.ROOT / 'dist/Shadowrocket.conf').read_text()
    try:
        identity = require_active_config(conf)
    except ClientConfigMismatch as exc:
        print('CLIENT_NOT_VERIFIED:', exc)
        return 2
    rules = build.rule_lines(conf)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            ntp = list(executor.map(ntp_probe, NTP))
            http = list(executor.map(http_probe, HTTP))
    except (OSError, subprocess.TimeoutExpired) as exc:
        print('Client probe could not complete:', exc)
        return 2
    for row in ntp:
        row['expected_policy'] = build.match_rules(rules, row['host'], port=123)
        print('NTP', row['host'], row['expected_policy'], row['valid_ntp_response'], row.get('rtt_ms'))
    for row in http:
        host = row['url'].split('/')[2]
        row['expected_policy'] = build.match_rules(rules, host, port=80 if row['url'].startswith('http:') else 443)
        print('HTTP', host, row['expected_policy'], row['http_code'], row['curl_exit'], row['time_total'])
    report = {'timestamp': dt.datetime.now(dt.timezone.utc).isoformat(),
              'config_sha256': build.sha(conf.encode()), 'client_identity': identity, 'ntp': ntp, 'http': http,
              'scope': __doc__}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    return 0 if all(x['valid_ntp_response'] for x in ntp) and all(x['curl_exit'] == 0 for x in http) else 1


if __name__ == '__main__':
    raise SystemExit(main())
