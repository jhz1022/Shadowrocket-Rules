#!/usr/bin/env python3
"""Optional Mac content test: public store lookup, artwork, signed update package.

Downloads at most one package <=20 MiB, verifies it, NEVER installs or executes it.
Artifacts and results stay in .build by default. Requires curl and pkgutil.
"""
import argparse
import datetime
import gzip
import hashlib
import io
import json
from pathlib import Path
import plistlib
import struct
import subprocess
import urllib.parse
import xml.etree.ElementTree as ET
import zlib


def verify_xar(blob, catalog_digest):
    if len(blob) < 28:
        raise ValueError('Short package')
    magic, header, version, packed, plain, algorithm = struct.unpack('>IHHQQI', blob[:28])
    if magic != 0x78617221 or version != 1 or header != 28 or algorithm != 1:
        raise ValueError('Unsupported package format')
    if not 0 < plain <= 8 * 1024 * 1024 or not 0 < packed <= len(blob) - header:
        raise ValueError('Invalid package table bounds')
    table = blob[header:header + packed]
    # Apple's catalog Digest for this XAR is the compressed TOC checksum,
    # NOT the SHA-1 of the complete .pkg. Payload checksums are signed in TOC.
    if hashlib.sha1(table).hexdigest() != catalog_digest.lower():
        raise ValueError('Catalog/package TOC mismatch')
    decoder = zlib.decompressobj()
    xml = decoder.decompress(table, plain + 1)
    if len(xml) != plain or not decoder.eof:
        raise ValueError('Invalid package table')
    tree = ET.fromstring(xml)
    base, checked = header + packed, 0
    for data in tree.findall('.//file/data'):
        checksum = data.find('archived-checksum')
        offset, length = int(data.findtext('offset')), int(data.findtext('length'))
        if checksum is None or offset < 0 or length < 0 or base + offset + length > len(blob):
            raise ValueError('Invalid package payload bounds/checksum')
        algo = checksum.attrib.get('style', '').lower().replace('-', '')
        if algo not in {'sha1', 'sha256', 'sha512'}:
            raise ValueError('Unsupported payload checksum')
        chunk = blob[base + offset:base + offset + length]
        if hashlib.new(algo, chunk).hexdigest() != checksum.text.lower():
            raise ValueError('Package payload checksum mismatch')
        checked += 1
    if checked == 0:
        raise ValueError('Package contains no verifiable payload entries')
    return checked


def fetch(url, destination, allowed_hosts, limit):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https' or parsed.hostname not in allowed_hosts or parsed.username or parsed.password:
        raise ValueError('Unexpected content endpoint')
    reply = subprocess.run(['curl', '--proxy', '', '--noproxy', '*', '--proto', '=https',
        '--proto-redir', '=https', '--fail', '--silent', '--show-error', '--location',
        '--max-time', '30', '--max-filesize', str(limit), '--output', str(destination),
        '--write-out', '%{json}', url], capture_output=True, text=True, timeout=35)
    if reply.returncode:
        raise ValueError('Content download failed: ' + parsed.hostname)
    metrics = json.loads(reply.stdout)
    if metrics['http_code'] != 200 or metrics['ssl_verify_result'] != 0:
        raise ValueError('Content HTTP/TLS verification failed')
    blob = destination.read_bytes()
    if not blob or len(blob) > limit:
        raise ValueError('Invalid content length')
    return blob, {'host': parsed.hostname, 'http_code': metrics['http_code'], 'bytes': len(blob),
                  'seconds': metrics['time_total'], 'tls_verify_result': metrics['ssl_verify_result']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path('.build/apple-content'))
    args = parser.parse_args()
    out = args.directory
    out.mkdir(parents=True, exist_ok=True)
    try:
        lookup, store = fetch('https://itunes.apple.com/lookup?id=836500024&country=cn',
            out / 'lookup.json', {'itunes.apple.com'}, 4 * 1024 * 1024)
        result = json.loads(lookup)
        if result['resultCount'] != 1:
            raise ValueError('Store lookup did not return the requested app')
        artwork, image = fetch(result['results'][0]['artworkUrl512'], out / 'artwork.png',
            {f'is{i}-ssl.mzstatic.com' for i in range(1, 6)}, 2 * 1024 * 1024)
        if not artwork.startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValueError('Artwork is not the expected PNG object')
        catalog, metadata = fetch('https://swscan.apple.com/content/catalogs/others/index-rosettaupdateauto-1.sucatalog.gz',
            out / 'catalog.gz', {'swscan.apple.com'}, 4 * 1024 * 1024)
        if catalog[:2] == b'\x1f\x8b':
            catalog = gzip.GzipFile(fileobj=io.BytesIO(catalog)).read(8 * 1024 * 1024 + 1)
        if len(catalog) > 8 * 1024 * 1024:
            raise ValueError('Oversized catalog')
        products = sorted(plistlib.loads(catalog)['Products'].values(),
                          key=lambda p: p.get('PostDate', datetime.datetime.min), reverse=True)
        package = next(q for p in products for q in p.get('Packages', [])
                       if 0 < q.get('Size', 0) <= 20 * 1024 * 1024
                       and q['URL'].startswith('https://swcdn.apple.com/'))
        path = out / 'RosettaUpdateAuto.pkg'
        blob, content = fetch(package['URL'], path, {'swcdn.apple.com'}, 20 * 1024 * 1024)
        if len(blob) != package['Size']:
            raise ValueError('Package size differs from catalog')
        checked = verify_xar(blob, package['Digest'])
        signature = subprocess.run(['pkgutil', '--check-signature', str(path)],
                                   capture_output=True, text=True, timeout=30)
        if signature.returncode or 'signed Apple Software' not in signature.stdout:
            raise ValueError('Apple package signature verification failed')
        report = {'store': store, 'artwork': image, 'catalog': metadata, 'package': content,
                  'catalog_toc_digest_matches': True, 'archived_entries_verified': checked,
                  'apple_signature_verified': True, 'executed_or_installed': False,
                  'scope': 'One real store/artwork/update object chain; not every product or installation.'}
        (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        return 0
    except (ValueError, KeyError, OSError, StopIteration, subprocess.TimeoutExpired, zlib.error) as exc:
        print('CONTENT_TEST_FAILED:', exc)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
