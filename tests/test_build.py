import copy
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build as b
import audit_sources


def spec(fmt='clash-domain', policy='DIRECT'):
    return {'id': 'test', 'format': fmt, 'policy': policy, 'min_records': 1, 'max_records': 20}


class ConversionTests(unittest.TestCase):
    def test_exact_and_suffix_have_distinct_semantics(self):
        rules, stats = b.parse_source(b"payload:\n  - 'Only.Example.com'\n  - '+.example.net'\n", spec())
        self.assertIn(b.Rule('DOMAIN', 'only.example.com', 'DIRECT'), rules)
        self.assertIn(b.Rule('DOMAIN-SUFFIX', 'example.net', 'DIRECT'), rules)
        lines = [r.line() for r in sorted(rules)] + ['FINAL,PROXY']
        self.assertEqual(b.match_rules(lines, 'child.only.example.com'), 'PROXY')
        self.assertEqual(b.match_rules(lines, 'child.example.net'), 'DIRECT')
        self.assertEqual(b.match_rules(lines, 'fakeexample.net'), 'PROXY')

    def test_unknown_formats_and_injection_fail(self):
        for value in ['regexp:.*', 'full:example.com', 'keyword:google', '*.example.com',
                      'example.com,PROXY', 'https://example.com', '1.2.3.4', '[General]']:
            with self.subTest(value=value), self.assertRaises(b.BuildError):
                b.parse_source(f"payload:\n  - '{value}'\n".encode(), spec())
        for data in [b'', b'<html>error</html>', b'payload:\n  - [x]\n', b'\xff']:
            with self.subTest(data=data), self.assertRaises(b.BuildError):
                b.parse_source(data, spec())

    def test_bom_crlf_idna_and_case(self):
        rules, _ = b.parse_source("\ufeffpayload:\r\n  - '+.百度.com.'\r\n".encode(), spec())
        self.assertEqual(next(iter(rules)).value, 'xn--wxtr44c.com')

    def test_duplicates_counted_and_excess_rejected(self):
        data = "payload:\n" + ''.join(f"  - '+.x{i}.com'\n" for i in range(20)) + "  - '+.x0.com'\n"
        _, stats = b.parse_source(data.encode(), spec())
        self.assertEqual(stats['duplicates'], 1)
        with self.assertRaises(b.BuildError):
            b.parse_source(b"payload:\n  - 'a.com'\n  - 'a.com'\n", spec())

    def test_cidr_family_canonicality_public_space(self):
        for fmt, text, kind in [('cidr4', '223.5.5.0/24', 'IP-CIDR'),
                                 ('cidr6', '2400:3200::/32', 'IP-CIDR6')]:
            rules, _ = b.parse_source((text + '\n').encode(), spec(fmt))
            self.assertEqual(next(iter(rules)).line(), f'{kind},{text},DIRECT,no-resolve')
        for text in ['0.0.0.0/0', '1.0.0.0/7', '192.168.0.0/16', '223.5.5.1/24',
                     '2400:3200::/32', '223.5.5.5']:
            with self.subTest(text=text), self.assertRaises(b.BuildError):
                b.parse_source((text + '\n').encode(), spec('cidr4'))

    def test_suffix_minimization(self):
        rules = {b.Rule(k, d, 'DIRECT') for k, d in [('DOMAIN-SUFFIX', 'cn'),
                 ('DOMAIN-SUFFIX', 'example.cn'), ('DOMAIN', 'www.example.cn'),
                 ('DOMAIN', 'only.example.com')]}
        self.assertEqual(len(b.minimize(rules)), 2)

    def test_registry_suffixes_do_not_make_unknown_domains_direct(self):
        config = {'direct_excluded_suffixes': ['cn', 'com.cn', 'net.cn', 'org.cn']}
        rows = {b.Rule('DOMAIN-SUFFIX', name, 'DIRECT') for name in
                ['cn', 'com.cn', 'xn--fiqs8s', 'baidu', 'baidu.com', 'qlogo.cn']}
        kept = b.precise_direct(rows, config)
        self.assertEqual({x.value for x in kept}, {'baidu.com', 'qlogo.cn'})

    def test_icann_boundaries_wildcards_exceptions_and_private_hosts(self):
        data = ('// ===BEGIN ICANN DOMAINS===\ncn\nbj.cn\nin.th\nco.uk\n'
                '*.ck\n!www.ck\n*.kawasaki.jp\n!city.kawasaki.jp\n'
                '中国 // IDN comment\n// ===END ICANN DOMAINS===\n'
                '// ===BEGIN PRIVATE DOMAINS===\nsinaapp.com\n'
                '// ===END PRIVATE DOMAINS===\n').encode()
        registry = b.parse_public_suffixes(data)
        self.assertEqual(registry, audit_sources.public_suffixes(data))
        for name in ['bj.cn', 'in.th', 'co.uk', 'a.ck', 'kawasaki.jp', 'a.kawasaki.jp',
                     'xn--fiqs8s', 'unknown-tld']:
            with self.subTest(name=name):
                self.assertTrue(b.registry_suffix(name, registry))
                self.assertTrue(audit_sources.registry_suffix(name, registry))
        for name in ['company.in.th', 'www.ck', 'a.www.ck', 'sub.a.ck', 'sinaapp.com',
                     'city.kawasaki.jp', 'sub.city.kawasaki.jp']:
            with self.subTest(name=name):
                self.assertFalse(b.registry_suffix(name, registry))
                self.assertFalse(audit_sources.registry_suffix(name, registry))
        config = {'direct_excluded_suffixes': ['cn', 'com.cn', 'net.cn', 'org.cn']}
        rows = {b.Rule('DOMAIN-SUFFIX', name, 'DIRECT') for name in ['in.th', 'company.in.th']}
        self.assertEqual(b.precise_direct(rows, config, registry),
                         {b.Rule('DOMAIN-SUFFIX', 'company.in.th', 'DIRECT')})

    def test_malformed_public_suffix_lists_fail_closed(self):
        begin, end = '// ===BEGIN ICANN DOMAINS===\n', '// ===END ICANN DOMAINS===\n'
        for text in ['', begin + 'com\n', end + 'com\n' + begin,
                     begin + begin + 'com\n' + end, begin + end,
                     begin + 'com\ncom\n' + end, begin + '*.*.ck\n' + end,
                     begin + '!www.ck\n' + end, begin + 'co.uk,DIRECT\n' + end]:
            with self.subTest(text=text), self.assertRaises(b.BuildError):
                b.parse_public_suffixes(text.encode())

    def test_typed_direct_domains_attributes_and_regex_omission(self):
        data = ''.join(f'domain:x{i}.com\n' for i in range(110))
        data += 'full:exact.example.net:@cn,@telemetry\nregexp:^regional[0-9]+\\.example.net$:@cn\n'
        source = dict(spec('v2ray-direct'), max_records=200)
        rules, stats = b.parse_source(data.encode(), source)
        self.assertIn(b.Rule('DOMAIN', 'exact.example.net', 'DIRECT'), rules)
        self.assertEqual(len(stats['omitted_direct_regex']), 1)
        self.assertEqual(stats['duplicates'], 0)
        with self.assertRaises(b.BuildError):
            b.parse_source(data.encode(), dict(source, policy='PROXY'))
        for value in ['keyword:google', 'include:cn', 'domain:a.com:@', 'domain:a.com:@x bad']:
            with self.subTest(value=value), self.assertRaises(b.BuildError):
                b.parse_source(value.encode(), source)

    def test_conflict_priority_in_both_directions(self):
        p = {b.Rule('DOMAIN-SUFFIX', 'proxy.com', 'PROXY'),
             b.Rule('DOMAIN', 'exact.direct.com', 'PROXY'),
             b.Rule('DOMAIN-SUFFIX', 'child.direct.com', 'PROXY')}
        d = {b.Rule('DOMAIN-SUFFIX', 'child.proxy.com', 'DIRECT'),
             b.Rule('DOMAIN-SUFFIX', 'direct.com', 'DIRECT')}
        kept, conflicts = b.resolve_conflicts(p, d)
        self.assertEqual(kept, {b.Rule('DOMAIN-SUFFIX', 'direct.com', 'DIRECT')})
        self.assertEqual(len(conflicts), 3)
        lines = [r.line() for r in sorted(p)] + [r.line() for r in sorted(kept)] + ['FINAL,PROXY']
        for name in ['x.child.proxy.com', 'exact.direct.com', 'x.child.direct.com']:
            self.assertEqual(b.match_rules(lines, name), 'PROXY')
        self.assertEqual(b.match_rules(lines, 'x.exact.direct.com'), 'DIRECT')


class DownloadTests(unittest.TestCase):
    def test_errors_retry_and_fail(self):
        for error in [urllib.error.URLError('timeout'),
                      urllib.error.HTTPError('https://example.com', 404, 'missing', None, None)]:
            with patch.object(b.urllib.request, 'urlopen', side_effect=error) as request, \
                    patch.object(b.time, 'sleep'), self.assertRaises(b.BuildError):
                b.download('https://example.com')
            self.assertEqual(request.call_count, 3)

    def test_empty_and_oversized_downloads(self):
        for data in [b'', b'12345']:
            response = io.BytesIO(data)
            response.geturl = lambda: 'https://example.com'
            with patch.object(b.urllib.request, 'urlopen', return_value=response), self.assertRaises(b.BuildError):
                b.download('https://example.com', limit=4)

    def test_https_required(self):
        with self.assertRaises(b.BuildError):
            b.download('http://example.com')

    def test_repository_revision_is_resolved_once(self):
        config = {'max_bytes': 1000, 'sources': [
            {'id': 'a', 'repository': 'owner/repo', 'ref': 'release', 'path': 'a.txt'},
            {'id': 'b', 'repository': 'owner/repo', 'ref': 'release', 'path': 'b.txt'}]}
        revision = 'a' * 40
        result = [json.dumps({'object': {'type': 'commit', 'sha': revision}}).encode(), b'a', b'b']
        with patch.object(b, 'download', side_effect=result) as request:
            inputs, metadata = b.fetch_inputs(config)
        self.assertEqual(request.call_count, 3)
        self.assertEqual(inputs, {'a': b'a', 'b': b'b'})
        self.assertEqual(metadata['a']['revision'], metadata['b']['revision'])
        self.assertIn('/' + revision + '/b.txt', metadata['b']['url'])


class ArchiveTests(unittest.TestCase):
    def archive(self, entries):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            entries = {**{f'unused-{i}': '# empty' for i in range(1000)}, **entries}
            for name, content in entries.items():
                data = content.encode()
                member = tarfile.TarInfo('repo/data/' + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return buffer.getvalue()

    def test_affiliation_include_filters_and_exclusions(self):
        data = self.archive({'cn': 'include:geolocation-cn\ninclude:cdn @cn @-ads',
                             'geolocation-cn': 'local.example\n',
                             'company': 'taobao.example &geolocation-cn\nforeign.example @!cn &geolocation-cn\nad.example @ads &geolocation-cn',
                             'cdn': 'full:exact.example @cn\nother.example\nad.cdn @cn @ads'})
        flat = b.parse_community_archive(data, 'cn').decode().splitlines()
        self.assertEqual(flat, ['domain:local.example', 'domain:taobao.example', 'full:exact.example'])

    def test_affiliated_target_without_file(self):
        data = self.archive({'cn': 'include:synthetic', 'brand': 'brand.example &synthetic'})
        self.assertEqual(b.parse_community_archive(data, 'cn'), b'domain:brand.example\n')

    def test_case_insensitive_attributes_includes_and_affiliations(self):
        data = self.archive({'cn': 'INCLUDE:VENDOR @-ADS\ninclude:SYNTHETIC',
            'vendor': 'foreign.example @!CN\nad.example @ADS\nFULL:legit.example @CN',
            'extra': 'affiliated.example &SYNTHETIC\nforeign2.example @!Cn &SYNTHETIC'})
        self.assertEqual(b.parse_community_archive(data, 'CN').decode().splitlines(),
                         ['domain:affiliated.example', 'full:legit.example'])
        self.assertEqual(audit_sources.community(data, 'CN'),
                         {('DOMAIN-SUFFIX', 'affiliated.example'), ('DOMAIN', 'legit.example')})
        self.assertEqual(b.parse_community_archive(data, 'VENDOR', 'CN'), b'full:legit.example\n')
        self.assertEqual(audit_sources.community(data, 'VENDOR', 'CN'), {('DOMAIN', 'legit.example')})

    def test_explicit_attribute_selection_does_not_include_global_services(self):
        data = self.archive({'cn': 'local.example', 'microsoft':
                             'full:download.example @cn\nglobal.example\nforeign.example @cn @!cn'})
        self.assertEqual(b.parse_community_archive(data, 'microsoft', 'cn'),
                         b'full:download.example\n')

    def test_missing_cyclic_and_unknown_syntax_fail(self):
        for entries in [{'cn': 'include:missing'}, {'cn': 'include:cycle', 'cycle': 'include:cn'},
                        {'cn': 'surprise:bad.example'}, {'cn': 'good.example @bad=value'}]:
            with self.subTest(entries=entries), self.assertRaises(b.BuildError):
                b.parse_community_archive(self.archive(entries), 'cn')

    def test_bad_archive_fails(self):
        with self.assertRaises(b.BuildError):
            b.parse_community_archive(b'not gzip', 'cn')


class PublishedSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = json.loads((ROOT / 'sources/sources.json').read_text())
        cls.template = (ROOT / 'config/template.conf').read_text()
        cls.overrides = json.loads((ROOT / 'config/overrides.json').read_text())
        cls.inputs, cls.metadata = b.offline_inputs(ROOT / 'dist', cls.config)
        cls.manifest = json.loads((ROOT / 'dist/manifest.json').read_text())
        cls.conf = (ROOT / 'dist/Shadowrocket.conf').read_text()

    def generate(self, **kwargs):
        args = dict(config=self.config, template=self.template, overrides=self.overrides,
                    inputs=self.inputs, metadata=self.metadata, baseline=self.manifest)
        args.update(kwargs)
        return b.generate(**args)

    def test_real_snapshot_is_deterministic(self):
        first, second = self.generate(), self.generate()
        self.assertEqual(first, second)
        self.assertEqual(first['Shadowrocket.conf'], self.conf.encode())

    def test_actual_rules_and_dns_baseline(self):
        stats = b.validate(self.conf)
        self.assertGreater(stats['rules'], 10000)
        self.assertGreater(stats['types']['IP-CIDR6'], 1000)
        self.assertNotIn('GEOIP,', self.conf)
        self.assertNotIn('RULE-SET,', self.conf)
        self.assertNotIn('[Proxy Group]', self.conf)
        self.assertEqual([line for line in b.rule_lines(self.conf) if ',REJECT' in line],
                         ['DST-PORT,53,REJECT'])

    def test_broad_registry_bypass_cannot_return(self):
        for suffix in ['com.cn', 'in.th', 'co.uk', 'xn--55qx5d']:
            with self.subTest(suffix=suffix), self.assertRaises(b.BuildError):
                b.validate(self.conf.replace('# BEGIN DIRECT\n',
                    '# BEGIN DIRECT\nDOMAIN-SUFFIX,' + suffix + ',DIRECT\n'))

    def test_apple_store_chain_and_overseas_service_separation(self):
        rules = b.rule_lines(self.conf)
        for host in ['itunes.apple.com', 'is1-ssl.mzstatic.com', 'is5-ssl.mzstatic.com',
                     'amp-api.apps.apple.com', 'iosapps.itunes.apple.com', 'osxapps.itunes.apple.com',
                     'gs.apple.com', 'gdmf-ados.apple.com', 'music.apple.com']:
            self.assertEqual(b.match_rules(rules, host, port=443), 'DIRECT')
            self.assertEqual(b.match_rules(rules, host, port=53), 'REJECT')
        for host in ['sub.itunes.apple.com', 'is6-ssl.mzstatic.com',
                     'tv.apple.com', 'apple-relay.apple.com', 'news.apple.com']:
            self.assertEqual(b.match_rules(rules, host, port=443), 'PROXY')

    def test_dns_guard_preserves_lan_and_blocks_uncaptured_public_dns(self):
        rules = b.rule_lines(self.conf)
        for address in ['223.5.5.5', '119.29.29.29', '8.8.8.8', '9.9.9.9',
                        '2606:4700:4700::1111', '2001:4860:4860::8888']:
            with self.subTest(address=address):
                self.assertEqual(b.match_rules(rules, '', address, port=53), 'REJECT')
        for address in ['192.168.1.1', '10.0.0.1', 'fd00::1', 'fe80::1']:
            self.assertEqual(b.match_rules(rules, '', address, port=53), 'DIRECT')
        self.assertEqual(b.match_rules(rules, 'www.baidu.com', port=53), 'REJECT')
        self.assertEqual(b.match_rules(rules, 'www.baidu.com', port=443), 'DIRECT')
        self.assertEqual(b.match_rules(rules, 'www.google.com', port=443), 'PROXY')

    def test_dns_capture_and_guard_cannot_silently_regress(self):
        for conf in [self.conf.replace('hijack-dns = *:53', 'hijack-dns = :53'),
                     self.conf.replace('hijack-dns = *:53', 'hijack-dns = 223.5.5.5'),
                     self.conf.replace('DST-PORT,53,REJECT', 'DST-PORT,53,DIRECT'),
                     self.conf.replace('DST-PORT,53,REJECT', 'DST-PORT,853,REJECT'),
                     self.conf.replace('# BEGIN DNS GUARD', '# BEGIN PROXY', 1),
                     self.conf.replace('FINAL,PROXY', 'DOMAIN,ads.example,REJECT\nFINAL,PROXY')]:
            with self.subTest(change=conf[:50]), self.assertRaises((b.BuildError, ValueError)):
                b.validate(conf)

    def test_proxy_domain_does_not_need_cn_ip_resolution(self):
        rules = b.rule_lines(self.conf)
        self.assertEqual(b.match_rules(rules, 'api.openai.com', '223.5.5.5'), 'PROXY')
        self.assertEqual(b.match_rules(rules, 'missing.example.invalid'), 'PROXY')

    def test_bad_template_and_wrong_order_rejected(self):
        for conf in [self.conf.replace('dns-fallback = false', 'dns-fallback = true'),
                     self.conf.replace('ipv6 = false\n', 'ipv6 = true\n', 1),
                     self.conf.replace('prefer-ipv6 = false', 'prefer-ipv6 = true'),
                     self.conf.replace('no-resolve', 'resolve', 1),
                     self.conf.replace('FINAL,PROXY', 'FINAL,DIRECT'),
                     self.conf.replace('[Host]', '[MITM]'),
                     self.conf.replace('# BEGIN PROXY', '# BEGIN DIRECT', 1)]:
            with self.subTest(change=conf[:60]), self.assertRaises((b.BuildError, ValueError)):
                b.validate(conf)

    def test_wechat_asset_routing_regression_is_rejected(self):
        for host in ['wx.qlogo.cn', 'mmbiz.qpic.cn', 'short.weixin.qq.com']:
            # An unexpected upstream PROXY entry must not silently capture WeChat.
            conf = self.conf.replace('# BEGIN PROTECTED\n',
                                     '# BEGIN PROTECTED\nDOMAIN,' + host + ',PROXY\n', 1)
            with self.subTest(host=host), self.assertRaisesRegex(b.BuildError, 'Protected service'):
                b.validate(conf)

    def test_reviewed_direct_overrides_broad_proxy_without_widening(self):
        rules = b.rule_lines(self.conf)
        direct = ['cn.pool.ntp.org'] + [f'{i}.cn.pool.ntp.org' for i in range(4)]
        direct += ['www.hsbc.com.cn', 'www.services.online-banking.hsbc.com.cn',
                   'www.hsbcinsurance.com.cn', 'www.hsbcqh.com.cn',
                   'account-cn.alibabacloud.com', 'captive.apple.com', 'time.apple.com',
                   'apps.apple.com', 'swcdn.apple.com', 'download.windowsupdate.com',
                   'dl.delivery.mp.microsoft.com', 'officecdn.microsoft.com',
                   'sub.0.cn.pool.ntp.org', 'sub.account-cn.alibabacloud.com',
                   'api.alibabacloud.com', 'cn.alibabacloud.com', 'status.alibabacloud.com']
        for host in direct:
            with self.subTest(host=host):
                self.assertEqual(b.match_rules(rules, host, port=443), 'DIRECT')
                self.assertEqual(b.match_rules(rules, host, port=53), 'REJECT')
        for host in ['0.pool.ntp.org', '0.jp.pool.ntp.org',
                     'hsbc.com.cn.example.net', 'www.hsbc.com.hk', 'www.hsbc.com',
                     'account-cn.alibabacloud.com.example.net',
                     'copilot.microsoft.com', 'api.openai.com', 'claude.ai', 'www.netflix.com',
                     'tv.apple.com', 'news.apple.com', 'apple-relay.cloudflare.com',
                     'other.apple.com', 'other.microsoft.com', 'other.akadns.net']:
            with self.subTest(host=host):
                self.assertEqual(b.match_rules(rules, host, port=443), 'PROXY')

    def test_local_management_names_use_direct_local_dns_policy(self):
        rules = b.rule_lines(self.conf)
        for host in ['asusrouter.com', 'www.asusrouter.com', 'router.asus.com',
                     'tplinkwifi.net', 'tplogin.cn', 'tendawifi.com', 'routerlogin.net',
                     'orbilogin.com', 'miwifi.com']:
            self.assertEqual(b.match_rules(rules, host, port=443), 'DIRECT')
            self.assertEqual(b.match_rules(rules, host, port=53), 'REJECT')
            self.assertEqual(b.match_rules(rules, host, '192.168.1.1', port=53), 'DIRECT')
        for host in ['asusrouter.com.example.net', 'sub.asusrouter.com', 'other.asus.com']:
            self.assertEqual(b.match_rules(rules, host, port=443), 'PROXY')

    def test_reviewed_blocks_and_order_cannot_silently_change(self):
        for content in [self.conf.replace('DOMAIN,0.cn.pool.ntp.org,DIRECT\n', ''),
                        self.conf.replace('DOMAIN,captive.apple.com,DIRECT',
                                          'DOMAIN,captive.apple.com,PROXY'),
                        self.conf.replace('# BEGIN REVIEWED DIRECT', '# BEGIN PROXY', 1)]:
            with self.assertRaises((b.BuildError, ValueError)):
                b.validate(content)

    def test_unsafe_reviewed_policy_is_rejected(self):
        changes = [('type', 'DOMAIN-KEYWORD'), ('domains', ['com.cn']),
                   ('domains', ['apple.com']), ('domains', ['api.openai.com']),
                   ('domains', ['sub.claude.ai']), ('evidence', []),
                   ('evidence', ['http://example.com']), ('unexpected', True)]
        for key, value in changes:
            override = copy.deepcopy(self.overrides)
            override['direct_exceptions'][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(b.BuildError):
                b.reviewed_rules(override)
        override = copy.deepcopy(self.overrides)
        override['lan_domains'][0]['type'] = 'DOMAIN-SUFFIX'
        with self.assertRaises(b.BuildError):
            b.reviewed_rules(override)

    def test_reviewed_upstream_evidence_is_checked_before_publication(self):
        overrides = copy.deepcopy(self.overrides)
        overrides['direct_exceptions'][0]['domains'] = ['invented.not-in-ntp.example']
        with self.assertRaisesRegex(b.BuildError, 'lost its upstream evidence'):
            self.generate(overrides=overrides)

    def test_abnormal_count_and_coverage_are_rejected(self):
        baseline = copy.deepcopy(self.manifest)
        baseline['sources']['direct']['unique'] *= 2
        with self.assertRaisesRegex(b.BuildError, 'abnormal change'):
            self.generate(baseline=baseline)
        baseline = copy.deepcopy(self.manifest)
        baseline['ip_coverage']['china4'] *= 2
        with self.assertRaisesRegex(b.BuildError, 'covered address'):
            self.generate(baseline=baseline)

    def test_no_change_preserves_all_files_and_mtimes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'dist'
            shutil.copytree(ROOT / 'dist', output)
            before = {p.relative_to(output): (p.read_bytes(), p.stat().st_mtime_ns)
                      for p in output.rglob('*') if p.is_file()}
            # Upstream may republish a new commit or change comments without
            # changing any generated rule. Neither justifies a publication.
            inputs = dict(self.inputs)
            inputs['proxy'] += b'\n# republished without semantic changes\n'
            metadata = copy.deepcopy(self.metadata)
            metadata['proxy']['revision'] = 'b' * 40
            with patch.object(b, 'fetch_inputs', return_value=(inputs, metadata)):
                self.assertFalse(b.run(output=output))
            after = {p.relative_to(output): (p.read_bytes(), p.stat().st_mtime_ns)
                     for p in output.rglob('*') if p.is_file()}
            self.assertEqual(before, after)

    def test_failed_network_and_corrupt_input_preserve_last_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'dist'
            shutil.copytree(ROOT / 'dist', output)
            before = {p.relative_to(output): p.read_bytes() for p in output.rglob('*') if p.is_file()}
            for ident in self.inputs:
                bad = dict(self.inputs, **{ident: b'<html>upstream unavailable</html>'})
                with patch.object(b, 'fetch_inputs', return_value=(bad, self.metadata)), self.assertRaises(b.BuildError):
                    b.run(output=output)
            with patch.object(b, 'fetch_inputs', side_effect=b.BuildError('network failure')), self.assertRaises(b.BuildError):
                b.run(output=output)
            after = {p.relative_to(output): p.read_bytes() for p in output.rglob('*') if p.is_file()}
            self.assertEqual(before, after)

    def test_snapshot_tampering_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'dist'
            shutil.copytree(ROOT / 'dist', output)
            (output / 'inputs/direct.tar.gz').write_text('corrupt')
            with self.assertRaisesRegex(b.BuildError, 'hash mismatch'):
                b.offline_inputs(output, self.config)


if __name__ == '__main__':
    unittest.main()
