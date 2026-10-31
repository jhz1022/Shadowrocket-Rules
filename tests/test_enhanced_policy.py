"""Policy regressions independent of the three originally reported brands."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build
import audit
import test_build as fixtures


class EnhancedPolicyTests(unittest.TestCase):
    def test_new_vendor_cn_services_are_selected_without_brand_code(self):
        data = fixtures.ArchiveTests().archive({
            'geolocation-!cn': 'include:new-vendor\ninclude:other-vendor',
            'new-vendor': 'cdn.vendor.example @cn\napi.vendor.example\n'
                          'full:update.vendor.example @CN\nad.vendor.example @ads @cn',
            'other-vendor': 'global.vendor.example @!cn @cn'})
        source = {'id': 'regional', 'format': 'v2fly-archive',
                  'path': 'data/geolocation-!cn', 'attribute': 'cn',
                  'policy': 'DIRECT', 'min_records': 1, 'max_records': 10}
        rows, _ = build.parse_source(data, source)
        self.assertEqual(rows, {build.Rule('DOMAIN-SUFFIX', 'cdn.vendor.example', 'DIRECT'),
                                build.Rule('DOMAIN', 'update.vendor.example', 'DIRECT')})

    def test_published_bare_suffix_and_full_records_are_not_interchangeable(self):
        source = {'id': 'enhanced', 'format': 'loyal-direct', 'policy': 'DIRECT',
                  'min_records': 1, 'max_records': 10}
        rows, _ = build.parse_source(b'vendor.example\nfull:host.other.example\n', source)
        lines = [r.line() for r in rows] + ['FINAL,PROXY']
        self.assertEqual(build.match_rules(lines, 'child.vendor.example'), 'DIRECT')
        self.assertEqual(build.match_rules(lines, 'child.host.other.example'), 'PROXY')
        for text in (b'keyword:vendor', b'*.vendor.example', b'vendor.example,DIRECT'):
            with self.assertRaises(build.BuildError):
                build.parse_source(text, source)

    def test_registry_exception_is_explicit_and_cannot_expand_arbitrarily(self):
        config = json.loads((ROOT / 'sources/sources.json').read_text())
        rows = {build.Rule('DOMAIN-SUFFIX', h, 'DIRECT') for h in ('cn', 'in.th', 'co.uk')}
        self.assertEqual(build.precise_direct(rows, config), {build.Rule('DOMAIN-SUFFIX', 'cn', 'DIRECT')})
        config['direct_allowed_registry_suffixes'].append('in.th')
        with self.assertRaises(build.BuildError):
            build.precise_direct(rows, config)

    def test_whitelist_and_protected_services_have_explicit_priority(self):
        rules = build.rule_lines((ROOT / 'dist/Shadowrocket.conf').read_text())
        for host in ('cn.sc.com', 'cn.bing.com', 'gateway.icloud.com.cn',
                     'dl.steam.clngaa.com', 'alibaba.cdn.steampipe.steamcontent.com',
                     'dcn01.ps5.update.playstation.net', 'cnpmjs.org', 'fresh-unlisted.cn'):
            with self.subTest(host=host):
                self.assertEqual(build.match_rules(rules, host), 'DIRECT')
        for host in ('www.google.cn', 'sydney.bing.com', 'copilot.microsoft.com',
                     'api.anthropic.com', 'chatgpt.com', 'tv.apple.com',
                     'steamcommunity.com', 'never-listed.invalid', 'fresh-unlisted.in.th'):
            with self.subTest(host=host):
                self.assertEqual(build.match_rules(rules, host), 'PROXY')

    def test_output_only_domain_injection_cannot_escape_full_audit(self):
        conf = (ROOT / 'dist/Shadowrocket.conf').read_text().replace('# BEGIN DIRECT\n',
            '# BEGIN DIRECT\nDOMAIN,unlisted-injected.invalid,DIRECT\n', 1)
        with self.assertRaisesRegex(build.BuildError, 'Full rule audit failed'):
            audit.audit(conf=conf)

    def test_whole_source_coverage_has_no_generic_proxy_shadowing(self):
        result = audit.audit()
        self.assertGreater(result['domain_boundary_cases'], 500000)
        for ident, counts in result['source_policy_coverage'].items():
            self.assertNotIn('ordinary-proxy-priority', counts, ident)
        self.assertGreater(result['source_policy_coverage']['enhanced']['direct'], 100000)
        self.assertGreater(result['source_policy_coverage']['regional']['direct'], 500)

    def test_policy_diff_accounts_for_changed_and_removed_boundaries(self):
        conf = (ROOT / 'dist/Shadowrocket.conf').read_text()
        old = conf.replace('# BEGIN DIRECT\n',
            '# BEGIN DIRECT\nDOMAIN,unlisted-previous.invalid,DIRECT\n', 1)
        result = audit.audit(previous=old)
        self.assertEqual(result['boundary_policy_changes'], {'DIRECT -> PROXY': 1})


if __name__ == '__main__':
    unittest.main()
