from pathlib import Path
import sys
import unittest
import json
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import audit
import build
import audit_sources


class FullAuditTests(unittest.TestCase):
    def test_registry_direct_injection_rejected_by_both_validators(self):
        conf = (ROOT / 'dist/Shadowrocket.conf').read_text()
        for name in ['in.th', 'co.uk', 'bj.cn', 'a.ck']:
            candidate = conf.replace('# BEGIN DIRECT\n',
                '# BEGIN DIRECT\nDOMAIN-SUFFIX,' + name + ',DIRECT\n')
            with self.subTest(name=name):
                with self.assertRaisesRegex(build.BuildError, 'Registry-level'):
                    build.validate(candidate)
                with self.assertRaisesRegex(build.BuildError, 'registry-level'):
                    audit.audit(conf=candidate)

    def test_audit_does_not_use_builder_source_decoder(self):
        with patch.object(build, 'parse_source', side_effect=AssertionError('shared parser')), \
                patch.object(build, 'parse_community_archive', side_effect=AssertionError('shared archive')):
            self.assertEqual(audit.audit()['domain_failures'], 0)

    def test_builder_decoder_mutation_is_detected(self):
        config = json.loads((ROOT / 'sources/sources.json').read_text())
        inputs, metadata = build.offline_inputs(ROOT / 'dist', config)
        block = (ROOT / 'dist/Shadowrocket.conf').read_text().split('# BEGIN DIRECT\n')[1].split('# END DIRECT')[0]
        line = next((x for x in block.splitlines() if x.startswith('DOMAIN,')), None)
        if line is None:
            self.skipTest('No ordinary exact DIRECT rule in this source snapshot')
        victim = build.Rule('DOMAIN', line.split(',')[1], 'DIRECT')
        original = build.parse_source
        def corrupt(data, spec):
            rules, stats = original(data, spec)
            if victim in rules:
                rules = (rules - {victim}) | {build.Rule('DOMAIN-SUFFIX', victim.value, 'DIRECT')}
            return rules, stats
        with patch.object(build, 'parse_source', side_effect=corrupt):
            candidate = build.generate(config, (ROOT / 'config/template.conf').read_text(),
                json.loads((ROOT / 'config/overrides.json').read_text()), inputs, metadata)
        with self.assertRaisesRegex(build.BuildError, 'Full rule audit failed'):
            audit.audit(conf=candidate['Shadowrocket.conf'].decode())

    def test_published_source_boundary_model_and_ip_unions(self):
        result = audit.audit()
        self.assertGreater(result['domain_boundary_cases'], 100000)
        self.assertTrue(all(result['ip_union_equal'].values()))

    def test_domain_scope_broadening_and_ip_loss_are_detected(self):
        conf = (ROOT / 'dist/Shadowrocket.conf').read_text()
        # Broadening a local management host must not route arbitrary subdomains directly.
        exact = 'DOMAIN,asusrouter.com,DIRECT'
        self.assertIn(exact, conf)
        wrong_scope = conf.replace(exact, exact.replace('DOMAIN,', 'DOMAIN-SUFFIX,', 1), 1)
        block = conf.split('# BEGIN CHINA IP\n')[1].split('# END CHINA IP')[0]
        first_ip = next(x for x in block.splitlines() if x.startswith('IP-CIDR,'))
        missing_ip = conf.replace(first_ip + '\n', '', 1)
        for candidate in [wrong_scope, missing_ip]:
            with self.assertRaisesRegex(build.BuildError, 'Full rule audit failed'):
                audit.audit(conf=candidate)
