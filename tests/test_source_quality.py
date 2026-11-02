import datetime
import json
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import check_source_quality as q
from check_routing_contract import Policy


def raw(**values):
    return {k: set(values.get(k, [])) for k in (*q.DIRECT, 'proxy')}


def policy(*rules):
    return Policy('[Rule]\n' + '\n'.join(rules) + '\nFINAL,PROXY\n')


class SourceQualityTests(unittest.TestCase):
    def test_removed_parent_cannot_hide_surviving_exact_child(self):
        before = raw(direct=[('DOMAIN-SUFFIX', 'example.org')],
                     enhanced=[('DOMAIN', 'cdn.example.org')])
        after = raw(enhanced=[('DOMAIN', 'cdn.example.org')])
        rows, changes, findings = q.transition_review(after, before,
            policy('DOMAIN,cdn.example.org,DIRECT'), policy('DOMAIN-SUFFIX,example.org,DIRECT'))
        self.assertEqual(changes['direct']['removed'], [('DOMAIN-SUFFIX', 'example.org')])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['type'], 'removed-but-still-direct')
        retained = findings[0]['retained_samples']
        self.assertEqual([r['host'] for r in retained], ['cdn.example.org'])
        self.assertIn('enhanced', retained[0]['remaining_sources'])

    def test_removal_reclassified_proxy_needs_no_direct_exception_review(self):
        before = raw(direct=[('DOMAIN', 'example.org')])
        after = raw(proxy=[('DOMAIN-SUFFIX', 'example.org')])
        self.assertEqual(q.transition_review(after, before, policy(), policy())[2], [])

    def test_equivalent_suffix_consolidation_is_not_a_withdrawal(self):
        before = raw(direct=[('DOMAIN', 'a.example.org')])
        after = raw(direct=[('DOMAIN-SUFFIX', 'example.org')])
        self.assertEqual(q.transition_review(after, before,
            policy('DOMAIN-SUFFIX,example.org,DIRECT'), policy())[2], [])

    def test_new_overlap_detects_both_parent_directions_and_protected_routes(self):
        for direct, proxy, host in [
            (('DOMAIN', 'cn.example.org'), ('DOMAIN-SUFFIX', 'example.org'), 'cn.example.org'),
            (('DOMAIN-SUFFIX', 'example.org'), ('DOMAIN', 'cn.example.org'), 'cn.example.org')]:
            with self.subTest(direct=direct):
                after = raw(direct=[direct], proxy=[proxy])
                p = policy(','.join((*direct, 'DIRECT')))
                findings = q.transition_review(after, raw(), p, policy())[2]
                self.assertEqual(findings[0]['host'], host)
                self.assertEqual(findings[0]['type'], 'new-direct-conflict')
                self.assertEqual(q.transition_review(after, after, p, p)[2], [])
                self.assertEqual(q.transition_review(after, raw(), policy(), policy())[2], [])

    def test_review_is_bound_to_both_snapshots_and_expires(self):
        finding = {'type': 'new-direct-conflict', 'host': 'example.org'}
        empty = {'schema': 1, 'approvals': []}
        first = q.apply_approvals([dict(finding)], empty, 'old', 'new')
        approvals = {'schema': 1, 'approvals': [{'id': first[0]['id'], 'reason': 'confirmed regional service',
            'evidence': ['https://example.org/docs'], 'expires': '2026-11-03'}]}
        today = datetime.date(2026, 11, 2)
        self.assertEqual(q.apply_approvals([dict(finding)], approvals, 'old', 'new', today), [])
        for old, new, date in [('other', 'new', today), ('old', 'other', today),
                               ('old', 'new', datetime.date(2026, 11, 4))]:
            self.assertTrue(q.apply_approvals([dict(finding)], approvals, old, new, date))

    def test_unknown_regex_and_changed_sample_block_instead_of_silent_omission(self):
        specs = {'sources': [{'id': 'direct'}]}
        manifest = {'sources': {'direct': {'omitted_direct_regex': ['regexp:example']}}}
        with patch.object(q.build, 'parse_source', return_value=(set(), {'omitted_direct_regex': ['regexp:example']})):
            _, blockers, _ = q.gap_review(specs, {'direct': b''}, manifest,
                                        {'schema': 1, 'entries': []}, policy())
            self.assertEqual(blockers[0]['type'], 'unreviewed-conversion-gap')
            review = {'schema': 1, 'entries': [{'pattern': 'regexp:example', 'reason': 'test',
                'evidence': ['test'], 'disposition': 'omit-with-visible-gap',
                'samples': [{'host': 'example.org', 'policy': 'PROXY'}]}]}
            _, blockers, _ = q.gap_review(specs, {'direct': b''}, manifest, review,
                                        policy('DOMAIN,example.org,DIRECT'))
            self.assertEqual(blockers[0]['type'], 'gap-sample-regression')

    def test_real_snapshot_report_is_complete_and_does_not_claim_full_regex_coverage(self):
        report = q.assess(ROOT, ROOT)
        self.assertTrue(report['passed'], report['blockers'])
        self.assertTrue(report['baseline_present'])
        self.assertEqual(report['review_queue'], [])
        manifest = json.loads((ROOT / 'dist/manifest.json').read_text())
        expected = {p for s in manifest['sources'].values() for p in s.get('omitted_direct_regex', [])}
        self.assertEqual({r['pattern'] for r in report['conversion_gaps']}, expected)
        self.assertTrue(all(r['reviewed'] and r['coverage'].startswith('UNKNOWN')
                            for r in report['conversion_gaps']))
        self.assertGreater(len(report['current_conflicts']), 0)
        self.assertGreaterEqual(len(report['incidents']), 3)

    def test_cli_missing_baseline_fails_with_saved_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'quality.json'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/check_source_quality.py'),
                '--require-baseline', '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 1)
            report = json.loads(output.read_text())
            self.assertFalse(report['passed'])
            self.assertIn('previous source snapshots', report['error'])

    def test_real_incident_detects_ai_route_regression(self):
        text = (ROOT / 'dist/Shadowrocket.conf').read_text()
        text = text.replace('[Rule]\n', '[Rule]\nDOMAIN,ios.chat.openai.com,DIRECT\n')
        rows = q.incident_review(ROOT, text)
        self.assertEqual(next(r for r in rows if r['id'] == 'iphone-ai-proxy')['failures'], 1)

    def test_cli_unknown_gap_blocks_and_keeps_candidate_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('dist', 'config', 'sources', 'tests', 'docs'):
                shutil.copytree(ROOT / name, root / name)
            reviews = json.loads((root / 'config/coverage-review.json').read_text())
            reviews['entries'].pop()
            (root / 'config/coverage-review.json').write_text(json.dumps(reviews))
            original = (root / 'dist/Shadowrocket.conf').read_bytes()
            output = root / 'report.json'
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/check_source_quality.py'),
                '--root', str(root), '--previous-root', str(root), '--require-baseline',
                '--output', str(output)], capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 1, result.stderr)
            report = json.loads(output.read_text())
            self.assertFalse(report['passed'])
            self.assertIn('unreviewed-conversion-gap', [b['type'] for b in report['blockers']])
            self.assertEqual((root / 'dist/Shadowrocket.conf').read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
