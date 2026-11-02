import copy
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import update_guard


class UpdateGuardTests(unittest.TestCase):
    def setUp(self):
        self.limits = json.loads((ROOT / 'config/update-policy.json').read_text())
        self.report = {'previous_config_sha256': 'a' * 64,
                       'domain_boundary_cases': 600000, 'boundary_policy_changes': {},
                       'ip_policy_changes': {f: {'previous_addresses': 10000,
                                                'added_addresses': 0, 'removed_addresses': 0}
                                             for f in ('china4', 'china6')}}

    def test_small_daily_changes_pass_but_each_budget_can_stop_publication(self):
        self.report['boundary_policy_changes'] = {'PROXY -> DIRECT': 16}
        self.assertTrue(update_guard.assess(self.report, self.limits)['passed'])
        cases = [({'PROXY -> DIRECT': 501}, 600000, 'proxy_to_direct'),
                 ({'PROXY -> DIRECT': 101}, 100000, 'proxy_to_direct_ratio'),
                 ({'DIRECT -> PROXY': 2001}, 600000, 'domain_changes'),
                 ({'DIRECT -> PROXY': 501}, 100000, 'domain_change_ratio')]
        for transitions, size, metric in cases:
            with self.subTest(metric=metric):
                report = copy.deepcopy(self.report)
                report.update(boundary_policy_changes=transitions, domain_boundary_cases=size)
                result = update_guard.assess(report, self.limits)
                self.assertFalse(result['passed'])
                self.assertIn(metric, [v['metric'] for v in result['violations']])

    def test_threshold_is_inclusive_and_missing_baseline_cannot_bypass_guard(self):
        self.report['boundary_policy_changes'] = {'PROXY -> DIRECT': 500}
        self.assertTrue(update_guard.assess(self.report, self.limits)['passed'])
        self.report['previous_config_sha256'] = None
        with self.assertRaises(ValueError):
            update_guard.assess(self.report, self.limits)
        for key, value in [('max_domain_changes', True), ('max_ip_added_ratio', float('nan'))]:
            bad = dict(self.limits, **{key: value})
            with self.assertRaises(ValueError):
                update_guard.assess(self.report, bad)

    def test_equal_size_ip_replacement_is_detected_for_both_families(self):
        for family, first, other in [('china4', '1.0.0.0/24', '2.0.0.0/24'),
                                     ('china6', '2400::/32', '2401::/32')]:
            before, after = [ipaddress.ip_network(first)], [ipaddress.ip_network(other)]
            delta = update_guard.ip_delta(before, after)
            self.assertEqual(delta['added_addresses'], before[0].num_addresses)
            self.assertEqual(delta['removed_addresses'], before[0].num_addresses)
            report = copy.deepcopy(self.report)
            report['ip_policy_changes'][family] = delta
            self.assertFalse(update_guard.assess(report, self.limits)['passed'])
            split = list(before[0].subnets(prefixlen_diff=1))
            self.assertEqual(update_guard.ip_delta(before, split)['removed_addresses'], 0)
            self.assertEqual(update_guard.ip_delta(split, before)['added_addresses'], 0)

    def test_partial_ip_overlap_counts_exact_membership(self):
        net = ipaddress.ip_network
        self.assertEqual(update_guard.ip_delta([net('1.0.0.0/24')],
            [net('1.0.0.128/25'), net('2.0.0.0/25')]),
            {'previous_addresses': 256, 'added_addresses': 128, 'removed_addresses': 128})

    def test_cli_blocks_and_preserves_evidence_for_large_policy_flip(self):
        # Candidate remains a valid source-derived configuration. The previous
        # publication routes its domestic domain rules through the proxy instead.
        text = (ROOT / 'dist/Shadowrocket.conf').read_text()
        previous = '\n'.join(line.rsplit(',DIRECT', 1)[0] + ',PROXY'
                             if line.startswith(('DOMAIN,', 'DOMAIN-SUFFIX,')) and line.endswith(',DIRECT')
                             else line for line in text.splitlines()) + '\n'
        with tempfile.TemporaryDirectory() as tmp:
            old, output = Path(tmp) / 'old.conf', Path(tmp) / 'audit.json'
            old.write_text(previous)
            p = subprocess.run([sys.executable, str(ROOT / 'scripts/audit.py'),
                                '--compare', str(old), '--enforce-changes', '--output', str(output)],
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            report = json.loads(output.read_text())
            self.assertEqual(report['domain_failures'], 0)
            self.assertFalse(report['update_guard']['passed'])
            self.assertIn('Routing change budget exceeded', p.stderr)


if __name__ == '__main__':
    unittest.main()
