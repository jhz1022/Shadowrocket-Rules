import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import build
import check_routing_contract as contract


class RoutingContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conf = (ROOT / 'dist/Shadowrocket.conf').read_text()
        cls.cases = json.loads((ROOT / 'tests/routing_cases.json').read_text())

    def test_cross_service_and_lazy_dns_contracts(self):
        result = contract.check(self.conf, self.cases)
        self.assertEqual(result['failures'], 0, [r for r in result['results'] if not r['passed']])
        self.assertEqual(result['native_client_validation'], 'NOT_RUN')

    def test_no_resolve_regression_breaks_unknown_cn_ip_cases(self):
        start, rest = self.conf.split('# BEGIN CHINA IP\n')
        block, end = rest.split('# END CHINA IP')
        broken = start + '# BEGIN CHINA IP\n' + ''.join(
            line + ',no-resolve\n' for line in block.splitlines()) + '# END CHINA IP' + end
        with self.assertRaisesRegex(build.BuildError, 'must allow DNS resolution'):
            build.validate(broken)
        result = contract.check(broken, self.cases)
        self.assertGreater(result['failures'], 0)

    def test_early_lan_resolution_cannot_return(self):
        broken = self.conf.replace('IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
                                   'IP-CIDR,10.0.0.0/8,DIRECT')
        with self.assertRaisesRegex(build.BuildError, 'LAN IP rule'):
            build.validate(broken)
        # Explicit domain routes must not have their DNS queried by an earlier
        # nonmatching LAN rule. Old route-only models would miss this regression.
        result = contract.check(broken, self.cases)
        self.assertGreater(result['failures'], 0)

    def test_domestic_public_services_do_not_depend_on_foreign_dns(self):
        policy = contract.Policy(self.conf)
        for host in ('www.gov.cn', 'www.tsinghua.edu.cn', 'future-school.edu.cn',
                     'future-department.gov.cn'):
            def unexpected_query(_):
                self.fail('Routing must select the domestic service before resolving')
            self.assertEqual(policy.decide(host, unexpected_query)['policy'], 'DIRECT')
        for host in ('fakeedu.cn', 'gov.cn.outside.invalid', 'future-company.com.cn'):
            self.assertEqual(policy.decide(host, lambda _: ['1.1.1.1'])['policy'], 'PROXY')

    def test_dns_failure_is_not_reclassified_as_direct(self):
        policy = contract.Policy(self.conf)
        def failure(_):
            raise TimeoutError('injected timeout')
        result = policy.decide('fresh-unlisted.cn', failure)
        self.assertEqual(result['policy'], 'PROXY')
        self.assertTrue(result['routing_dns_requested'])


if __name__ == '__main__':
    unittest.main()
