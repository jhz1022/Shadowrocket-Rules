import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import build
import audit

class FullIPAuditTests(unittest.TestCase):
    def setUp(self):self.conf=(ROOT/'dist/Shadowrocket.conf').read_text()

    def test_full_ipv4_ipv6_unions_equal(self):
        result=audit.audit()
        self.assertEqual(result['ip_union_equal'],{'4':True,'6':True})
        self.assertEqual(result['domain_independence_cases'],24)

    def test_independent_of_builder_source_decoder(self):
        with patch.object(build,'parse_source',side_effect=AssertionError('not independent')):
            audit.audit()

    def test_ip_loss_and_expansion_detected(self):
        line=build.block(self.conf,'CHINA IP')[0]
        for conf in [self.conf.replace(line+'\n',''),self.conf.replace('# END CHINA IP','IP-CIDR,1.1.1.0/24,DIRECT\n# END CHINA IP')]:
            with self.assertRaises(build.BuildError):audit.audit(conf=conf)

    def test_output_only_domain_and_resolution_mutations_detected(self):
        for rule in ['DOMAIN-SUFFIX,cn,DIRECT','DOMAIN,us.ip111.cn,PROXY','IP-CIDR,1.1.1.0/24,DIRECT,no-resolve']:
            conf=self.conf.replace('# BEGIN CHINA IP\n','# BEGIN CHINA IP\n'+rule+'\n')
            with self.assertRaises(build.BuildError):audit.audit(conf=conf)

    def test_comparison_does_not_mislabel_domain_only_counts_as_ip_decisions(self):
        old=self.conf.replace('# BEGIN CHINA IP\n','# BEGIN CHINA IP\nDOMAIN-SUFFIX,cn,DIRECT\n')
        self.assertEqual(audit.audit(previous=old)['previous_business_domain_rules'],1)

if __name__=='__main__':unittest.main()
