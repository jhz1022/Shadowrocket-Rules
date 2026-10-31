from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import audit
import build


class FullAuditTests(unittest.TestCase):
    def test_published_source_boundary_model_and_ip_unions(self):
        result = audit.audit()
        self.assertGreater(result['domain_boundary_cases'], 100000)
        self.assertTrue(all(result['ip_union_equal'].values()))

    def test_domain_scope_broadening_and_ip_loss_are_detected(self):
        conf = (ROOT / 'dist/Shadowrocket.conf').read_text()
        # Broadening a precise China NTP exception would leak its unapproved
        # subdomains into DIRECT, even though both still look syntactically valid.
        exact = 'DOMAIN,0.cn.pool.ntp.org,DIRECT'
        self.assertIn(exact, conf)
        wrong_scope = conf.replace(exact, exact.replace('DOMAIN,', 'DOMAIN-SUFFIX,', 1), 1)
        block = conf.split('# BEGIN CHINA IP\n')[1].split('# END CHINA IP')[0]
        first_ip = next(x for x in block.splitlines() if x.startswith('IP-CIDR,'))
        missing_ip = conf.replace(first_ip + '\n', '', 1)
        for candidate in [wrong_scope, missing_ip]:
            with self.assertRaisesRegex(build.BuildError, 'Full rule audit failed'):
                audit.audit(conf=candidate)
