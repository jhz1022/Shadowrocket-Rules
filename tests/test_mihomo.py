import copy
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
import mihomo
import check_mihomo
from check_routing_contract import Policy


class MihomoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conf = (ROOT/'dist/Shadowrocket.conf').read_text()
        cls.files = mihomo.generate(cls.conf)
        cls.config = yaml.safe_load(cls.files['mihomo/Mihomo.yaml'])

    def test_full_published_contract_and_ordered_expansion(self):
        result = check_mihomo.check()
        self.assertEqual(result['source_rules'], len(Policy(self.conf).rows))
        self.assertGreaterEqual(result['routing_cases'], 115)
        self.assertEqual(result['routing_failures'], 0)

    def test_native_failure_policy_is_explicit_not_direct(self):
        rules = self.config['rules']
        for group in ('protected', 'proxy'):
            i = rules.index(f'RULE-SET,{group},PROXY')
            self.assertEqual(rules[i+1], f'AND,((NETWORK,udp),(RULE-SET,{group})),REJECT')
        self.assertEqual(rules[-2:], ['MATCH,PROXY', 'MATCH,REJECT'])
        self.assertEqual(self.config['proxy-groups'][0]['proxies'], ['REJECT'])

    def test_dns_never_uses_system_or_unknown_direct_upstream(self):
        dns = self.config['dns']
        self.assertTrue(dns['direct-nameserver-follow-policy'])
        self.assertTrue(all(s.endswith('#PROXY') for s in dns['direct-nameserver']))
        self.assertTrue(all(s.endswith('#DIRECT') for s in dns['proxy-server-nameserver']))
        self.assertNotIn('fallback', dns)

    def test_yaml_safely_round_trips_without_aliases(self):
        values = {'name': '测试: x\ny', 'flag': False, 'items': [1, None, {}, [], {'x': '#quote'}]}
        self.assertEqual(yaml.safe_load(mihomo.yaml_bytes(values)), values)
        self.assertNotIn(b'&id', self.files['mihomo/Mihomo.yaml'])

    def test_looping_or_implicit_resolvers_rejected(self):
        for server in ('system', 'udp://127.0.0.1:53#DIRECT', 'udp://192.168.1.99:53#DIRECT',
                       'udp://192.168.1.1:53#PROXY', '8.8.8.8'):
            with self.subTest(server=server), self.assertRaises(ValueError):
                mihomo.generate(self.conf, {'schema':1, 'direct_dns':[server]})

    def test_order_and_guards_cannot_silently_change(self):
        # Reauthenticate a corrupted serialization to test the semantic checker,
        # rather than merely testing its content-hash gate.
        for mutate in ('guard', 'order', 'dns', 'empty-node-direct'):
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                shutil.copytree(ROOT/'dist', root/'dist')
                config = copy.deepcopy(self.config)
                if mutate == 'guard':
                    config['rules'].remove('AND,((NETWORK,udp),(RULE-SET,protected)),REJECT')
                elif mutate == 'order':
                    config['rules'][2], config['rules'][3] = config['rules'][3], config['rules'][2]
                elif mutate == 'dns':
                    config['dns']['direct-nameserver'] = ['system']
                else:
                    config['proxy-groups'][0]['proxies'] = ['DIRECT']
                data = mihomo.yaml_bytes(config)
                (root/'dist/mihomo/Mihomo.yaml').write_bytes(data)
                manifest = json.loads((root/'dist/mihomo/manifest.json').read_text())
                manifest['files']['Mihomo.yaml'] = {'sha256':check_mihomo.sha(data), 'bytes':len(data)}
                data = (json.dumps(manifest)+'\n').encode()
                (root/'dist/mihomo/manifest.json').write_bytes(data)
                parent = json.loads((root/'dist/manifest.json').read_text())
                parent['mihomo_manifest_sha256'] = check_mihomo.sha(data)
                (root/'dist/manifest.json').write_text(json.dumps(parent))
                with self.assertRaises(ValueError):
                    check_mihomo.check(root=ROOT, output=root/'dist')


if __name__ == '__main__':
    unittest.main()
