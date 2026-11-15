from pathlib import Path
import sys
import tempfile
import unittest

import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import prepare_mihomo_nodes as nodes
import mihomo


class PrivateNodeTests(unittest.TestCase):
    def test_only_nodes_are_supplied_by_subscription(self):
        url='https://subscription.example/mihomo/private-token?x=a%24b'
        config=nodes.provider_config(url)
        self.assertEqual(set(config),{'proxy-providers'})
        self.assertEqual(config['proxy-providers']['nodes']['url'],url)
        self.assertEqual(config['proxy-providers']['nodes']['proxy'],'DIRECT')
        self.assertFalse(config['proxy-providers']['nodes']['health-check']['enable'])

    def test_subscription_host_has_independent_narrow_bootstrap(self):
        url='https://subscription.example/mihomo/private-token'
        text=nodes.module_content(url).decode()
        self.assertNotIn('private-token',text)
        body=text.split('[YAML]\n')[1].split('[Overwrite]')[0]
        policy=yaml.safe_load(body)['dns']['+nameserver-policy']
        self.assertEqual(list(policy),['subscription.example'])
        self.assertTrue(all(x.endswith('#DIRECT') for x in policy['subscription.example']))
        self.assertEqual(yaml.safe_load(body)['proxy-groups'][0]['proxies'],['REJECT'])
        self.assertIn('"proxy-providers"\n',text)

    def test_firewall_dns_mode_uses_native_uci_not_broken_boolean_module_entry(self):
        text=nodes.module_content('https://subscription.example/mihomo/private-token').decode()
        general=text.split('[General]\n')[1].split('[YAML]')[0]
        settings={k.strip():v.strip() for line in general.splitlines()
                  if line.strip() and not line.lstrip().startswith('#') and '=' in line
                  for k,v in [line.split('=',1)]}
        self.assertNotIn('ENABLE_REDIRECT_DNS',settings)
        self.assertEqual(settings['ROUTER_SELF_PROXY'],'0')

    def test_bad_or_legacy_urls_rejected_without_echoing_secret(self):
        for url in ('http://host/mihomo/secret','https://host/clash-legacy/secret',
                    'https://user:password@host/mihomo/x','https://host/x#fragment',
                    'https://host/x\nsecret'):
            with self.subTest(case=url.split(':')[0]),self.assertRaises(ValueError) as error:
                nodes.provider_config(url)
            self.assertNotIn(url,str(error.exception))

    def test_explicit_authorization_required_for_existing_http_subscription(self):
        url='http://subscription.example:2096/custom/private-token'
        with self.assertRaises(ValueError):
            nodes.provider_config(url)
        self.assertEqual(nodes.provider_config(url,allow_http=True)['proxy-providers']['nodes']['url'],url)

    def test_private_files_are_restricted_and_yaml_data_is_literal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'nodes.private.yaml'
            url='https://subscription.example/mihomo/token$KEEP?key=quote%22'
            nodes.write_private(path,mihomo.yaml_bytes(nodes.provider_config(url)))
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(yaml.safe_load(path.read_text())['proxy-providers']['nodes']['url'],url)
            with self.assertRaises(ValueError):
                nodes.write_private(Path(tmp)/'public.yaml',b'secret')


if __name__=='__main__':
    unittest.main()
