import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.request
import contextlib

import yaml

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import check_mihomo_subscription as subscription
import mihomo


class SubscriptionReadTests(unittest.TestCase):
    def fixture(self,tmp,returncode=0,payload=None):
        base=Path(tmp)
        bundle=base/'bundle';bundle.mkdir()
        config={'proxies':[],'proxy-groups':[{'name':'PROXY','type':'select','proxies':['REJECT']}],
                'rules':['MATCH,REJECT'],'dns':{'ipv6':False}}
        (bundle/'Mihomo.yaml').write_bytes(mihomo.yaml_bytes(config))
        remote=payload if payload is not None else {
            'proxies':[{'name':'private-name','type':'vless','server':'private.example',
                        'port':443,'uuid':'private-uuid','tls':True,'network':'tcp'}],
            'rules':['MATCH,DIRECT'],'dns':{'ipv6':True}}
        body=yaml.safe_dump(remote).encode()
        opener=SimpleNamespace(open=lambda *a,**k:io.BytesIO(body))
        native=SimpleNamespace(returncode=returncode,stdout=b'private native diagnostic')
        return base,bundle,opener,native

    def test_private_read_only_check_does_not_import_subscription_rules_or_dns(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,bundle,opener,native=self.fixture(tmp)
            with patch.object(subscription.urllib.request,'build_opener',return_value=opener), \
                 patch.object(subscription.subprocess,'run',return_value=native) as run:
                result=subscription.check_subscription('https://sub.example/mihomo/private-token',
                    Path('/native-mihomo'),base/'private',bundle=bundle)
            self.assertEqual(result['node_count'],1)
            self.assertFalse(result['proxy_started'])
            candidate=yaml.safe_load((base/'private/Mihomo.private.yaml').read_text())
            self.assertEqual(candidate['rules'],['MATCH,REJECT'])
            self.assertFalse(candidate['dns']['ipv6'])
            self.assertEqual(run.call_args.args[0][1],'-t')
            for text in ('private-token','private-uuid','private.example','private-name'):
                self.assertNotIn(text,json.dumps(result))
                self.assertNotIn(text,str(run.call_args.args[0]))
            for path in (base/'private').iterdir():
                if path.is_file():self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_native_failure_stays_a_failure_with_private_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,bundle,opener,native=self.fixture(tmp,returncode=1)
            with patch.object(subscription.urllib.request,'build_opener',return_value=opener), \
                 patch.object(subscription.subprocess,'run',return_value=native), \
                 self.assertRaisesRegex(ValueError,'syntax check failed'):
                subscription.check_subscription('https://sub.example/mihomo/private-token',
                    Path('/native-mihomo'),base/'private',bundle=bundle)
            self.assertFalse((base/'private/summary.json').exists())

    def test_non_node_response_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base,bundle,opener,_=self.fixture(tmp,payload={'rules':['MATCH,DIRECT']})
            with patch.object(subscription.urllib.request,'build_opener',return_value=opener), \
                 patch.object(subscription.subprocess,'run') as run, self.assertRaises(ValueError):
                subscription.check_subscription('https://sub.example/mihomo/private-token',
                    Path('/native-mihomo'),base/'private',bundle=bundle)
            run.assert_not_called()

    def test_subscription_redirect_does_not_disclose_to_another_host_or_downgrade(self):
        handler=subscription.SameHostRedirect()
        request=urllib.request.Request('https://sub.example/mihomo/private-token')
        for destination in ('https://other.example/path','http://sub.example/path'):
            with self.subTest(destination=destination),self.assertRaises(ValueError):
                handler.redirect_request(request,None,302,'redirect',{},destination)

    def test_cli_failure_does_not_echo_a_private_exception_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'subscription.private.txt'
            source.write_text('https://sub.example/mihomo/private-token')
            error=io.StringIO()
            with patch.object(sys,'argv',['check','--subscription-file',str(source),'--binary','/native']), \
                 patch.object(subscription,'check_subscription',side_effect=ValueError('private-token private-uuid')), \
                 contextlib.redirect_stderr(error):
                self.assertEqual(subscription.main(),1)
            self.assertNotIn('private-token',error.getvalue())
            self.assertNotIn('private-uuid',error.getvalue())


if __name__=='__main__':
    unittest.main()
