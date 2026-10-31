import copy
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import build as b

class DownloadTests(unittest.TestCase):
    def test_errors_retry_and_fail(self):
        for error in [urllib.error.URLError('timeout'),
                      urllib.error.HTTPError('https://example.com', 404, 'missing', None, None)]:
            with patch.object(b.urllib.request, 'urlopen', side_effect=error) as request, \
                    patch.object(b.time, 'sleep'), self.assertRaises(b.BuildError):
                b.download('https://example.com')
            self.assertEqual(request.call_count, 3)

    def test_empty_and_oversized_downloads(self):
        for data in [b'', b'12345']:
            response = io.BytesIO(data)
            response.geturl = lambda: 'https://example.com'
            with patch.object(b.urllib.request, 'urlopen', return_value=response), self.assertRaises(b.BuildError):
                b.download('https://example.com', limit=4)

    def test_https_required(self):
        with self.assertRaises(b.BuildError):
            b.download('http://example.com')

    def test_repository_revision_is_resolved_once(self):
        config = {'max_bytes': 1000, 'sources': [
            {'id': 'a', 'repository': 'owner/repo', 'ref': 'release', 'path': 'a.txt'},
            {'id': 'b', 'repository': 'owner/repo', 'ref': 'release', 'path': 'b.txt'}]}
        revision = 'a' * 40
        result = [json.dumps({'object': {'type': 'commit', 'sha': revision}}).encode(), b'a', b'b']
        with patch.object(b, 'download', side_effect=result) as request:
            inputs, metadata = b.fetch_inputs(config)
        self.assertEqual(request.call_count, 3)
        self.assertEqual(inputs, {'a': b'a', 'b': b'b'})
        self.assertEqual(metadata['a']['revision'], metadata['b']['revision'])
        self.assertIn('/' + revision + '/b.txt', metadata['b']['url'])


class DestinationIPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config=json.loads((ROOT/'sources/sources.json').read_text())
        cls.template=(ROOT/'config/template.conf').read_text()
        cls.conf=(ROOT/'dist/Shadowrocket.conf').read_text()
        cls.inputs,cls.metadata=b.offline_inputs(ROOT/'dist',cls.config)
        cls.manifest=json.loads((ROOT/'dist/manifest.json').read_text())
        cls.rules=b.rule_lines(cls.conf)

    def generate(self, **kw):
        args=dict(config=self.config,template=self.template,inputs=self.inputs,metadata=self.metadata,baseline=self.manifest)
        args.update(kw)
        return b.generate(**args)

    def test_real_snapshot_reproduces(self):
        self.assertEqual(self.generate(),self.generate())
        self.assertEqual(self.generate()['Shadowrocket.conf'],self.conf.encode())

    def test_destination_beats_suffix_brand_and_old_protection(self):
        for host in ['us.ip111.cn','cn.bing.com','claude.ai','api.openai.com','www.baidu.com','gateway.icloud.com.cn','steamcommunity.com']:
            for ip,want in [('162.222.90.70','PROXY'),('223.5.5.5','DIRECT'),('2400:3200::1','DIRECT'),('2606:4700:4700::1111','PROXY')]:
                with self.subTest(host=host,ip=ip):
                    self.assertEqual(b.match_rules(self.rules,host,ip,443),want)
        self.assertEqual(b.match_rules(self.rules,'fresh.cn',port=443),'PROXY')

    def test_plain_ip_and_local_network(self):
        for ip,want in [('1.1.1.1','PROXY'),('223.5.5.5','DIRECT'),('192.168.1.1','DIRECT'),('fd00::1','DIRECT')]:
            self.assertEqual(b.match_rules(self.rules,'',ip,443),want)
        self.assertEqual(b.match_rules(self.rules,'printer.local',port=443),'DIRECT')

    def test_dns_guard_precedes_public_ip_routes(self):
        for ip in ['223.5.5.5','8.8.8.8','2400:3200::1','2606:4700:4700::1111']:
            self.assertEqual(b.match_rules(self.rules,'',ip,53),'REJECT')
        self.assertEqual(b.match_rules(self.rules,'','192.168.1.1',53),'DIRECT')

    def test_public_domain_shortcuts_and_no_resolve_cannot_return(self):
        for rule in ['DOMAIN-SUFFIX,cn,DIRECT','DOMAIN,claude.ai,PROXY','DOMAIN-SUFFIX,bing.com,DIRECT','IP-CIDR,223.5.5.0/24,DIRECT,no-resolve','GEOIP,CN,DIRECT']:
            with self.subTest(rule=rule),self.assertRaises(b.BuildError):
                b.validate(self.conf.replace('# BEGIN CHINA IP\n','# BEGIN CHINA IP\n'+rule+'\n'))

    def test_dns_resolution_address_consistency_and_ipv4_baseline(self):
        for key,val in [('always-ip-address','false'),('use-local-host-item-for-proxy','false'),('dns-direct-system','true'),('dns-fallback','true'),('ipv6','true'),('udp-policy-not-supported-behaviour','DIRECT')]:
            with self.subTest(key=key),self.assertRaises(b.BuildError):
                b.validate(self.conf.replace(key+' = '+b.REQUIRED_SETTINGS[key],key+' = '+val))
        with self.assertRaises(b.BuildError):
            b.validate(self.conf.replace('localhost = 127.0.0.1','localhost = 127.0.0.1\nus.ip111.cn = 223.5.5.5'))

    def test_bad_rules_order_guard_and_final_rejected(self):
        for text in [self.conf.replace('DST-PORT,53,REJECT','DST-PORT,53,DIRECT'),self.conf.replace('FINAL,PROXY','FINAL,DIRECT'),self.conf.replace('[Host]','[Script]'),self.conf.replace('# BEGIN CHINA IP','# BEGIN OTHER')]:
            with self.assertRaises((b.BuildError,ValueError)): b.validate(text)

    def test_cidr_rejects_wrong_family_private_default_and_bad_input(self):
        spec={'id':'test','format':'cidr4','policy':'DIRECT','min_records':1,'max_records':30}
        for data in [b'',b'0.0.0.0/0',b'1.0.0.0/7',b'192.168.0.0/16',b'223.5.5.1/24',b'2400:3200::/32',b'223.5.5.5',b'<html>error</html>',b'\xff']:
            with self.subTest(data=data),self.assertRaises(b.BuildError): b.parse_source(data,spec)
        nets,stats=b.parse_source(b'\xef\xbb\xbf223.5.5.0/24\r\n',spec)
        self.assertEqual(str(next(iter(nets))),'223.5.5.0/24')
        with self.assertRaises(b.BuildError): b.parse_source(b'223.5.5.0/24\n223.5.5.0/24',spec)

    def test_domain_sources_cannot_reenter_publication(self):
        config=copy.deepcopy(self.config)
        config['sources'].append({'id':'enhanced'})
        with self.assertRaises(b.BuildError):self.generate(config=config)

    def test_abnormal_source_count_and_coverage_stop_release(self):
        for mutate in ['count','coverage']:
            baseline=copy.deepcopy(self.manifest)
            if mutate=='count': baseline['sources']['china4']['unique']*=10
            else: baseline['ip_coverage']['china4']*=10
            with self.assertRaises(b.BuildError):self.generate(baseline=baseline)

    def copy_tree(self,tmp):
        root=Path(tmp)
        for name in ['dist','config','sources']:
            shutil.copytree(ROOT/name,root/name)
        return root

    def test_no_change_preserves_files_and_mtimes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self.copy_tree(tmp)
            before={p.relative_to(root):(p.read_bytes(),p.stat().st_mtime_ns) for p in (root/'dist').rglob('*') if p.is_file()}
            self.assertFalse(b.run(root,offline=True))
            after={p.relative_to(root):(p.read_bytes(),p.stat().st_mtime_ns) for p in (root/'dist').rglob('*') if p.is_file()}
            self.assertEqual(before,after)

    def test_failed_download_or_input_preserves_previous_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self.copy_tree(tmp)
            before={p.relative_to(root):p.read_bytes() for p in (root/'dist').rglob('*') if p.is_file()}
            with patch.object(b,'fetch_inputs',side_effect=b.BuildError('offline')),self.assertRaises(b.BuildError):b.run(root)
            bad=dict(self.inputs);bad['china6']=b'broken'
            with patch.object(b,'fetch_inputs',return_value=(bad,self.metadata)),self.assertRaises(b.BuildError):b.run(root)
            self.assertEqual(before,{p.relative_to(root):p.read_bytes() for p in (root/'dist').rglob('*') if p.is_file()})

    def test_source_tampering_and_check_mismatch_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=self.copy_tree(tmp)
            file=root/'dist/inputs/china4.txt'
            file.write_bytes(file.read_bytes()+b'1.1.1.0/24\n')
            with self.assertRaises(b.BuildError): b.run(root,offline=True,check=True)
        with tempfile.TemporaryDirectory() as tmp:
            root=self.copy_tree(tmp)
            file=root/'dist/Shadowrocket.conf';file.write_text(file.read_text()+'# changed\n')
            with self.assertRaises(b.BuildError):b.run(root,offline=True,check=True)

if __name__=='__main__':unittest.main()
