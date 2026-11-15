#!/usr/bin/env python3
"""Read a private subscription and validate node syntax without starting a proxy.

No credentials, URL, node names or addresses are printed. Raw subscription,
private candidate and native diagnostics stay in ignored files with mode 0600.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import urlsplit

import yaml
from check_mihomo import load_yaml
from mihomo import yaml_bytes
from prepare_mihomo_nodes import provider_config, write_private

ROOT=Path(__file__).resolve().parents[1]


class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        old,new=urlsplit(request.full_url),urlsplit(newurl)
        if old.hostname!=new.hostname or new.scheme not in ('http','https') or (old.scheme=='https' and new.scheme!='https'):
            raise ValueError('Subscription redirect changed destination or downgraded TLS')
        return super().redirect_request(request,fp,code,message,headers,newurl)


def check_subscription(url,binary,work,allow_http=False,bundle=ROOT/'dist/mihomo'):
    work.mkdir(parents=True,exist_ok=True)
    work.chmod(0o700)
    (work/'summary.json').unlink(missing_ok=True)
    provider_config(url,allow_http)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),SameHostRedirect())
    request=urllib.request.Request(url,headers={'User-Agent':'mihomo','Accept':'application/yaml,text/yaml,text/plain'})
    with opener.open(request,timeout=15) as response:
        data=response.read(16*1024*1024+1)
    if not data or len(data)>16*1024*1024:
        raise ValueError('Subscription is empty or exceeds the private-provider budget')
    path=work/'subscription.private.yaml'
    write_private(path,data)
    subscription=load_yaml(path)
    if not isinstance(subscription,dict) or not isinstance(subscription.get('proxies'),list) or not subscription['proxies']:
        raise ValueError('Server did not return Mihomo YAML with a nonempty proxies list')
    nodes=subscription['proxies']
    if len(nodes)>10000 or any(not isinstance(n,dict) for n in nodes):
        raise ValueError('Invalid or oversized node collection')
    names=[node.get('name') for node in nodes]
    if any(not isinstance(n,str) or not n for n in names) or len(set(names))!=len(names):
        raise ValueError('Missing/duplicate node names in subscription')
    config=load_yaml(bundle/'Mihomo.yaml')
    config['proxies']=nodes
    config['proxy-groups'][0]['proxies']=['REJECT']+names
    candidate=work/'Mihomo.private.yaml'
    write_private(candidate,yaml_bytes(config))
    result=subprocess.run([str(binary),'-t','-d',str(work),'-f',str(candidate)],
                          stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=40)
    diagnostic=work/'native-diagnostic.private.txt'
    diagnostic.write_bytes(result.stdout);diagnostic.chmod(0o600)
    if result.returncode:
        raise ValueError('Private native node syntax check failed; inspect the private diagnostic locally')
    summary={'node_count':len(nodes),'protocols':dict(Counter(node.get('type','missing') for node in nodes)),
             'vless_tcp_tls_nodes':sum(node.get('type')=='vless' and node.get('network','tcp')=='tcp'
                                       and node.get('tls') is True for node in nodes),
             'native_syntax':'PASS','node_handshake':'NOT_RUN','proxy_started':False,
             'panel_configuration_changed':False,'subscription_transport':urlsplit(url).scheme,
             'subscription_rules_and_dns_imported':False}
    report=work/'summary.json'
    report.write_text(json.dumps(summary,indent=2)+'\n');report.chmod(0o600)
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subscription-file',type=Path,required=True)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--work-dir',type=Path,default=ROOT/'.build/subscription-check')
    parser.add_argument('--allow-http',action='store_true')
    args=parser.parse_args()
    try:
        result=check_subscription(args.subscription_file.read_text().strip(),args.binary.resolve(),
                                  args.work_dir.resolve(),args.allow_http)
        print(json.dumps(result,indent=2))
    except (ValueError,OSError,subprocess.SubprocessError,yaml.YAMLError) as exc:
        # Exception bodies may contain a private URL or a native parser's node
        # mapping; do not echo them into build logs.
        status=exc.code if isinstance(exc,urllib.error.HTTPError) else None
        print(json.dumps({'private_subscription_check':'FAILED','error_type':type(exc).__name__,'http_status':status}),file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(main())
