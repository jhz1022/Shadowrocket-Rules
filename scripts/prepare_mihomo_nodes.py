#!/usr/bin/env python3
"""Prepare a LOCAL private node-provider file, never change a router or fetch it.

Reads the subscription URL from a private file, not a command-line argument.
The 3x-ui /mihomo/<sub-id> response is consumed as nodes only. Public routing,
DNS, groups or DIRECT choices in that response are not imported.
"""
import argparse
import ipaddress
import os
from pathlib import Path
import tempfile
from urllib.parse import urlsplit

from mihomo import yaml_bytes

ROOT=Path(__file__).resolve().parents[1]


def provider_config(url, allow_http=False):
    if not isinstance(url, str) or any(c.isspace() for c in url):
        raise ValueError('Subscription must be one absolute HTTPS URL')
    parsed=urlsplit(url)
    schemes=('https','http') if allow_http else ('https',)
    if parsed.scheme not in schemes or not parsed.hostname or parsed.fragment or parsed.username or parsed.password:
        raise ValueError('Subscription must use an explicitly allowed scheme without inline basic-auth or fragment')
    if '/clash-legacy/' in parsed.path:
        raise ValueError('VLESS needs the Mihomo endpoint, not clash-legacy')
    return {'proxy-providers': {'nodes': {
        'type':'http', 'url':url, 'path':'./proxy_provider/nodes.private.yaml',
        'interval':3600, 'proxy':'DIRECT', 'size-limit':16*1024*1024,
        'health-check':{'enable':False}, 'header':{'User-Agent':['mihomo']},
    }}}


def module_content(url, root=ROOT):
    # Node-subscription fetching must bootstrap before any proxy nodes exist.
    # This is a narrow, explicit control-plane hostname exception, never a
    # catch-all/system DNS fallback for ordinary unknown/proxy destinations.
    host=urlsplit(url).hostname
    bootstrap=['https://223.5.5.5/dns-query#DIRECT','https://223.6.6.6/dns-query#DIRECT']
    try:
        ipaddress.ip_address(host)
        fragment=''
    except ValueError:
        fragment=yaml_bytes({'dns':{'+nameserver-policy':{host:bootstrap}}}).decode().split('\n',1)[1].rstrip()
    template=(root/'config/openclash-local-nodes.ini').read_text()
    return template.replace('# NODE_SUBSCRIPTION_BOOTSTRAP_POLICY',fragment).encode()


def write_private(path, data):
    if not path.name.endswith(('.private.yaml','.private.yml','.private.ini')):
        raise ValueError('Private output must end in .private.yaml, .private.yml or .private.ini')
    path.parent.mkdir(parents=True,exist_ok=True)
    fd,temp=tempfile.mkstemp(prefix='.'+path.name,dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(data)
            stream.flush();os.fsync(stream.fileno())
        os.chmod(temp,0o600)
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--subscription-file',type=Path,required=True)
    parser.add_argument('--output',type=Path,default=Path('.build/nodes.private.yaml'))
    parser.add_argument('--module-output',type=Path,default=Path('.build/nodes.private.ini'))
    parser.add_argument('--allow-http',action='store_true',help='Only for an explicitly authorized existing HTTP subscription')
    args=parser.parse_args()
    url=args.subscription_file.read_text().strip()
    value=provider_config(url,args.allow_http)
    module=module_content(url)
    write_private(args.output,yaml_bytes(value))
    write_private(args.module_output,module)
    print('Prepared private provider and local module, mode 0600. No URL printed, fetched or deployed.')


if __name__=='__main__':
    main()
