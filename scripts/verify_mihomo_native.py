#!/usr/bin/env python3
"""Run native Mihomo against loopback-only DNS/node/origin fixtures.

Never changes system routes/DNS or a router. Uses no real nodes or Internet
destinations. The staged copy replaces DNS transports by local TCP fixtures and
adds a synthetic CN-IP witness (127.0.0.1/32). Thus it verifies routing/DNS/failure
mechanics, NOT public DoH TLS, VLESS authentication, or transparent LAN routing.
"""
import argparse
from contextlib import ExitStack
import copy
import json
from pathlib import Path
import secrets
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

import yaml
from check_mihomo import load_yaml

ROOT = Path(__file__).resolve().parents[1]


def exact(sock, count):
    data = b''
    while len(data) < count:
        part = sock.recv(count-len(data))
        if not part:
            raise EOFError('fixture connection closed')
        data += part
    return data


def dns_packet(name, kind=16):
    query_id = secrets.randbits(16)
    qname = b''.join(bytes([len(s)])+s.encode() for s in name.split('.'))+b'\0'
    return struct.pack('!HHHHHH', query_id, 0x100, 1, 0, 0, 0)+qname+struct.pack('!HH',kind,1)


def dns_question(packet):
    pos, labels = 12, []
    while packet[pos]:
        count = packet[pos]
        labels.append(packet[pos+1:pos+1+count].decode())
        pos += count+1
    pos += 1
    return '.'.join(labels), struct.unpack_from('!H',packet,pos)[0], pos+4


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.events = []
        self.node_enabled = True
        self.live_dns = {'local','proxy1','proxy2','bootstrap'}
        self.subscription = {}
        self.subscription_mode = 'valid'

    def record(self, **event):
        with self.lock:
            self.events.append(event)

    def snapshot(self):
        with self.lock:
            return list(self.events)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, address):
        # Client-side failure probes deliberately close incomplete handshakes.
        error=sys.exc_info()[1]
        if isinstance(error,(EOFError,ConnectionError,TimeoutError)):
            self.state.record(kind='fixture-connection-closed', server=self.label)
        else:
            self.state.record(kind='fixture-error',server=self.label,error_type=type(error).__name__)
            super().handle_error(request,address)


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet = exact(self.request, struct.unpack('!H',exact(self.request,2))[0])
        name, kind, end = dns_question(packet)
        state = self.server.state
        state.record(kind='dns', resolver=self.server.label, name=name, qtype=kind)
        if self.server.label not in state.live_dns:
            return
        if kind == 1:
            answer = socket.inet_aton('127.0.0.2' if 'unknown-foreign' in name else '127.0.0.1')
        elif kind == 28:
            answer = socket.inet_pton(socket.AF_INET6,'::1')
        elif kind == 16:
            answer = bytes([len(self.server.label)])+self.server.label.encode()
        else:
            answer = None
        header = packet[:2]+struct.pack('!HHHHH',0x8180,1,int(answer is not None),0,0)
        response = header+packet[12:end]
        if answer is not None:
            response += b'\xc0\x0c'+struct.pack('!HHIH',kind,1,0,len(answer))+answer
        self.request.sendall(struct.pack('!H',len(response))+response)


class OriginHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        self.request.recv(8192)
        self.server.state.record(kind='direct-http')
        self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDIRECT')


class NodeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock, state = self.request, self.server.state
        sock.settimeout(8)
        version, count = exact(sock,2)
        if version != 5:
            raise ValueError('SOCKS5 required')
        exact(sock,count)
        sock.sendall(b'\x05\x00')
        version, command, _, family = exact(sock,4)
        if family == 1:
            host = socket.inet_ntoa(exact(sock,4))
        elif family == 3:
            host = exact(sock,exact(sock,1)[0]).decode()
        elif family == 4:
            host = socket.inet_ntop(socket.AF_INET6,exact(sock,16))
        else:
            raise ValueError('Unknown SOCKS address')
        port = struct.unpack('!H',exact(sock,2))[0]
        state.record(kind='node-connect', host=host, port=port)
        if command != 1 or not state.node_enabled:
            sock.sendall(b'\x05\x01\x00\x01'+bytes(6))
            return
        sock.sendall(b'\x05\x00\x00\x01'+bytes(6))
        if host == '127.0.0.1' and port in self.server.dns_ports:
            # The only fixture forwarding is to an explicitly allowed loopback
            # resolver. Never dial arbitrary names/IPs from a test request.
            with socket.create_connection((host,port),timeout=5) as upstream:
                packet = exact(sock,struct.unpack('!H',exact(sock,2))[0])
                upstream.sendall(struct.pack('!H',len(packet))+packet)
                size = struct.unpack('!H',exact(upstream,2))[0]
                response = exact(upstream,size)
                sock.sendall(struct.pack('!H',size)+response)
        else:
            sock.recv(8192)
            state.record(kind='proxy-http', host=host)
            sock.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nPROXY')


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        self.server.state.record(kind='direct-udp', payload=data.decode(errors='replace'))
        sock.sendto(data,self.client_address)


class SubscriptionHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        self.request.recv(8192)
        state=self.server.state
        state.record(kind='node-subscription-fetch',mode=state.subscription_mode)
        if state.subscription_mode=='malformed':
            body=b'not a proxy subscription'
        elif state.subscription_mode=='empty':
            body=b'proxies: []\n'
        else:
            body=yaml.safe_dump(state.subscription,sort_keys=False).encode()
        self.request.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()
                             +b'\r\nConnection: close\r\n\r\n'+body)


def serve(stack, state, label, handler, udp=False):
    cls = socketserver.ThreadingUDPServer if udp else Server
    server = cls(('127.0.0.1',0),handler)
    server.state, server.label = state,label
    thread = threading.Thread(target=server.serve_forever,daemon=True)
    thread.start()
    stack.callback(server.server_close)
    stack.callback(server.shutdown)
    return server


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def socks_connect(port, host, target_port):
    sock = socket.create_connection(('127.0.0.1',port),timeout=7)
    sock.settimeout(7)
    sock.sendall(b'\x05\x01\x00')
    assert exact(sock,2) == b'\x05\x00'
    encoded = host.encode()
    sock.sendall(b'\x05\x01\x00\x03'+bytes([len(encoded)])+encoded+struct.pack('!H',target_port))
    response = exact(sock,10)
    assert response[1] == 0, response
    return sock


def http_probe(port, host, target_port):
    try:
        with socks_connect(port,host,target_port) as sock:
            sock.sendall(f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
            response=b''
            while True:
                part=sock.recv(8192)
                if not part:
                    break
                response+=part
        if not response.startswith(b'HTTP/1.1 200 OK\r\n'):
            return 'FAILED'
        return response.split(b'\r\n\r\n',1)[-1].decode()
    except (OSError, EOFError) as exc:
        print(f'HTTP fixture probe {host}: {type(exc).__name__}: {exc}', flush=True)
        return 'FAILED'


def dns_probe(port,name):
    packet=dns_packet(name)
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(7)
            sock.sendto(packet,('127.0.0.1',port))
            response=sock.recv(4096)
        assert response[:2] == packet[:2]
        return response[3]&15
    except socket.timeout:
        return 'TIMEOUT'


def udp_probe(port,host,target_port):
    with socket.create_connection(('127.0.0.1',port),timeout=4) as control:
        control.settimeout(4)
        control.sendall(b'\x05\x01\x00')
        assert exact(control,2)==b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01'+bytes(6))
        reply=exact(control,10)
        assert reply[:4]==b'\x05\x00\x00\x01',reply
        udp_port=struct.unpack('!H',reply[8:10])[0]
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            name=host.encode()
            packet=b'\0\0\0\x03'+bytes([len(name)])+name+struct.pack('!H',target_port)+b'udp-witness'
            sock.sendto(packet,('127.0.0.1',udp_port))
            try:
                return bool(sock.recv(4096))
            except socket.timeout:
                return False


def verify(binary, bundle, work):
    work.mkdir(parents=True,exist_ok=True)
    (work/'result.json').unlink(missing_ok=True)
    state=State()
    outcomes=[]
    def passed(name,condition):
        if not condition:
            (work/'failed-events.json').write_text(json.dumps(state.snapshot(),indent=2)+'\n')
            raise AssertionError(name)
        outcomes.append({'check':name,'passed':True})
    with ExitStack() as stack:
        resolvers={name:serve(stack,state,name,DNSHandler) for name in ('local','proxy1','proxy2','bootstrap')}
        origin=serve(stack,state,'origin',OriginHandler)
        echo=serve(stack,state,'echo',EchoHandler,True)
        node=serve(stack,state,'node',NodeHandler)
        subscription=serve(stack,state,'subscription',SubscriptionHandler)
        node.dns_ports={s.server_address[1] for s in resolvers.values()}
        staged=work/'profile'
        # Fixtures use new ephemeral ports each run; a previous run's cached
        # HTTP provider would correctly remain valid for its 1h interval but
        # point to a stopped fixture. Always start this isolated copy cold.
        if staged.exists():
            shutil.rmtree(staged)
        shutil.copytree(bundle,staged)
        config=load_yaml(staged/'Mihomo.yaml')
        config['rule-providers']['china-ip']['payload'].append('IP-CIDR,127.0.0.1/32')
        mixed,dns_port,controller=free_port(),free_port(),free_port()
        token=secrets.token_hex(16)
        config.update({'mixed-port':mixed,'external-controller':f'127.0.0.1:{controller}',
                       'secret':token,'log-level':'debug'})
        config['dns']['listen']=f'127.0.0.1:{dns_port}'
        state.subscription={
            'proxies':[{'name':'fixture-node','type':'socks5','server':'node-bootstrap.test',
                        'port':node.server_address[1],'udp':False}],
            # These mimic a full 3x-ui response and must NEVER be imported by a
            # node provider: only its `proxies` field belongs to the subscription.
            'rules':['MATCH,DIRECT'], 'mode':'global',
            'dns':{'enable':False,'nameserver':['192.0.2.123']},
            'proxy-groups':[{'name':'PROXY','type':'select','proxies':['DIRECT']}],
        }
        config['proxies']=[]
        config['proxy-providers']={'nodes':{'type':'http',
            'url':f'http://subscription-bootstrap.test:{subscription.server_address[1]}/mihomo/fixture',
            'path':'./proxy_provider/nodes.private.yaml','interval':3600,'proxy':'DIRECT',
            'health-check':{'enable':False}}}
        config['proxy-groups'][0]['use']=['nodes']
        def endpoint(name,via):
            return f'tcp://127.0.0.1:{resolvers[name].server_address[1]}#{via}'
        proxy=[endpoint('proxy1','PROXY'),endpoint('proxy2','PROXY')]
        config['dns']['nameserver']=proxy
        config['dns']['direct-nameserver']=proxy
        config['dns']['default-nameserver']=[endpoint('bootstrap','DIRECT')]
        config['dns']['proxy-server-nameserver']=[endpoint('bootstrap','DIRECT')]
        for name in config['dns']['nameserver-policy']:
            config['dns']['nameserver-policy'][name]=([endpoint('local','DIRECT')]
                if name.split(':')[1] in ('lan','local-names','reviewed-direct','regional','direct') else proxy)
        config['dns']['nameserver-policy']={'subscription-bootstrap.test':[endpoint('bootstrap','DIRECT')],
                                           **config['dns']['nameserver-policy']}
        config_path=staged/'fixture.yaml'
        def api(path,method='GET',body=None):
            data=json.dumps(body).encode() if body is not None else (b'' if method=='PUT' else None)
            request=urllib.request.Request(f'http://127.0.0.1:{controller}'+path,data=data,method=method,
                headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
            try:
                with urllib.request.urlopen(request,timeout=8) as response:
                    content=response.read()
                    return response.status,json.loads(content) if content else None
            except urllib.error.HTTPError as error:
                return error.code,None
        def run_core(label):
            config_path.write_text(yaml.safe_dump(config,sort_keys=False,allow_unicode=True))
            log=(work/f'{label}.log').open('wb')
            process=subprocess.Popen([str(binary),'-d',str(staged),'-f',str(config_path)],stdout=log,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                if process.poll() is not None:
                    log.close()
                    raise AssertionError(f'Native core exited: {label}; inspect its log')
                try:
                    headers={'Authorization':'Bearer '+token}
                    request=urllib.request.Request(f'http://127.0.0.1:{controller}/version',headers=headers)
                    with urllib.request.urlopen(request,timeout=1) as response:
                        version=json.load(response)
                    request=urllib.request.Request(f'http://127.0.0.1:{controller}/providers/rules',headers=headers)
                    with urllib.request.urlopen(request,timeout=1) as response:
                        loaded=json.load(response)['providers']
                    if all(loaded.get(name,{}).get('ruleCount',0)>0 for name in config['rule-providers']):
                        # ApplyConfig opens its API/listeners before finishing
                        # providers, GC and tunnel.OnRunning(). Wait on a separate
                        # loopback-IP readiness probe, not a domain-policy test.
                        if http_probe(mixed,'127.0.0.1',origin.server_address[1])=='DIRECT':
                            status,nodes=api('/providers/proxies/nodes')
                            names=[n['name'] for n in nodes['proxies']]
                            if not names:
                                time.sleep(.1)
                                continue
                            status,_=api('/proxies/PROXY','PUT',{'name':names[0]})
                            assert status==204
                            return process,log,version
                except (OSError,ValueError):
                    time.sleep(.1)
            process.terminate();process.wait(timeout=10);log.close()
            raise AssertionError('Native core did not become ready')
        process,log,version=run_core('guarded')
        try:
            for host,wanted in [('www.baidu.com','DIRECT'),('claude.ai','PROXY'),
                                ('unknown-cn.test','DIRECT'),('unknown-foreign.test','PROXY')]:
                actual=http_probe(mixed,host,origin.server_address[1])
                passed('native HTTP routing '+host+f' (observed {actual!r})',actual==wanted)
            before=len(state.snapshot())
            passed('TCP DNS port guard rejects before domain DIRECT policy',http_probe(mixed,'www.baidu.com',53)=='FAILED')
            passed('DNS guard sent no request to direct origin',not any(e['kind']=='direct-http' for e in state.snapshot()[before:]))
            name=secrets.token_hex(6)+'.ipv6-disabled.test'
            before=len(state.snapshot())
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.settimeout(5)
                sock.sendto(dns_packet(name,28),('127.0.0.1',dns_port))
                answer=sock.recv(4096)
            passed('IPv4 baseline returns no AAAA answer',struct.unpack_from('!H',answer,6)[0]==0)
            passed('disabled AAAA never reaches any upstream',not any(e.get('name')==name for e in state.snapshot()[before:]))
            passed('subscription hostname independently bootstrapped',any(e.get('resolver')=='bootstrap' and e.get('name')=='subscription-bootstrap.test' for e in state.snapshot()))
            passed('complete subscription cannot override reviewed rules or DNS',api('/configs')[1]['mode']=='rule')
            original_nodes=[n['name'] for n in api('/providers/proxies/nodes')[1]['proxies']]
            for mode in ('malformed','empty'):
                state.subscription_mode=mode
                passed('invalid node subscription update rejected: '+mode,api('/providers/proxies/nodes','PUT')[0]==503)
                passed('last valid nodes retained: '+mode,
                       [n['name'] for n in api('/providers/proxies/nodes')[1]['proxies']]==original_nodes)
                passed('protected routing survives bad node update: '+mode,
                       http_probe(mixed,'claude.ai',origin.server_address[1])=='PROXY')
            state.subscription_mode='valid'
            state.subscription['proxies'][0]['name']='fixture-node-v2'
            passed('valid node-only subscription update accepted',api('/providers/proxies/nodes','PUT')[0]==204)
            names=[n['name'] for n in api('/providers/proxies/nodes')[1]['proxies']]
            passed('new node appears without replacing public rule policy',names==['fixture-node-v2'])
            passed('updated node can be explicitly selected',api('/proxies/PROXY','PUT',{'name':names[0]})[0]==204)
            passed('updated subscription node still follows protected rules',http_probe(mixed,'claude.ai',origin.server_address[1])=='PROXY')
            passed('node hostname independently bootstrapped',any(e.get('resolver')=='bootstrap' and e.get('name')=='node-bootstrap.test' for e in state.snapshot()))
            for suffix,wanted in [('baidu.com','local'),('claude.ai','proxy'),('unknown-dns.test','proxy')]:
                name=secrets.token_hex(6)+'.'+suffix
                before=len(state.snapshot())
                passed('DNS answer '+suffix,dns_probe(dns_port,name)==0)
                seen=[e for e in state.snapshot()[before:] if e.get('kind')=='dns' and e.get('name')==name]
                passed('DNS selected path '+suffix,bool(seen) and all(e['resolver'].startswith(wanted) for e in seen))
            state.live_dns.remove('proxy1')
            name=secrets.token_hex(6)+'.unknown-primary-failed.test'
            passed('one proxy resolver failed, other still answers',dns_probe(dns_port,name)==0)
            state.live_dns.remove('proxy2')
            before=len(state.snapshot()); name=secrets.token_hex(6)+'.unknown-both-failed.test'
            passed('all proxy DNS failed without system fallback',dns_probe(dns_port,name)!=0)
            passed('failed proxy DNS never queried local resolver',not any(e.get('resolver')=='local' and e.get('name')==name for e in state.snapshot()[before:]))
            passed('DIRECT HTTP survives proxy DNS outage',http_probe(mixed,'www.baidu.com',origin.server_address[1])=='DIRECT')
            state.live_dns.update(('proxy1','proxy2'))
            state.node_enabled=False
            before=len(state.snapshot())
            passed('proxy node failure rejects protected HTTP',http_probe(mixed,'claude.ai',origin.server_address[1])=='FAILED')
            passed('protected HTTP never reaches DIRECT origin on node failure',not any(e['kind']=='direct-http' for e in state.snapshot()[before:]))
            passed('DIRECT HTTP survives node outage',http_probe(mixed,'www.baidu.com',origin.server_address[1])=='DIRECT')
            before=len(state.snapshot()); name=secrets.token_hex(6)+'.unknown-node-failed.test'
            passed('node failure prevents proxy DNS answer',dns_probe(dns_port,name)!=0)
            passed('node outage never queries local DNS for unknown name',not any(e.get('resolver')=='local' and e.get('name')==name for e in state.snapshot()[before:]))
            state.node_enabled=True
            before=len(state.snapshot())
            passed('unsupported UDP is rejected',not udp_probe(mixed,'claude.ai',echo.server_address[1]))
            passed('unsupported UDP did not reach DIRECT origin',not any(e['kind']=='direct-udp' for e in state.snapshot()[before:]))
        finally:
            process.terminate(); process.wait(timeout=10);log.close()
        # A negative control demonstrates that the guard, not a broken UDP test
        # fixture, prevents a protected name from falling through to CN DIRECT.
        config['rules']=[r for r in config['rules'] if not r.startswith('AND,((NETWORK,udp),')]
        process,log,_=run_core('unguarded-negative-control')
        try:
            before=len(state.snapshot())
            udp_probe(mixed,'claude.ai',echo.server_address[1])
            passed('negative control exposes unsupported UDP falling into CN DIRECT',any(e['kind']=='direct-udp' for e in state.snapshot()[before:]))
        finally:
            process.terminate();process.wait(timeout=10);log.close()
        passed('fixture produced no unexpected handler errors',not any(e['kind']=='fixture-error' for e in state.snapshot()))
    result={'native_core':version,'checks':outcomes,'failures':0,
            'scope':__doc__,'real_vless_node':'NOT_CONFIGURED','router_proxy':'NOT_ENABLED'}
    (work/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--bundle',type=Path,default=ROOT/'dist/mihomo')
    parser.add_argument('--work-dir',type=Path,default=ROOT/'.build/mihomo-native')
    args=parser.parse_args()
    result=verify(args.binary.resolve(),args.bundle.resolve(),args.work_dir.resolve())
    print(json.dumps({'native_core':result['native_core'],'checks':len(result['checks']),'failures':0,
                      'real_vless_node':'NOT_CONFIGURED','router_proxy':'NOT_ENABLED'},indent=2))


if __name__=='__main__':
    main()
