from scapy.all import *
from netfilterqueue import NetfilterQueue
import sys
from multiprocessing import Process, Manager
from MathABS import ABS
from charm.toolbox.pairinggroup import PairingGroup
import socketserver
import socket
import json
from charm.toolbox.securerandom import OpenSSLRand

def print_and_accept(pkt):
    a = IP(pkt.get_payload())
    if a[IP][TCP].dport == 80:
        source,dest = a[IP].src, a[IP].dst
        host = 0
        port = 0
        print(clientlist)
        try:
            port = clientlist[source]
            host = source
        except Exception:
            try:
                port = clientlist[dest]
                host = dest
            except Exception:
                pkt.accept()
            else:
                if checkprotocol(host,port):
                    iplist.append(a[IP].src)
                    print('FIREWALL: whitelist changed to ',iplist)
                    pkt.accept()
                else:
                    pkt.drop()
        else:
            if checkprotocol(host,port):
                iplist.append(a[IP].src)
                print('FIREWALL: whitelist changed to ',iplist)
                pkt.accept()
            else:
                pkt.drop()
    else:
        pkt.accept()

def checkprotocol(host,port):
    sock.connect((host,port))
    print('FIREWALL: Connected to client {}:{}'.format(host,port))
    nonce = str(OpenSSLRand().getRandomBytes(20))[2:].replace("\\x","")
    stuple = (nonce,accesspolicy)
    sock.sendall(bytes(json.dumps(stuple),'utf8'))
    print('FIREWALL: Sent nonce {} and policy {}'.format(nonce,accesspolicy))

    data = sock.recv(hugeness).strip()
    msg = data.decode('utf-8')
    signature = absinst.decodestr(msg)
    judgement = absinst.verify((tpk,apk),signature,nonce,accesspolicy)
    print('FIREWALL: Received and decoded signature as',judgement)

    return absinst.verify((tpk,apk),signature,nonce,accesspolicy)

def FWsubprocess():
    try:
        nfqueue = NetfilterQueue()
        nfqueue.bind(0,print_and_accept)
        nfqueue.run()
    except KeyboardInterrupt:
        nfqueue.unbind()

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.data = self.request.recv(hugeness).strip()
            msg = self.data.decode('utf-8')
            host,port = self.client_address[0],self.client_address[1]
            print('SERVER: received from {}:{} attributes'.format(host,port),msg)

            ska = absinst.generateattributes(ask,msg.split(","))
            striple = (absinst.encodestr(tpk),absinst.encodestr(apk),absinst.encodestr(ska))
            self.request.sendall(bytes(json.dumps(striple),'utf8'))
            clientlist[host] = port
            print('SERVER: keys sent, client {}:{} added to list'.format(host,port))
        except Exception as err:
            print('SERVER: MISERABLE FAILURE:',err)

try:
    attributes = [
        'MOTIVATED',
        'SKILLFUL',
        'ECCENTRIC',
        'LAZY',
        'VIOLENT'
    ]
    print('SERVER: ATTRIBUTE TABLE: ',attributes)
    accesspolicy = '(SKILLFUL AND MOTIVATED) OR ECCENTRIC'

    valuemanager = Manager()
    iplist = valuemanager.list()
    clientlist = valuemanager.dict()
    #os.system("sudo iptables -A OUTPUT -p tcp -j NFQUEUE")
    fwp = Process(target = FWsubprocess)
    fwp.start()
    print('FIREWALL: READY')

    group = PairingGroup('SS512')
    absinst = ABS(group)
    tpk = absinst.trusteesetup(attributes)
    ask,apk = absinst.authoritysetup(tpk)

    hugeness = 6000

    host,port = 'localhost',0
    server = socketserver.TCPServer((host,port), MyTCPHandler)
    print('SERVER: READY, port',server.server_address[1])
    server.serve_forever()
except KeyboardInterrupt:
    fwp.join()
    server.shutdown()
