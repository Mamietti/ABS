from scapy.all import *
from netfilterqueue import NetfilterQueue
import sys
from multiprocessing import Process, Manager
from MathABS import ABS
from charm.toolbox.pairinggroup import PairingGroup
import socketserver
import json
from charm.toolbox.securerandom import OpenSSLRand

def print_and_accept(pkt):
    a = IP(pkt.get_payload())
    #print(a[IP][TCP].sport,a[IP][TCP].dport)
    if a[IP][TCP].dport == 80:
        if a[IP].src not in iplist:
            if checkprotocol():
                iplist.append(a[IP].src)
                print('FIREWALL: List changed to ',iplist)
                pkt.accept()
            else:
                pkt.drop()
        elif a[IP].dst not in iplist:
            if checkprotocol():
                iplist.append(a[IP].dst)
                print('FIREWALL: List changed to ',iplist)
                pkt.accept()
            else:
                pkt.drop()
        else:
            pkt.accept()
    else:
        pkt.accept()

def checkprotocol():
    return True

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
            print('SERVER: RECEIVED TESTCASE ATTRIBUTES',msg)

            ska = absinst.generateattributes(ask,msg.split(","))
            striple = (absinst.encodestr(tpk),absinst.encodestr(apk),absinst.encodestr(ska))
            self.request.sendall(bytes(json.dumps(striple),'utf8'))
            print('SERVER: TESTCASE SKA GENERATED AND SENT, READY TO RECEIVE!')

            self.data = self.request.recv(hugeness).strip()
            msg = self.data.decode('utf-8')
            site = msg.split(':')[1]
            print('{}:{} wants to connect to {}'.format(self.client_address[0],self.client_address[1],site))

            policy = accesspolicies[site]
            nonce = str(OpenSSLRand().getRandomBytes(20))[2:].replace("\\x","")
            stuple = (nonce,policy)
            self.request.sendall(bytes(json.dumps(stuple),'utf8'))
            print('SERVER: Sent nonce {} and policy {}'.format(nonce,policy))

            self.data = self.request.recv(hugeness).strip()
            msg = self.data.decode('utf-8')
            signature = absinst.decodestr(msg)
            print('SERVER: Received and decoded signature')

            judgement = 'DENIED'
            if absinst.verify((tpk,apk),signature,nonce,policy):
                judgement = 'OK'
            self.request.sendall(bytes(judgement,'utf-8'))
            print('SERVER: Sent judgement', judgement, '\n')
        except Exception as err:
            print(err)
            print('SERVER: MISERABLE FAILURE')

try:
    valuemanager = Manager()
    iplist = valuemanager.list()
    #os.system("sudo iptables -A OUTPUT -p tcp -j NFQUEUE")
    fwp = Process(target = FWsubprocess)
    fwp.start()
    print('FIREWALL: READY')

    attributes = [
        'MOTIVATED',
        'SKILLFUL',
        'ECCENTRIC',
        'LAZY',
        'VIOLENT'
    ]
    print('SERVER: ATTRIBUTE TABLE: ',attributes)

    group = PairingGroup('SS512')
    absinst = ABS(group)
    tpk = absinst.trusteesetup(attributes)
    ask,apk = absinst.authoritysetup(tpk)

    hugeness = 6000

    accesspolicies = {'www.vtt.fi': '(SKILLFUL AND MOTIVATED) OR ECCENTRIC'}

    host,port = 'localhost',0
    server = socketserver.TCPServer((host,port), MyTCPHandler)
    print('SERVER: READY, port',server.server_address[1])
    server.serve_forever()
except KeyboardInterrupt:
    fwp.join()
    server.shutdown()
