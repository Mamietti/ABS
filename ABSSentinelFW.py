from scapy.all import *
from netfilterqueue import NetfilterQueue
import sys
from multiprocessing import Process, Manager
from MathABS import ABS
from charm.toolbox.pairinggroup import PairingGroup
import socketserver
import socket
import json
import threading
from charm.toolbox.securerandom import OpenSSLRand

def print_and_accept(pkt):
    a = IP(pkt.get_payload())
    if a[IP][TCP].dport == 80:
        source,dest = a[IP].src, a[IP].dst
        host = 0
        port = 0
        #print(a[IP].src,a[IP].dst)
        #print(clientlist)
        #print(networkalias)
        #print(checklist)
        try:
            port = clientlist[networkalias[source]]
            host = networkalias[source]
        except Exception:
            try:
                port = clientlist[networkalias[dest]]
                host = networkalias[dest]
            except Exception:
                pkt.accept()
            else:
                if source in iplist:
                    pkt.accept()
                else:
                    triple = (host,port,source)
                    if triple not in checklist:
                        print('FIREWALL: unknown source',source)
                        checklist.append(triple)
                    else:
                        pkt.drop()
        else:
            if dest in iplist:
                pkt.accept()
            else:
                triple = (host,port,dest)
                if triple not in checklist:
                    print('FIREWALL: unknown destination',dest)
                    checklist.append(triple)
                else:
                    pkt.drop()
    else:
        pkt.accept()

def FWsubprocess():
    try:
        nfqueue = NetfilterQueue()
        nfqueue.bind(0,print_and_accept)
        nfqueue.run()
    except KeyboardInterrupt:
        nfqueue.unbind()

def checkprotocol(host,port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host,int(port)))
        print('WATCHDOG: Connected to client {}:{}'.format(host,port))
        nonce = str(OpenSSLRand().getRandomBytes(20))[2:].replace("\\x","")
        stuple = (nonce,accesspolicy)
        sock.sendall(bytes(json.dumps(stuple),'utf8'))
        print('WATCHDOG: Sent nonce {} and policy {}'.format(nonce,accesspolicy))

        data = sock.recv(hugeness).strip()
        msg = data.decode('utf-8')
        signature = absinst.decodestr(msg)
        judgement = absinst.verify((tpk,apk),signature,nonce,accesspolicy)

        sock.sendall(bytes(str(judgement),'utf-8'))
        print('WATCHDOG: Sent judgement', judgement)
        return judgement
    except Exception as err:
        print(err)
    sock.close()


class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.data = self.request.recv(hugeness).strip()
            msg = self.data.decode('utf-8')
            host,port = self.client_address[0],self.client_address[1]
            print('SERVER: received from {}:{} attributes'.format(host,port),msg)

            content = msg.split(",")
            netalias = content[0]
            ska = absinst.generateattributes(ask,content[1:])
            striple = (absinst.encodestr(tpk),absinst.encodestr(apk),absinst.encodestr(ska))
            self.request.sendall(bytes(json.dumps(striple),'utf8'))
            clientlist[host] = port
            networkalias[netalias] = host
            print('SERVER: keys sent, client {}:{} added to list with netalias {}'.format(host,port, netalias))
        except Exception as err:
            print('SERVER: MISERABLE FAILURE:',err)

class ThreadedTCPServer(socketserver.ThreadingMixIn,socketserver.TCPServer):
    pass

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
    networkalias = valuemanager.dict()
    checklist = valuemanager.list()

    group = PairingGroup('SS512')
    absinst = ABS(group)
    tpk = absinst.trusteesetup(attributes)
    ask,apk = absinst.authoritysetup(tpk)

    #os.system("sudo iptables -A OUTPUT -p tcp -j NFQUEUE")
    fwp = Process(target = FWsubprocess)
    fwp.start()
    print('FIREWALL: READY')

    hugeness = 8000

    host,port = 'localhost',0
    #server = socketserver.TCPServer((host,port), MyTCPHandler)
    server = ThreadedTCPServer((host,port),MyTCPHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print('SERVER: READY, port',server.server_address[1])
    #server.serve_forever()

    while True:
        if len(checklist)>0:
            host,port,ip = checklist.pop(0)
            if checkprotocol(host,port):
                print('WATCHDOG: APPENDED',ip,'TO IPLIST')
                iplist.append(ip)


except KeyboardInterrupt:
    fwp.join()
    server.shutdown()
