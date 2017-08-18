from MathABS import ABS
from charm.toolbox.pairinggroup import PairingGroup
import socketserver
import json
from charm.toolbox.securerandom import OpenSSLRand
from time import sleep
import socket
import sys
import subprocess
import os

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            nonce,policy = json.loads(str(self.request.recv(hugeness),'utf-8'))
            print('Received nonce {} and policy {}'.format(nonce,policy))

            lam = testinst.sign((tpk,apk), ska, nonce, policy)
            self.request.sendall(bytes(testinst.encodestr(lam),'utf-8'))
            print('Sent created signature from nonce and policy')
            print('Received judgement:',str(self.request.recv(hugeness),'utf-8'),'\n')
        except Exception as err:
            print(err)
            print('MISERABLE FAILURE')

try:
    try:
        host,port,netalias = sys.argv[1],int(sys.argv[2]),sys.argv[3]
    except IndexError:
        print("Format: ABSClient.py serverhost serverport networkalias")
        exit()

    hugeness = 8000

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

    group = PairingGroup('SS512')
    testinst = ABS(group)
    sock.connect((host,port))
    myhost,myport = sock.getsockname()
    print('Connected to server')

    outputlist = []
    location = '{}/.mozilla/firefox/'.format(os.environ['HOME'])
    for i in os.listdir(location):
        if i.endswith('.default'):
            add = os.path.join(location+i,'extensions.json')
            with open(add) as filex:
                data = json.load(filex)
                for i in data['addons']:
                    if i['active']:
                        outputlist.append(i['defaultLocale']['name'])

    sock.sendall(bytes("{},{}".format(netalias,",".join(outputlist)),'utf-8'))
    print('SENT MOZILLA EXTENSIONS FOR TEST CASE')

    tpk,apk,ska = json.loads(str(sock.recv(hugeness),'utf-8'))
    tpk = testinst.decodestr(tpk)
    apk = testinst.decodestr(apk)
    ska = testinst.decodestr(ska)
    print('TEST CASE TPK, APK AND SIGNING KEY RECEIVED, READY TO ROLL!')
    sock.close()
    sleep(1)

    server = socketserver.TCPServer((myhost,myport), MyTCPHandler)
    print(server.server_address[0],server.server_address[1])
    server.serve_forever()

except KeyboardInterrupt:
    try:
        server.shutdown()
    except NameError:
        print('\nayy lmao')
