from MathABS import ABS
from charm.toolbox.pairinggroup import PairingGroup
import socketserver
import json
from charm.toolbox.securerandom import OpenSSLRand
import socket
import sys

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            nonce,policy = json.loads(str(sock.recv(hugeness),'utf-8'))
            print('Received nonce {} and policy {}'.format(nonce,policy))

            lam = testinst.sign((tpk,apk), ska, nonce, policy)
            sock.sendall(bytes(testinst.encodestr(lam),'utf-8'))
            print('Sent created signature from nonce and policy')
            print('Received judgement:',str(sock.recv(hugeness),'utf-8'),'\n')
            sock.close()
        except Exception as err:
            print(err)
            print('MISERABLE FAILURE')

try:
    try:
        host,port = sys.argv[1],int(sys.argv[2])
    except IndexError:
        print("Format: ABSClient.py serverhost serverport attrib1 attrib2 ...")
        exit()

    hugeness = 6000

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    group = PairingGroup('SS512')
    testinst = ABS(group)
    sock.connect((host,port))
    myhost,myport = sock.getsockname()
    print('Connected to server')

    sock.sendall(bytes(",".join(sys.argv[3:]),'utf-8'))
    print('SENT ATTRIBUTES FOR TEST CASE')

    tpk,apk,ska = json.loads(str(sock.recv(hugeness),'utf-8'))
    tpk = testinst.decodestr(tpk)
    apk = testinst.decodestr(apk)
    ska = testinst.decodestr(ska)
    print('TEST CASE TPK, APK AND SIGNING KEY RECEIVED, READY TO ROLL!')
    sock.close()

    server = socketserver.TCPServer((myhost,myport), MyTCPHandler)
    print(server.server_address[0],server.server_address[1])
    server.serve_forever()
except KeyboardInterrupt:
    try:
        server.shutdown()
    except NameError:
        print('\nayy lmao')
