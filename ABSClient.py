from charm.toolbox.pairinggroup import PairingGroup
from MathABS import ABS
import socket
import sys
import json

try:
    host,port,site = sys.argv[1],int(sys.argv[2]),sys.argv[3]
except IndexError:
    print("Format: ABSClient.py serverhost serverport site attrib1 attrib2 ...")
    exit()

hugeness = 6000

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

group = PairingGroup('SS512')
testinst = ABS(group)
sock.connect((host,port))
print('Connected to server')

sock.sendall(bytes(",".join(sys.argv[4:]),'utf-8'))
print('SENT ATTRIBUTES FOR TEST CASE')

tpk,apk,ska = json.loads(str(sock.recv(hugeness),'utf-8'))
tpk = testinst.decodestr(tpk)
apk = testinst.decodestr(apk)
ska = testinst.decodestr(ska)
print('TEST CASE TPK, APK AND SIGNING KEY RECEIVED, READY TO ROLL!')

sock.sendall(bytes('CONNECT:{}'.format(site),'utf-8'))
print('Sent {} permission request'.format(site))

nonce,policy = json.loads(str(sock.recv(hugeness),'utf-8'))
print('Received nonce {} and policy {}'.format(nonce,policy))

lam = testinst.sign((tpk,apk), ska, nonce, policy)
sock.sendall(bytes(testinst.encodestr(lam),'utf-8'))
print('Sent created signature from nonce and policy')
print('Received judgement:',str(sock.recv(hugeness),'utf-8'),'\n')
sock.close()
