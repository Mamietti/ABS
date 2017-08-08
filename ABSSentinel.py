from MathABS import ABS
from charm.toolbox.pairinggroup import PairingGroup
import socketserver
import json
from charm.toolbox.securerandom import OpenSSLRand

class MyTCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.data = self.request.recv(hugeness).strip()
            msg = self.data.decode('utf-8')
            print('RECEIVED TESTCASE ATTRIBUTES',msg)

            ska = absinst.generateattributes(ask,msg.split(","))
            striple = (absinst.encodestr(tpk),absinst.encodestr(apk),absinst.encodestr(ska))
            self.request.sendall(bytes(json.dumps(striple),'utf8'))
            print('TESTCASE SKA GENERATED AND SENT, READY TO RECEIVE!')

            self.data = self.request.recv(hugeness).strip()
            msg = self.data.decode('utf-8')
            site = msg.split(':')[1]
            print('{}:{} wants to connect to {}'.format(self.client_address[0],self.client_address[1],site))

            policy = accesspolicies[site]
            nonce = str(OpenSSLRand().getRandomBytes(20))[2:].replace("\\x","")
            stuple = (nonce,policy)
            self.request.sendall(bytes(json.dumps(stuple),'utf8'))
            print('Sent nonce {} and policy {}'.format(nonce,policy))

            self.data = self.request.recv(hugeness).strip()
            msg = self.data.decode('utf-8')
            signature = absinst.decodestr(msg)
            print('Received and decoded signature')

            judgement = 'DENIED'
            if absinst.verify((tpk,apk),signature,nonce,policy):
                judgement = 'OK'
            self.request.sendall(bytes(judgement,'utf-8'))
            print('Sent judgement', judgement, '\n')

        except Exception as err:
            print(err)
            print('MISERABLE FAILURE')

try:
    attributes = [
        'MOTIVATED',
        'SKILLFUL',
        'ECCENTRIC',
        'LAZY',
        'VIOLENT'
    ]
    print('ATTRIBUTE TABLE: ',attributes)

    group = PairingGroup('SS512')
    absinst = ABS(group)
    tpk = absinst.trusteesetup(attributes)
    ask,apk = absinst.authoritysetup(tpk)

    hugeness = 6000

    accesspolicies = {'www.vtt.fi': '(SKILLFUL AND MOTIVATED) OR ECCENTRIC'}

    host,port = 'localhost',0
    server = socketserver.TCPServer((host,port), MyTCPHandler)
    print('port: ',server.server_address[1])
    server.serve_forever()
except KeyboardInterrupt:
    try:
        server.shutdown()
    except NameError:
        print('\nayy lmao')
