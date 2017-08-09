from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser
from charm.toolbox.node import *
import json
import random

class ABS:
    '''
    2B done
    '''
    def __init__(self,group):
        self.group = group

    def trusteesetup(self, attributes):
        '''
        Run by signature trustees
        returns the trustee public key

        Notice: Certain variables have been removed completely.
        G and H are handled by G1 and G2 type generators respectively,
        and the hash function is a generic one for the curve and can
        be derived from the group attribute.

        Attributes have to be appended to the end for global-ness
        '''
        tpk = {}
        tmax = 2*len(attributes)

        tpk['g'] = self.group.random(G1)
        for i in range(tmax+1): #provide the rest of the generators
            tpk['h{}'.format(i)] = self.group.random(G2)

        attriblist = {}
        counter = 2
        for i in attributes:
            attriblist[i] = counter
            counter += 1

        tpk['atr'] = attriblist

        return tpk

    def authoritysetup(self, tpk):
        '''
        Run by attribute-giving authority, takes tpk as parametre
        returns attribute master key and public key
        '''
        ask = {}
        apk = {}
        tmax = 2 * len(tpk['atr'])

        group = self.group
        a0,a,b = group.random(ZR), group.random(ZR), group.random(ZR)
        ask['a0'] = a0
        ask['a'] = a
        ask['b'] = b
        ask['atr'] = tpk['atr'] #this is for ease of usage

        apk['A0'] = tpk['h0'] ** a0
        for i in range(1,tmax+1):#rest of the whateverifys
            apk['A{}'.format(i)] = tpk['h{}'.format(i)] ** a

        for i in range(1,tmax+1):
            apk['B{}'.format(i)] = tpk['h{}'.format(i)] ** b

        apk['C'] = tpk['g'] ** group.random(ZR) #C = g^c at the end

        return ask,apk

    def generateattributes(self, ask, attriblist):
        '''
        returns signing key SKa
        '''
        ska = {}

        Kbase = self.group.random(G1) # "random generator" within G
        ska['Kbase'] = Kbase

        ska['K0'] = Kbase ** (1/ask['a0'])

        for i in attriblist:
            number = ask['atr'][i]
            ska['K{}'.format(number)] = Kbase ** (1 / (ask['a'] + number * ask['b']))

        return ska

    def sign(self, pk, ska, message, policy): #pk = (tpk,apk)
        '''
        return signature
        '''
        tpk,apk = pk
        lambd = {}

        M,u = self.getMSP(policy, tpk['atr'])

        mu = self.group.hash(message+policy)

        r = []
        for i in range(len(M)+1):
            r.append(self.group.random(ZR))

        lambd['Y'] = ska['Kbase'] ** r[0]
        lambd['W'] = ska['K0'] ** r[0]

        for i in range(1,len(M)+1):
            end = 0
            multi = ((apk['C'] * (tpk['g'] ** mu)) ** r[i])
            try: #this fills in for the v vector
                end = multi * (ska['K{}'.format(tpk['atr'][u[i-1]])] ** r[0])
            except KeyError:
                end = multi
            lambd['S{}'.format(i)] = end

        for j in range(1,len(M[0])+1):
            end = 0
            for i in range(1,len(M)+1):
                base = apk['A{}'.format(j)] * (apk['B{}'.format(j)] ** tpk['atr'][u[i-1]])
                exp = M[i-1][j-1] * r[i]
                end = end * (base ** exp)
            lambd['P{}'.format(j)] = end

        return lambd

    def verify(self, pk, sign, message, policy):
        '''
        return bool
        '''
        tpk,apk = pk

        M,u = self.getMSP(policy,tpk['atr'])

        mu = self.group.hash(message+policy)

        if sign['Y']==0 or pair(sign['Y'],tpk['h0']) != pair(sign['W'],apk['A0']):
            return False
        else:
            sentence = True
            for j in range(1,len(M[0])+1):
                multi = 0
                for i in range(1,len(M)+1):
                    a = sign['S{}'.format(i)]
                    b = (apk['A{}'.format(j)] * (apk['B{}'.format(j)] ** tpk['atr'][u[i-1]])) ** M[i-1][j-1]
                    multi = multi * pair(a,b)
                try:
                    after = pair(apk['C'] * tpk['g'] ** mu, sign['P{}'.format(j)])
                    pre = pair(sign['Y'],tpk['h{}'.format(j)])
                    if j == 1:
                        if multi != (pre * after):#after:
                            sentence = False
                    else:
                        if multi != (after):
                            sentence = False
                    #print(j,sentence, multi, pre * after, after)
                except Exception as err:
                    print(err)
            return sentence

    def getMSP(self,policy,attributes):
        '''
        returns the MSP that fits given policy

        utilizes the charm-crypto "policy -> binary tree" structure which has to be
        gone through only once

        target vector (1,0,....,0)
        '''
        policylist = [] #list of all attributes, we need this for handiness
        u = {}
        counter = 0
        for i in attributes:
            policylist.append(i)
            u[counter] = i
            u[i] = counter
            counter += 1

        parser = PolicyParser()
        tree = parser.parse(policy)

        matrix = [] #create matrix as a dummy first (easy indexing)
        for i in range(len(attributes)):
            matrix.append([])

        counter = [1]
        def recursivefill(node,vector): #create MSP compatible rows
            if node.getNodeType() == OpType.ATTR:
                text = node.getAttribute()
                temp = list(vector)
                matrix[u[text]] = temp
            elif node.getNodeType() == OpType.OR:
                recursivefill(node.getLeft(),vector)
                recursivefill(node.getRight(),vector)
            else: #AND here, right?
                temp = list(vector)
                while(len(temp)<counter[0]):
                    temp.append(0)
                emptemp = []
                while(len(emptemp)<counter[0]):
                    emptemp.append(0)
                temp.append(1)
                emptemp.append(-1)
                counter[0] += 1
                recursivefill(node.getLeft(),temp)
                recursivefill(node.getRight(),emptemp)
        recursivefill(tree,[1])

        for i in matrix:
            while(len(i)<counter[0]):
                i.append(0)

        print(matrix)
        return matrix,u

    def encodestr(self, dicti):
        '''
        pairing group dict -> string
        for sending
        '''
        returnage = {}
        for i in dicti:
            returnage[i] = dicti[i]
            try:
                returnage[i] = self.group.serialize(returnage[i]).decode()
            except Exception:
                continue
        return json.dumps(returnage)

    def decodestr(self, stri):
        '''
        string -> pairing group array
        for receiving
        '''
        dicti = json.loads(stri)
        for i in dicti:
            try:
                dicti[i] = self.group.deserialize(str.encode(dicti[i]))
            except Exception:
                continue
        return dicti

if __name__ == "__main__":

    group = PairingGroup('MNT159')
    attributes = ['SKILLFUL','ECCENTRIC','LAZY','VIOLENT']
    print('ATTRIBUTE TABLE: ',attributes)
    absinst = ABS(group)
    tpk = absinst.trusteesetup(attributes)
    ask,apk = absinst.authoritysetup(tpk)
    ska = absinst.generateattributes(ask,['SKILLFUL'])
    lam = absinst.sign((tpk,apk), ska, 'rar', 'SKILLFUL OR ECCENTRIC')
    print(absinst.verify((tpk,apk),lam,'rar','SKILLFUL OR ECCENTRIC'))
    ska2 = absinst.generateattributes(ask,['SKILLFUL','ECCENTRIC'])
    lam2 = absinst.sign((tpk,apk), ska2, 'rar', 'SKILLFUL OR ECCENTRIC')
    print(absinst.verify((tpk,apk),lam2,'rar','SKILLFUL OR ECCENTRIC'))
