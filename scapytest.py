from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
import sys

def print_and_accept(pkt):
    a = IP(pkt.get_payload())
    print(a.show())
    pkt.drop()

try:
    os.system("sudo iptables -A OUTPUT -p tcp -j NFQUEUE")
    nfqueue = NetfilterQueue()
    print('y2')
    nfqueue.bind(0,print_and_accept)
    nfqueue.run()
except KeyboardInterrupt:
    os.system("sudo iptables -D OUTPUT -p tcp -j NFQUEUE")
    print('')
    nfqueue.unbind()
