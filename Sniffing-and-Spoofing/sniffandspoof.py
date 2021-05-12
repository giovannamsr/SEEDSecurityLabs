#!usr/bin/python
from scapy.all import *

def print_pkt(pkt):
    if pkt.haslayer(Raw):
        print("------------Packet info------------")
        print(pkt[Raw].load)

#insert the filter here
fil = 'tcp'

pkt = sniff(filter = fil, prn = print_pkt)

