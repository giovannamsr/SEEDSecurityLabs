#!usr/bin/python
from scapy.all import *

def print_pkt(pkt):
    print("------------Packet info------------")
    print("Source IP: ", pkt[IP].src)
    print("Destination IP: ", pkt[IP].dst)
    print("Protocol : ",pkt[IP].proto)

#insert the filter here
fil = 'tcp and dst portrange 10-100'

pkt = sniff(filter = fil, prn = print_pkt)

