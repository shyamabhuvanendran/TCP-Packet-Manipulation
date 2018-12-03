#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This script converts pcap files containing tcp packets to csv

@author: shyamabs
"""
import dpkt
import codecs
from scapy.all import *
import csv
import numpy as np
import pandas as pd

def pcapToCsv(fname):
    pkts=rdpcap(fname)
    outfile='output.csv'
    with open(outfile, 'w', newline='') as csvfile:
        fieldnames = ['dst', 'src', 'type', 'IP version', 'IP ihl', 'IP tos','IP len', 'IP id', 'IP flags', 'IP frag', 'IP ttl',
                      'IP proto','IP chksum','IP src','IP dst','TCP sport','TCP dport', 'TCP seq', 'TCP ack', 'TCP dataofs', 
                      'TCP reserved', 'TCP flags','TCP window', 'TCP chksum','TCP urgptr','TCP options']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
        writer.writeheader()
    
        for pkt in pkts:
            #pkt.show()
            if pkt.haslayer(TCP):
                #print( "dst: " +  str(pkt.getlayer(IP).chksum))
                writer.writerow({'dst': str(pkt.dst), 'src': str(pkt.src), 'type' : str(pkt.type), 'IP version': str(pkt.getlayer(IP).version), 
                             'IP ihl': str(pkt.getlayer(IP).ihl), 'IP tos': str(pkt.getlayer(IP).tos),'IP len': str(pkt.getlayer(IP).len), 
                             'IP id': str(pkt.getlayer(IP).id),'IP flags': str(pkt.getlayer(IP).flags), 'IP frag': str(pkt.getlayer(IP).frag), 
                             'IP ttl': str(pkt.getlayer(IP).ttl), 'IP proto': str(pkt.getlayer(IP).proto),'IP chksum': str(pkt.getlayer(IP).chksum),
                             'IP src': str(pkt.getlayer(IP).src),'IP dst': str(pkt.getlayer(IP).dst),'TCP sport': str(pkt.getlayer(TCP).sport),
                          'TCP dport': str(pkt.getlayer(TCP).dport), 'TCP seq': str(pkt.getlayer(TCP).seq), 'TCP ack': str(pkt.getlayer(TCP).ack), 
                          'TCP dataofs': str(pkt.getlayer(TCP).dataofs), 'TCP reserved': str(pkt.getlayer(TCP).reserved), 
                          'TCP flags': str(pkt.getlayer(TCP).flags),'TCP window': str(pkt.getlayer(TCP).window), 'TCP chksum': str(pkt.getlayer(TCP).chksum),
                          'TCP urgptr': str(pkt.getlayer(TCP).urgptr),'TCP options': str(pkt.getlayer(TCP).options)})
    
    print("Done with conversion...")
    return outfile
        


    
print("Starting pcap to csv conversion...")
fname = 'input.pcap'
csvfile=pcapToCsv(fname)

