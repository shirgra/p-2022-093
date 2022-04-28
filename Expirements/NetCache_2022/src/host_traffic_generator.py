#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import argparse
import os
import csv
from tqdm import tqdm
# scapy logger - this remove IPv6 warning from the terminal prints
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# scapy
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
# threads
import threading
import time


""" help functions """

# returns eth0 interface for the running host
def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

# this function sends packets sequence according to a given flow
def send_packet(flow = None):
    """
    this function sends one packet to the outsode world.
    input:
        flow: list, e.g. ['1', '192.10.10.15', '8', '19']
    output:
        True/False if packet sent to the switch
    """
    if not flow:
        return 0 # fail
    # parse flow var
    ip_dst_addr             = socket.gethostbyname(flow[1])
    no_of_packets_in_flow   = int(flow[2])
    payload_size            = int(flow[3])
    # build params for packet
    #metadata    = "hello world " + str(random.randint(0,15)) # todo hard coded
    metadata    = "A"*(payload_size)
    iface       = get_if()
    src_hw_addr = get_if_hwaddr(iface)
    dst_hw_addr = 'ff:ff:ff:ff:ff:ff'
    # build packet
    pkt =  Ether(src = src_hw_addr, dst = dst_hw_addr) 
    pkt =  pkt / IP(dst = ip_dst_addr) 
    pkt =  pkt / TCP(dport=1234, sport=random.randint(49152,65535)) 
    pkt =  pkt / metadata
    # sending the pkt
    for p in range(no_of_packets_in_flow):
        sendp(pkt, iface=iface, verbose=False)
    #pkt.show2()
    #print "sending on interface {} to IP addr {}".format(iface, str(addr))
    return no_of_packets_in_flow

if __name__ == '__main__':

    # initial uploading for traffic flows
    if len(sys.argv)<2:
        print('Need to pass a .csv file of traffic flows: ./host_traffic_generator.py expirements_dependencies/flow_tst.csv')
        exit(1)
    traffic = [] # this will be a list of lists of flows 
    try:
        # load the csv file to local list
        name_csv = sys.argv[1]
        no_pkts_total = 0
        with open(name_csv) as csvfile:
            flows = csv.reader(csvfile, quotechar='|')
            for flow in flows:
                traffic.append(flow)
                # flow[0] -> flow id
                # flow[1] -> dst ip addr
                # flow[2] -> no. of packets
                # flow[3] -> payload size
                try:
                    no_pkts_total = no_pkts_total + (int)(flow[2])
                except:
                    pass
            traffic = traffic[1::] # dont take the headers
            print("Successfully uploaded %d flows of traffic." % len(traffic))
    except:
        print("Failed to upload csv file.")
        exit(1)

    # running the host program
    print("Sending traffic...")
    sent_counter = 0
    for flow in tqdm(traffic): 
        sent_counter += send_packet(flow = flow)

    # done
    print("Successfully transsmitted %d out of %d packets of traffic." % (sent_counter, no_pkts_total))
    print("Traffic Generator Program Ended Sucsessfully.")  
