#!/usr/bin/env python2

######################################################################################################################################## Imports

import sys
import socket
import random
import csv
import time
from time import sleep

# scapy 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # - this remove IPv6 warning from the terminal prints
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR

######################################################################################################################################## Global variables

MAX_PACKETS_SENT = 1000

######################################################################################################################################## Functions

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
def send_packet(dst_ip = "192.10.10.10"):

    try:

        # parse flow var
        ip_dst_addr             = socket.gethostbyname(dst_ip)

        # build params for packet
        metadata    = "A"
        iface       = get_if()
        src_hw_addr = get_if_hwaddr(iface)
        dst_hw_addr = 'ff:ff:ff:ff:ff:ff'

        # build packet
        pkt =  Ether(src = src_hw_addr, dst = dst_hw_addr) 
        pkt =  pkt / IP(dst = dst_ip) 
        pkt =  pkt / TCP(dport=1234, sport=random.randint(49152,65535)) 
        pkt =  pkt / metadata

        # sending the pkt
        sendp(pkt, iface=iface, verbose=False)

        return 1

    except:

        return 0

######################################################################################################################################## Main

if __name__ == '__main__':

    # load flows
    if "Loading flows":

        # initial uploading for traffic flows
        if len(sys.argv)<2:
            print('Need to pass a .csv file of traffic flows: ./host_traffic_generator.py ../test_dependencies/flow_1.csv')
            exit(1)

        flow_small  = {}
        flow_medium = {}
        flow_large  = {}

        # read csv
        try:

            # load the csv file to local list
            name_csv = sys.argv[1]
            with open(name_csv) as csvfile:

                rows = csv.reader(csvfile, quotechar='|')
                for flow in rows:

                    # flow[0] -> flow id
                    # flow[1] -> type of flow
                    # flow[2] -> dst ip addr

                    if flow[1] == "Small":
                        flow_small[flow[0]] = flow[2]
                    if flow[1] == "Medium":
                        flow_medium[flow[0]] = flow[2]
                    if flow[1] == "Large":
                        flow_large[flow[0]] = flow[2]
                        

            print("Successfully uploaded %d flows of traffic." % (len(flow_large) + len(flow_medium) + len(flow_small)))

        except:

            print("Failed to upload csv file.")
            exit(1)

    # start sending process
    time_start = time.time()
    sent_counter = 0
    sml = md = lrg = 0
    loops_per_sec = 0

    l = m = s = 0

    small_bank = flow_small.values()
    med_bank   = flow_medium.values()
    large_bank = flow_large.values()


    # running the host program
    print("Sending traffic...")
    while sent_counter < MAX_PACKETS_SENT:
        loops_per_sec += 1

        # large flows - 40 pps - 10 addresses
        try:
            sent_counter += send_packet(dst_ip = large_bank[l])
            l += 1
        except:
            sent_counter += send_packet(dst_ip = large_bank[0])
            l = 0
        lrg += 1

        # medium flows - 20 pps - 20 addresses
        if lrg % 2:
            try:
                sent_counter += send_packet(dst_ip = med_bank[m])
                m += 1
            except:
                sent_counter += send_packet(dst_ip = med_bank[0])
                m = 0
            md += 1

            # small flows - 10 pps - 10 addresses
            if md % 2:
                try:
                    sent_counter += send_packet(dst_ip = small_bank[s])
                    s += 1
                except:
                    sent_counter += send_packet(dst_ip = small_bank[0])
                    s = 0
                sml += 1


        # seconds timer handler            
        if time.time() - time_start >= 2:
            print("Sending rate: %d pp2s.    Sent %d packets so far.     (%d, %d, %d)" % (loops_per_sec, sent_counter, sml, md, lrg))
            # reset timer
            time_start = time.time()
            loops_per_sec = 0

            sml = md = lrg = 0

    # finish main
    print("Successfully transsmitted %d packets." % (sent_counter))
    print("Traffic Generator Program Ended Sucsessfully.")  