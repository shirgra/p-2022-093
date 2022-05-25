#!/usr/bin/env python2

######################################################################################################################################## Imports

import sys
import socket
import random
import csv
import time
from time import sleep
import os

import argparse
import grpc
import os
import sys
import time
import socket
import random
import struct
import csv
import threading    
from time import sleep


# scapy 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # - this remove IPv6 warning from the terminal prints
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR

######################################################################################################################################## Global variables

MAX_PACKETS_SENT = 5000

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

def write_pps_to_file(data , file):
    hits_file = open(file, 'a')
    hits_file.write(data)
    hits_file.write("\n")

######################################################################################################################################## Main

if __name__ == '__main__':

    # load flows
    if "Loading flows":

        # initial uploading for traffic flows
        if len(sys.argv)<2:
            print('Need to pass a .csv file of traffic flows: ./host_traffic_generator.py 1 EX_2_3')
            exit(1)

        flow_small  = {}
        flow_medium = {}
        flow_large  = {}

        # read csv
        try:

            # load the csv file to local list
            name_csv = '../tests_dependencies/flow_1.csv'
            print name_csv 
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

    
    if "Loading file name":
        try:
            name_file = '../../results'+'/'+ sys.argv[2] +'/h' + sys.argv[1] + '_pps.txt'
        except:
            name_file = '../../results'+ '/h' + sys.argv[1] + '_pps.txt'
        sw_pps_file = open(name_file, 'w')


    # start sending process
    time_start = time.time()
    sent_counter = 0
    sml = md = lrg = 0
    loops_per_sec = 0

    l = m = s = 0

    small_bank = flow_small.values()
    med_bank   = flow_medium.values()
    large_bank = flow_large.values()

    tmp = 0




    # running the host program
    print("Sending traffic...")
    print("Sending rate: X p in Y sec.    Sent 0 packets so far.     (s, m, l)")

    while sent_counter < MAX_PACKETS_SENT:
        # reset timer
        time_start = time.time()

        # 70 pps = 40 pps + 20 + 10
        for loop in range(40):
            
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
        pps = sml+md+lrg
        t = (time.time() - time_start)
        #pps = pps/t
        print("Sending rate: %d p in %f s.    Sent %d packets so far.     (%d, %d, %d)" % (pps, t, sent_counter, sml, md, lrg))
        
        sml = md = lrg = 0

        #  to file:
        sw_pps_file = open(name_file, "a")
        sw_pps_file.writelines([str(time.time()), "  ", str(t) ," = 70 pp\n"])
        sw_pps_file.close()


    # finish main
    print("Successfully transsmitted %d packets." % (sent_counter))
    print("Traffic Generator Program Ended Sucsessfully.")  