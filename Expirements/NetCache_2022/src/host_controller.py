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
# scapy logger - this remove the IPv6 warning from the terminal prints
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# scapy
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
# threads
import threading
import time

# global variables
rules = [] # this will be a list of lists ? TODO decide...


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

def longestCommonPrefix(strs):
    """
    :type strs: List[str]
    :rtype: str
    """
    if len(strs) == 0:
        return ""
    current = strs[0]
    for i in range(1,len(strs)):
        temp = ""
        if len(current) == 0:
            break
        for j in range(len(strs[i])):
            if j<len(current) and current[j] == strs[i][j]:
                temp+=current[j]
            else:
                break
        current = temp
    return current

#change from "192.168.22.1" to "10010111.10000111.00001010.11111111"
def to_binary(ip):
    return ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])

#check if the destination address is match to the policy address by at list the mast size
#retern [policyAddr,mask] if has a match and false if not
def if_lpm(destAddr,policyAddr,mask):
    dest_Addr = to_binary(destAddr)
    policy_Addr = to_binary(policyAddr)
    numOfEqaul = len(longestCommonPrefix([dest_Addr,policy_Addr]))
    if (numOfEqaul >= int(mask)):
        return [policyAddr,mask],numOfEqaul
    return False,numOfEqaul

def get_rule(wanted_addr = None):
    max_eqaul = 0
    res_rule = []
    for rule in rules:
        addr_mask,eqaul = if_lpm(wanted_addr,rule[0],rule[1])
        if (addr_mask and eqaul > max_eqaul):
            res_rule = addr_mask
        else:
            continue
    if res_rule !=[]:
        #print(res_rule)
        return str(res_rule)
    return False
        
def send_rule_to_host(ip_dst_addr, metadata):
    """
    this function sends one packet to the outside world.
    input:
        ip_dst_addr: e.g. '192.10.10.15', string
        metadata:    e.g. '[wanted_addr, 32]', string
    output:
        packet sent to the switch
    """
    # reformat string to ip
    ip_dst_addr = socket.gethostbyname(ip_dst_addr)
    # build params for packet
    iface       = get_if()
    src_hw_addr = get_if_hwaddr(iface)
    dst_hw_addr = 'ff:ff:ff:ff:ff:ff'
    # build packet
    pkt =  Ether(src = src_hw_addr, dst = dst_hw_addr) 
    pkt =  pkt / IP(dst = ip_dst_addr, flags = 2) # herd coded? flag? check
    pkt =  pkt / TCP(dport=1234, sport=random.randint(49152,65535)) 
    pkt =  pkt / metadata
    # sending the pkt
    sendp(pkt, iface=iface, verbose=False)
    #pkt.show2()
    return True


def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234: # notice 1234 has to be identical to the one in host_traffic_generator
        addr_of_host_sending_request = pkt[IP].src
        lookup_ip_request            = pkt[IP].dst 
        sys.stdout.flush() 
        # TODO add to counters
        # parse varables from packet
        # check if the address metch our rules
        controller_answer = get_rule(lookup_ip_request)
        # if match - send back packet to host with payload = (IP,MASK)
        if controller_answer:
            print("Received a new requenst: Writing rule to the outside controller.")
            # TODO write to file

            """
            print("Received a new requenst. Returning to host a rule.")
            send_rule_to_host(ip_dst_addr = addr_of_host_sending_request, metadata = controller_answer)
            """
        else:
            #TODO keep threshold
            print("Received a new requenst: Counting threshold.")
        

""" main function """
if __name__ == '__main__':
    # initial uploading for policy csv
    if len(sys.argv)<2:
        print('Need to pass a .csv file of policy rules: ./host_controller.py policy.csv')
        exit(1)
    # upload the policy to our ptogram
    try:
        # load the csv file to local list
        name_csv = sys.argv[1]
        with open(name_csv) as csvfile:
            policies_csv = csv.reader(csvfile, quotechar='|')
            for policy in policies_csv:
                rules.append(policy)
                # policy[0] -> policy address
                # policy[1] -> policy mask
            rules = rules[1::] # dont take the headers
            print("Successfully uploaded %d rules for traffic." % len(rules))
    except:
        print("Failed to upload csv file.")
        exit(1)
    # main pipeline -> listen to eth0 (receive socket) and replay according to a policy table
    print("Staring The Host Controller Program")
    print("Press ctrl + z to exit the program.")
    # keep results for expirement
    # TODO keep up with the hits and misses and write it to file - make them global variables

    # listen to packets incoming ...
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "Sniffing on %s - ready." % iface
    sys.stdout.flush()
    # for every packet comming in we handle_pkt --- stuck here untill ctrl + c (listening...)
    while True:
        # please notice - can only handle one packet at a time... may miss some packets in overloads...
        sniff(count = 1, iface = iface, prn = lambda x: handle_pkt(x))
    # if user press ctrl + z -> exit
    print("\nController Program Terminated.")  
    exit(0)

""" CONNAMDS BANK
time.sleep(5) # inseconds
addr = socket.gethostbyname(sys.argv[1]) # get MAC address?
x = threading.Thread(target=thread_receiver, args=(1,5,)) # assign thread
x.start() # start running the thread
x.join() # wait for thread to finish before continue
#pkt.show2()

"""