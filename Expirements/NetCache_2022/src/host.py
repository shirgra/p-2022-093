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

# initiate a cache variable - dictionary (key is address)
CACHE_SIZE = 8 #TODO decide if this is a variable from running 
global cache
cache = {} # {'192.0.0.0': [32, 1]} = {'IP ADDR': [MASK, LRU]} - global variable


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

# this function is a copied function, gets the resemblense between two strings
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

# change from "192.168.22.1" to "10010111100001110000101011111111"
def to_binary(ip):
    return ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])

#check if the destination address is match to the policy address by at list the mast size
def if_lpm(destAddr,policyAddr,mask):
    # return [policyAddr,mask] if has a match and false if not
    dest_Addr = to_binary(destAddr)
    policy_Addr = to_binary(policyAddr)
    numOfEqaul = len(longestCommonPrefix([dest_Addr,policy_Addr]))
    if (numOfEqaul >= int(mask)):
       return True
    return False

# this is the only place we write to the cache and change it
def update_cache_LRU(key_addr):
    global cache
    curr_LRU_flag_for_key_addr = cache[key_addr][1] # LRU flag
    # +1 to all lower values
    for k in cache.keys():
        m = cache[k][0]
        i = cache[k][1]
        if i < curr_LRU_flag_for_key_addr:
            cache[k] = [m, i + 1]
    # update to be last one to be used
    cache[key_addr] = [cache[key_addr][0], 1]
    return None

# insert the new rule to cache and update LRU
def insert_cache(new_rule):
    global cache
    # parse new_rule
    new_rule = new_rule[1:-1].split(', ')
    key = new_rule[0][1:-1] # take only the address w/o ''
    mask = new_rule[1][1:-1] # take only the mask w/o ''
    # check if we already have that rule
    if key in cache.keys():
        return None
    # if there is room for more rules:
    if len(cache) < CACHE_SIZE:
        # update all LRU
        for k in cache.keys():
            m = cache[k][0]
            i = cache[k][1] + 1
            cache[k] = [m, i]
        # insert new rule
        cache[key] = [mask, 1]
    else:
        # update all LRU
        for k in cache.keys():
            m = cache[k][0]
            i = cache[k][1]
            if i == CACHE_SIZE:
                # this is the LRU - evict rule
                cache.pop(k, None)
            else:
                cache[k] = [m, i+1]
        # insert new rule
        cache[key] = [mask, 1]
    return None

# this function return true if we have the adress in the cache and false otherwise
def check_if_in_cache(addr):
    for cache_addr in cache.keys():
        mask = cache[cache_addr][0]
        if if_lpm(addr, cache_addr, mask):
            update_cache_LRU(key_addr = cache_addr) # update according to LRU
            return True
    return False

# what is done when receiving a packet
def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234 and bytes(pkt[IP].dst) == '10.0.2.2': #TODO CHANGE FOR HOST
        new_rule = bytes(pkt[TCP].payload)
        sys.stdout.flush()
        insert_cache(new_rule = new_rule)


# this function sends packets sequence according to a given flow
def send_packet(flow = None, cache_flag = 2):
    """
    this function sends one packet to the outsode world.
    input:
        flow: list, e.g. ['1', '192.10.10.15', '8', '19']
        cache_flag, int. 2 means not in cache and goto the controller, 3 means in cache. 3 is const and very importent beacuse it resolved to drop in the connected switch.
    output:
        packet sent to the switch
    """
    if not flow:
        return False # fail
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
    pkt =  pkt / IP(dst = ip_dst_addr, flags = cache_flag) 
    pkt =  pkt / TCP(dport=1234, sport=random.randint(49152,65535)) 
    pkt =  pkt / metadata
    # sending the pkt
    for p in range(no_of_packets_in_flow):
        sendp(pkt, iface=iface, verbose=False)
    #pkt.show2()
    #print "sending on interface {} to IP addr {}".format(iface, str(addr))
    return True


""" threads and main functions """

def thread_receiver():
    print("Receiver Thread is starting")
    # TODO add received packet to cache
    # sniffing until ... ?? TODO make stop condition?? timer??
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    #print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
    # TODO maybe set that the last of traffic send a message to the controller and then the controller send a signal through a packet to finish??
    print("Receiver Thread finished")

def main(traffic = None):
    print("Staring The Main Function in H2") # TODO change name of host
    print("Cache size is %d." % CACHE_SIZE)
    # initiate expirement variables
    found_in_cache = 0
    not_found_in_cache = 0
    # start receiving thread to listen to rules come in
    # Thread that listen/snif
    receiver = threading.Thread(target=thread_receiver)
    receiver.start()
    time.sleep(3)
    # sending the traffic
    print("Sending traffic...")
    for flow in tqdm(traffic): 
        # chack if the destination address is in the cache - TODO mutable OR only read so it is OK?
        if check_if_in_cache(flow[1]):
            found_in_cache += 1
            send_packet(flow = flow, cache_flag = 3) # 3 means drop in switch
        else: 
            not_found_in_cache += 1
            send_packet(flow = flow, cache_flag = 2) # 2 means sent to controller
        # TODO add expire date to the rule in the cache
        # TODO add mutable for writing cache rule? only one writer 
    print("Successfully sent %d flows of traffic." % len(traffic))
    print("%d of the flows were found in the cache and %d were not." % (found_in_cache,not_found_in_cache))

    receiver.join()
    #TODO for the receiver stop after finish sending becuse we are done
    print("Finished Program Sucsessfully.")  


if __name__ == '__main__':
    # initial uploading for traffic flows
    if len(sys.argv)<2:
        print('Need to pass a .csv file of traffic flows: ./host.py traffic_h2.csv')
        exit(1)
    traffic = [] # this will be a list of lists of flows 
    try:
        # load the csv file to local list
        name_csv = sys.argv[1]
        with open(name_csv) as csvfile:
            flows = csv.reader(csvfile, quotechar='|')
            for flow in flows:
                traffic.append(flow)
                # flow[0] -> flow id
                # flow[1] -> dst ip addr
                # flow[2] -> no. of packets
                # flow[3] -> payload size
            traffic = traffic[1::] # dont take the headers
            print("Successfully uploaded %d flows of traffic." % len(traffic))
    except:
        print("Failed to upload csv file.")
        exit(1)
    # running the host program
    main(traffic)
