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
rules = {} # {'192.0.0.0': ['32', 0]}  -> {'IP ADDR': [MASK, threshold]} 
cache = {} # {'192.0.0.0': [32, 1]}    -> {'IP ADDR': [MASK, LRU]} 

THRESHOLD = 2
CACHE_SIZE = 8 # initiate a cache variable - dictionary (key is address)

hit_to_policy_counter = 0
miss_to_policy_counter = 0
found_in_cache = 0
found_not_in_cache = 0
packet_counter = 0


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


def write_rule_to_file(rule):
    rules_file = open('rules.txt', 'a')
    rules_file.write(rule)
    rules_file.write("\n")

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

# gets address as str and return the rule if exists or false otherwise
def get_rule(wanted_addr = None):
    global hit_to_policy_counter, miss_to_policy_counter
    dest_Addr   = to_binary(wanted_addr)
    # search for rule in policy:
    for addr in rules.keys():
        mask = rules[addr][0]
        policy_Addr = to_binary(addr)
        numOfEqaulBits = len(longestCommonPrefix([dest_Addr,policy_Addr]))
        if (numOfEqaulBits >= mask):
            # found in policy
            hit_to_policy_counter += 1
            return addr
    # not found in policy - dump
    miss_to_policy_counter += 1
    return 0
    
def handle_pkt(pkt):
    global packet_counter
    packet_counter += 1 # update counter


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
            # get address treshold
            # TODO threshold
            threshold = rules[controller_answer][1]
            if threshold > THRESHOLD:
                print("Received a new requenst: Writing rule to the outside controller.")
                
                """
                if check_if_in_cache():
                    found_in_cache += 1
                else: 
                    found_not_in_cache += 1
                    insert_cache(new_rule = controller_answer)
                """
                # write to file
                write_rule_to_file(str([controller_answer, rules[controller_answer][0]]))

                rules[controller_answer][1] = 0


            else:
                # not enough miss - update threshold
                print("Received a new requenst: Updating threshold.")
                rules[controller_answer][1] = rules[controller_answer][1] + 1
        else:
            print("Received a new requenst: Dumping it.")
        """
    

        rules = {} # {'192.0.0.0': ['32', 0]}  -> {'IP ADDR': [MASK, threshold]} 
        cache = {} # {'192.0.0.0': [32, 1]}    -> {'IP ADDR': [MASK, LRU]} 

        found_in_cache = 0
        found_not_in_cache = 0



        # print values every 50 packets incoming
        if (packet_counter % 50) == 0:
            print("Packet counter = %d:" % packet_counter)
            print("   Found in cache = %d and %d missed.." % (found_in_cache,found_not_in_cache))
            print("   Hit in policy = %d and %d missed." % (hit_to_policy_counter, miss_to_policy_counter))
        """
       

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
                try:
                    rules[policy[0]] = [(int)(policy[1]), 0] # initiate treshold to 0
                except:
                    pass
                # policy[0] -> policy address
                # policy[1] -> policy mask
            print("Successfully uploaded %d rules for traffic." % len(rules))
    except:
        print("Failed to upload csv file.")
        exit(1)
    # main pipeline -> listen to eth0 (receive socket) and replay according to a policy table
    print("Staring The Host Controller Program")
    print("Cache size is %d." % CACHE_SIZE)
    print("Threshold size is %d." % THRESHOLD )
    print("Press ctrl + z to exit the program.")
    # keep results for expirement
    # TODO keep up with the hits and misses and write it to file - make them global variables

    # open a rules file
    rules_file = open('rules.txt', 'w')
    print("Opend a 'rules.txt file.")

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