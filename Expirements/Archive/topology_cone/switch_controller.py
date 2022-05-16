#!/usr/bin/env python2

import argparse
import grpc
import os
import sys
import time
import socket
import random
import struct
import csv
from time import sleep
from tqdm import tqdm

# Import P4Runtime lib from parent utils dir Probably there's a better way of doing this.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),'../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

# scapy logger - this remove the IPv6 warning from the terminal prints
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# scapy
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR

###########################################################################################

THRESHOLD = 2
CACHE_SIZE = 8

# global variables

rules = {}    # {1: ['192.0.0.0', 32]}  -> { policy_id: ['IP ADDR', MASK] } 

s1_cache = {} # {2: ['192.0.0.0', 32, 1]}    -> {policy_id: ['IP ADDR', MASK, LRU, table_entry]} 
s2_cache = {} # {2: ['192.0.0.0', 32, 1]}    -> {policy_id: ['IP ADDR', MASK, LRU, table_entry]} 
s3_cache = {} # {2: ['192.0.0.0', 32, 1]}    -> {policy_id: ['IP ADDR', MASK, LRU, table_entry]}

s1_threshold = {}  # {1: 0}  -> { policy_id: threshold } 
s2_threshold = {}  # {1: 0}  -> { policy_id: threshold } 
s3_threshold = {}  # {1: 0}  -> { policy_id: threshold } 

###########################################################################################

""" P4RUNTIME FUNCTIONS """

def p4runtime_init():
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='.././build_dependencies/net_cache.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='.././build_dependencies/net_cache.json')
    args = parser.parse_args()
    # if does not exist -> exit
    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    # Instantiate a P4Runtime helper from the p4info file
    bmv2_file_path = args.bmv2_json
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(args.p4info)   
    # return values
    return bmv2_file_path, p4info_helper

def writeRule(p4info_helper, src_sw, dst_ip_addr, mask=32, 
    action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:01:11", sw_exit_post=1):

    if action == "MyIngress.ipv4_forward":
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dst_ip_addr, mask)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": dst_host_eth_addr,
                "port": sw_exit_post
            })

    if action == "MyIngress.drop":
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dst_ip_addr, mask)
            },
            action_name="MyIngress.drop",
            action_params={
            }) 

    src_sw.WriteTableEntry(table_entry)
    print 'Added a new rule in - %s/%d -> %s' % (dst_ip_addr, mask, action)
    return table_entry # for deletion

def readTableRules(p4info_helper, sw):
    print '\n----- Reading tables rules for %s -----' % sw.name
    """
    Reads the table entries from all tables on the switch.
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            
            # print 'Table %s; ' % (table_name),
            for m in entry.match:
                # print '%s' % p4info_helper.get_match_field_name(table_name, m.field_id),
                # print address ipv4
                str_tmp = list((p4info_helper.get_match_field_value(m),)[0][0]) #'\n\x00\x02\x02'
                for s in str_tmp:
                    print '%s.' % ord(s),
            print

""" CONTROLLER ALGORITHM FUNCTIONS """

# gets two lists of bits and return a common prefix list
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

# gets address as str and return the rule if exists or false otherwise
def get_rule(wanted_addr = None):
    wanted_addr   = to_binary(wanted_addr)
    # search for rule in policy:
    for pol in rules.keys():
        addr = rules[pol][0] # { policy_id: ['IP ADDR', MASK, threshold] }
        mask = rules[pol][1] # { policy_id: ['IP ADDR', MASK, threshold] }
        policy_Addr = to_binary(addr)
        numOfEqaulBits = len(longestCommonPrefix([wanted_addr, policy_Addr]))
        if (numOfEqaulBits >= mask): 
            return pol       # return [policy_id, 'IP ADDR', MASK]
    return -1

# what is done when receiving a packet
def handle_pkt(pkt):
    # global vars
    global s1, s2, s3
    global s1_cache, s2_cache, s3_cache
    global s1_threshold, s2_threshold, s3_threshold
    global rules

    # parse packet 
    source_host_ip      = pkt[IP].src # recognize the switch src
    lookup_ip_request   = pkt[IP].dst # the request for an unknown destination
    sys.stdout.flush()

    # choose switch to handle
    if source_host_ip == "10.0.1.1":
        switch = s1
        switch_name = "s1"
        switch_cache = s1_cache
        switch_threshold = s1_threshold
    if source_host_ip == "10.0.2.2":
        switch = s2
        switch_name = "s2"
        switch_cache = s2_cache
        switch_threshold = s2_threshold
    if source_host_ip == "10.0.3.3":
        switch = s3
        switch_name = "s3"
        switch_cache = s3_cache
        switch_threshold = s3_threshold

    # check if the address metch our rules
    controller_answer = get_rule(lookup_ip_request)
    if controller_answer != -1: 

        # parse answer
        address   = rules[controller_answer][0]                 # get rule address
        mask      = rules[controller_answer][1]                 # get rule mask
        threshold = switch_threshold.get(controller_answer, 0)  # get rule treshold

        # check if rule got enough threshold counts
        if threshold > THRESHOLD:

            if controller_answer not in switch_cache.keys():
            # check if already in switch cache

                if len(switch_cache) < CACHE_SIZE:
                # cache is not full yet - just write:

                    ### write to switch ###
                    print("Writing rule in %s." % switch_name)
                    table_entry = writeRule(p4info_helper, src_sw=switch, dst_ip_addr=address, mask=mask, action="MyIngress.drop")

                    # update all LRU
                    for k in switch_cache.keys():
                        switch_cache[k] = [switch_cache[k][0], switch_cache[k][1], switch_cache[k][2]+1, table_entry]
                    # insert new rule
                    switch_cache[controller_answer] = [address, mask, 1, table_entry]

                else:
                # cache is not full yet - delete LRU then write
                    for k in switch_cache.keys():

                        if switch_cache[k][2] >= CACHE_SIZE:

                            # delete old rule and inser new rule
                            print("Deleting rule and writing new rule in %s." % switch_name)

                            """readTableRules(p4info_helper, switch)
                            print("\n %s" % str(switch_cache[k][3][0]))
                            switch.DeleteTableEntry(switch_cache[k][3][0])
                            readTableRules(p4info_helper, switch)"""
                            try:
                                table_entry = writeRule(p4info_helper, src_sw=switch, dst_ip_addr=address, mask=mask, action="MyIngress.drop")

                                # this is the LRU - evict rule
                                switch_cache.pop(k, None)
                                # insert new rule
                                switch_cache[controller_answer] = [address, mask, 1, table_entry]
                            except:
                                # this is the LRU - evict rule
                                switch_cache.pop(k, None)
                                # insert new rule
                                switch_cache[controller_answer] = [address, mask, 1, None]
                                print("IN BUG - line 248 write rule ")



                        else:
                            switch_cache[k] = [switch_cache[k][0], switch_cache[k][1], switch_cache[k][2] + 1, switch_cache[k][3]]
           
            # reset threshold
            switch_threshold[controller_answer] = 0

        else:
            # update threshold
            switch_threshold[controller_answer] = threshold + 1



###########################################################################################

"""MAIN"""

if __name__ == '__main__':

    # listen to packets incoming ...
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    print ifaces
    
    sys.stdout.flush()

    print "Starting Controller Program"
    print("Cache size is %d." % CACHE_SIZE )
    print("Threshold size is %d." % THRESHOLD )

    ######################## P4runtime definitions  ##############

    ## Retriving information about the envirunment:
    bmv2_file_path, p4info_helper = p4runtime_init()
    print "Uploaded p4-runtime system parameters"


    """ POC 08-05-2022 
    s0 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s0',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s0-p4runtime-requests.txt') # TODO configuration file

    # Send master arbitration update message to establish this controller as
    s0.MasterArbitrationUpdate()
    # Install the P4 program on the switches
    s0.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
    writeRule(p4info_helper, s0, "192.0.0.0", mask=8, action="MyIngress.drop", dst_host_eth_addr="08:00:00:00:00:00", sw_exit_post=4)


    """


    ## Set initial definition the the smart switches
    try:
        # acordding to current topology:
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s1-p4runtime-requests.txt') # TODO configuration file
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        for s in [s1, s2, s3]:
            # Send master arbitration update message to establish this controller as
            s.MasterArbitrationUpdate()
            # Install the P4 program on the switches
            s.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
      
        print "Installed P4 Program using SetForwardingPipelineConfig on all switches."

        # s1 basic rules
        writeRule(p4info_helper, s1, "10.0.1.1", mask=32, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:01:11", sw_exit_post=1)
        writeRule(p4info_helper, s1, "10.0.2.2", mask=32, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:02:00", sw_exit_post=2)
        writeRule(p4info_helper, s1, "10.0.3.3", mask=32, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:03:00", sw_exit_post=3)
        # s2 basic rules
        writeRule(p4info_helper, s2, "10.0.1.1", mask=32, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:01:00", sw_exit_post=2)
        writeRule(p4info_helper, s2, "10.0.2.2", mask=32, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:02:22", sw_exit_post=1)
        writeRule(p4info_helper, s2, "10.0.3.3", mask=32, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:03:00", sw_exit_post=3)
        # s3 basic rules
        writeRule(p4info_helper, s3, "10.0.1.1", mask=32, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:01:00", sw_exit_post=3)
        writeRule(p4info_helper, s3, "10.0.2.2", mask=32, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:02:00", sw_exit_post=2)
        writeRule(p4info_helper, s3, "10.0.3.3", mask=32, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:03:33", sw_exit_post=1)
        
        print 'Instlled Basic rules to forward packets normally to hosts in the topology.'
        
        # install default rules - all unknown addresses goto h1
        writeRule(p4info_helper, s1, "192.0.0.0", mask=8, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:00:00", sw_exit_post=4)
        writeRule(p4info_helper, s2, "192.0.0.0", mask=8, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:00:00", sw_exit_post=4)
        writeRule(p4info_helper, s3, "192.0.0.0", mask=8, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:00:00", sw_exit_post=4)
        
        print 'Installed default route for unknown address to be sent to s0' 
        
    ## ending the program
    except KeyboardInterrupt:
        print "Shutting down."


    ######################## READ POLICY  ########################
    
    # upload the policy to our ptogram
    try:
        # load the csv file to local list
        name_csv = sys.argv[1]
    except:
        name_csv = "policy.csv"

    with open(name_csv) as csvfile:
        policies_csv = csv.reader(csvfile, quotechar='|')
        i=0
        for policy in policies_csv:
            try:
                rules[i] = [policy[0], (int)(policy[1]), 0] # initiate treshold to 0
                i += 1
            except:
                pass
            # policy[0] -> policy address
            # policy[1] -> policy mask
    print("Successfully uploaded %d rules for traffic." % len(rules))
    


    ######################## START LISTENING #####################

    iface = 's0-eth4'
    print "Sniffing on %s - ready." % iface
    sys.stdout.flush()


    """
    readTableRules(p4info_helper, s2)
    t = writeRule(p4info_helper, src_sw=s2, dst_ip_addr="192.10.10.10", mask=32, action="MyIngress.drop")
    readTableRules(p4info_helper, s2)    
    
    for response in s2.ReadTableEntries():
        #print(response, "\n")

        for entity in response.entities:
            print(entity)
            print("------------")
            entry = entity.table_entry
            print(entity)
            print("------------")
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            #table_name = p4info_helper.get_tables_name(entry.table_id)
            #print('%s: ' % table_name, end=' ')
            #for m in entry.match:
                #print(p4info_helper.get_match_field_name(table_name, m.field_id), end=' ')
                #print('%r' % (p4info_helper.get_match_field_value(m),), end=' ')
            #action = entry.action.action
            #action_name = p4info_helper.get_actions_name(action.action_id)
            #print('->', action_name, end=' ')
            #for p in action.params:
                #print(p4info_helper.get_action_param_name(action_name, p.param_id), end=' ')
                #print('%r' % p.value, end=' ')
            #print()

    #deleteRule(p4info_helper, src_sw=s2, dst_ip_addr="192.10.10.20", mask=32, action="MyIngress.drop")
    #s2.DeleteTableEntry(t.table_entry)
    readTableRules(p4info_helper, s2)
    """



    # for every packet comming in we handle_pkt --- stuck here untill ctrl + c (listening...)
    packet_counter = 0
    while True:  
        # sniffing
        sniff(count = 1, iface = iface, prn = lambda x: handle_pkt(x))
        packet_counter += 1


        # print values every 50 packets incoming
        if (packet_counter % 50) == 0:
            print("****************")
            print("Packet counter received in the controller = %d:" % packet_counter)
            # todo
            print("****************")

    print("\nController Program Terminated.")  
    # close the connection
    ShutdownAllSwitchConnections()   