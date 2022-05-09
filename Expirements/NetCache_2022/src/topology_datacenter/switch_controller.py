#!/usr/bin/env python2

######################################################################################################################################## Imports

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

######################################################################################################################################## Global Varriables

THRESHOLD_MISS = 2
THRESHOLD_HIT = 2
CACHE_SIZE = 8
policy_csv_path = "policy.csv"

policy_rules = {}  #  {1: ['192.0.0.0', 32]}  -> { policy_id: ['IP ADDR', MASK] } 


######################################################################################################################################## Class CacheSwitch

class CacheSwitch:
    def __init__(self, name, localhost_port, device_id, helper_localhost_port, helper_device_id):
        self.name_str = name

        # topology properties
        self.localhost_port = localhost_port
        self.address =  '127.0.0.1:' + str(localhost_port)
        self.device_id = device_id

        # cache properties
        self.cache = {}
        self.threshold_miss = 0
        self.threshold_miss = 0

        # initiate bmv2
        self.obj = self.initiate_bmv2_switch()

        # hit counter switch
        self.helper_name_str = name + '0'
        self.helper_localhost_port = helper_localhost_port
        self.helper_address =  '127.0.0.1:' + str(helper_localhost_port)
        self.helper_device_id = helper_device_id
        self.helper_obj = self.initiate_hit_counter_switch()



    def initiate_bmv2_switch(self):
        ## Set initial definition the the smart switches
        obj = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=self.name_str,
            address=self.address,
            device_id=self.device_id,
            proto_dump_file='logs/' + self.name_str + '-p4runtime-requests.txt')         
        # Send master arbitration update message to establish this controller as
        obj.MasterArbitrationUpdate()
        # Install the P4 program on the switches
        obj.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        print("Connected %s to controller." % self.name_str)
        return obj


    def initiate_hit_counter_switch(self):
        ## Set initial definition the the smart switches
        obj = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name=self.helper_name_str,
            address=self.helper_address,
            device_id=self.helper_device_id,
            proto_dump_file='logs/' + self.helper_name_str + '-p4runtime-requests.txt')         
        # Send master arbitration update message to establish this controller as
        obj.MasterArbitrationUpdate()
        # Install the P4 program on the switches
        obj.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        print("Connected %s helper (%s) to controller." % (self.name_str, self.helper_name_str))
        return obj

######################################################################################################################################## Functions

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

    pkt.show()

    """
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

                            readTableRules(p4info_helper, switch)
                            print("\n %s" % str(switch_cache[k][3][0]))
                            switch.DeleteTableEntry(switch_cache[k][3][0])
                            readTableRules(p4info_helper, switch)

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

    """

######################################################################################################################################## MAIN

"""MAIN"""

if __name__ == '__main__':



    print("\n********************************************")
    print("Starting Controller Program")
    print("Cache size is %d." % CACHE_SIZE )
    print("Threshold HIT size is %d." % THRESHOLD_HIT )
    print("Threshold MISS size is %d." % THRESHOLD_MISS )
    print("Policy is read from file: %s." % policy_csv_path )
    print("********************************************")

    ################################################################################################################ load policy rules

    with open(policy_csv_path) as csvfile:
        policies_csv = csv.reader(csvfile, quotechar='|')
        i = 0
        for policy in policies_csv:
            try:
                policy_rules[i] = [policy[0], (int)(policy[1])] # initiate treshold to 0
                i += 1
            except:
                pass
            # policy[0] -> policy address
            # policy[1] -> policy mask
    print("Successfully uploaded %d rules for traffic." % len(policy_rules))
    print("********************************************")

    ################################################################################################################ Connect Switches to controller - p4runtime

    ## Retriving information about the envirunment:
    bmv2_file_path, p4info_helper = p4runtime_init()
    print("Uploaded p4-runtime system parameters.")


    ## connect to switches s1-s6

    # TODO SHIR

    #s1 = CacheSwitch(name= 's1', localhost_port= 50052, device_id=1, helper_localhost_port=50053, helper_device_id=2)
    
    print("Finished connecting to switches in the topology.")
    print("********************************************")

    ################################################################################################################ Insert basic forwarding rules

    # TODO SHIR



    print("Inserted basic forwarding rules to switches.")
    print("********************************************")

    ################################################################################################################ Open threads - listen to hit counts and act on it

    ### ANNA TODO


    print("Opened threads for listening to hit-count.")
    print("********************************************")
    
    ################################################################################################################ Listen to s0-p1 incomint messages to controller

    iface = 's0-eth1'
    packet_counter = 0
     
    print("Starting listening to port-1 on controller - incoming requests...")


    while True:  
        try:

            # sniffing
            sniff(count = 1, iface = iface, prn = lambda x: handle_pkt(x))
            sys.stdout.flush()

            # packet counter
            packet_counter += 1

            # print values every 50 packets incoming
            if (packet_counter % 50) == 0:
                print("********************************************")

                print("Packet counter received in the controller = %d:" % packet_counter)
                
                # todo add all data to print
                


                print("********************************************")

        ################################################################################################################ Ending main

        except KeyboardInterrupt:
            print("\nController Program Terminated.")  
            # close the connection
            ShutdownAllSwitchConnections()








""" Command bank:

# listen to packets incoming ...
ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
print ifaces
sys.stdout.flush()

# s1 basic rules
writeRule(p4info_helper, s1, "10.0.3.3", mask=32, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:03:00", sw_exit_post=3)
# install default rules - all unknown addresses goto h1
writeRule(p4info_helper, s1, "192.0.0.0", mask=8, action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:00:00", sw_exit_post=4)

## ending the program
except KeyboardInterrupt:
print "Shutting down."


"""