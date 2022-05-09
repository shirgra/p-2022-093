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

policy_rules = {}                   # { policy_id: ['IP ADDR', MASK] } 
controller_threshold_miss = {}      # { policy_id: [th counter] }


######################################################################################################################################## Class CacheSwitch

class CacheSwitch:
    def __init__(self, name, localhost_port, device_id, helper_localhost_port, helper_device_id):
        self.name_str = name
        # topology properties
        self.localhost_port = localhost_port
        self.address =  '127.0.0.1:' + str(localhost_port)
        self.device_id = device_id
        self.obj = self.initiate_bmv2_switch()
        # cache properties
        self.cache = {}             # { policy_id: [LRU flag] } 
        self.threshold_hit  = {}    # { policy_id: [th counter] } 
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

    def insert_rule(self, dst_ip_addr, mask, sw_exit_port):
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.ipv4_lpm",
            match_fields={
                "hdr.ipv4.dstAddr": (dst_ip_addr, mask)
            },
            action_name="MyIngress.ipv4_forward",
            action_params={
                "dstAddr": "08:00:00:00:00:00",
                "port": sw_exit_port
            })
        self.obj.WriteTableEntry(table_entry)
        print 'Added a new rule in %s:  %s / %d.' % (self.name_str, dst_ip_addr, mask)

        # XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        # TODO BUG
        return table_entry # for deletion

    def check_and_insert_rule_to_cache(self, rule_id, wanted_sw_exit_port):

        # get rule to insert
        global policy_rules
        address   = policy_rules[rule_id][0]                 # get rule address
        mask      = policy_rules[rule_id][1]                 # get rule mask

        # make sure rule is not in switch cache
        if rule_id in self.cache.keys():
            return False

        if len(self.cache) < CACHE_SIZE:
            # if we have enough room for rule:

            # update LRU
            for i in self.cache.keys():
                self.cache[i] = self.cache[i] + 1
            self.cache[rule_id] = 1

        else:
            # if cache is full -> evict LRU rule

            # update LRU and get rule we want to delete
            for i in self.cache.keys():
                if self.cache[i] >= CACHE_SIZE:
                    rule_to_del = i
                else:
                    self.cache[i] = self.cache[i] + 1
            self.cache.pop(rule_to_del, None) # delete LRU rule
            self.cache[rule_id] = 1           # new rule

            # delete LRU rule
            # rule_to_del
            # TODO bug - delete rule!!!!!!!
        
        # insert new rule
        self.insert_rule(dst_ip_addr=address, mask=mask, sw_exit_port=wanted_sw_exit_port)

    def read_tables(self):
        print('----- Reading tables rules for %s -----' % self.name_str)
        for response in self.obj.ReadTableEntries():
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
                    print(' / %d' % list((p4info_helper.get_match_field_value(m),)[0])[1])
                print
        print('--------------------------------------')

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

""" CONTROLLER ALGORITHM FUNCTIONS """

# gets two lists of ipv4 addresses (str) and return the number of bits prefix match (int)
def longestCommonPrefix(addr_1, addr_2):
    # convert to binary - from "192.168.22.1" to "10010111.10000111.00001010.11111111"
    addr_1 = str(''.join([bin(int(x)+256)[3:] for x in addr_1.split('.')]))
    addr_2 = str(''.join([bin(int(x)+256)[3:] for x in addr_2.split('.')]))

    # get the longest string of bits in the addresses
    res = 0
    for i in range(32):
        if addr_1[i] == addr_2[i]:
            res += 1
        else:
            return res
    return res

# gets address as str and return the rule if exists or false otherwise
def get_rule(wanted_addr):
    global policy_rules
    # search for rule in policy:
    for pol in policy_rules.keys():
        addr = policy_rules[pol][0] # { policy_id: ['IP ADDR', MASK] }
        mask = policy_rules[pol][1] # { policy_id: ['IP ADDR', MASK] }
        if (longestCommonPrefix(wanted_addr, addr) >= mask): 
            return pol       # return policy_id
    # if rule not found
    return False

# what is done when receiving a packet
def handle_pkt_controller(pkt):

    global controller_threshold_miss, s6

    # parse packet 
    lookup_ip_request   = pkt[IP].dst # the request for an unknown destination
    sys.stdout.flush()

    # check if the address metch our rules
    rule_id = get_rule(lookup_ip_request)

    if rule_id:

        # update threshold miss count
        try:
            controller_threshold_miss[rule_id] += 1
        except:
            controller_threshold_miss[rule_id]  = 1

        # if we crossed the miss threshold for this rule
        if controller_threshold_miss[rule_id] >= THRESHOLD_MISS:

            # insert rule to switch s6 cache
            s6.check_and_insert_rule_to_cache(rule_id=rule_id, wanted_sw_exit_port=4)

            # reset threshold count
            controller_threshold_miss[rule_id]  = 0

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
        i = 1
        for policy in policies_csv:
            try:
                policy_rules[i] = [policy[0], (int)(policy[1])] # { policy_id: ['IP ADDR', MASK] } 
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
    s1 = CacheSwitch(name= 's1', localhost_port= 50052, device_id=1, helper_localhost_port=50058, helper_device_id=7)
    s2 = CacheSwitch(name= 's2', localhost_port= 50053, device_id=2, helper_localhost_port=50059, helper_device_id=8)
    s3 = CacheSwitch(name= 's3', localhost_port= 50054, device_id=3, helper_localhost_port=50060, helper_device_id=9)
    s4 = CacheSwitch(name= 's4', localhost_port= 50055, device_id=4, helper_localhost_port=50061, helper_device_id=10)
    s5 = CacheSwitch(name= 's5', localhost_port= 50056, device_id=5, helper_localhost_port=50062, helper_device_id=11)
    s6 = CacheSwitch(name= 's6', localhost_port= 50057, device_id=6, helper_localhost_port=50063, helper_device_id=12)

    print("Connected to all switches in the topology.")
    print("********************************************")

    ################################################################################################################ Insert basic forwarding rules

    ## TOR switches
    # s1 to s4 and s5
    s1.insert_rule(dst_ip_addr="192.0.0.0",   mask=12, sw_exit_port=3)
    s1.insert_rule(dst_ip_addr="192.240.0.0", mask=12, sw_exit_port=4)
    # s2 to s4 and s5
    s2.insert_rule(dst_ip_addr="192.0.0.0",   mask=12, sw_exit_port=3)
    s2.insert_rule(dst_ip_addr="192.240.0.0", mask=12, sw_exit_port=4)
    # s3 to s4 and s5
    s3.insert_rule(dst_ip_addr="192.0.0.0",   mask=12, sw_exit_port=3)
    s3.insert_rule(dst_ip_addr="192.240.0.0", mask=12, sw_exit_port=4)

    ## Aggregation switches
    # s4 to s6
    s4.insert_rule(dst_ip_addr="192.0.0.0",   mask=8, sw_exit_port=5)
    # s5 to s6
    s5.insert_rule(dst_ip_addr="192.0.0.0",   mask=8, sw_exit_port=5)
    # s6 to s0-controller
    s6.insert_rule(dst_ip_addr="192.0.0.0",   mask=8, sw_exit_port=1)

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

    roof = 0
    while roof < 100 :  
        roof +=1

        # sniffing
        sniff(count = 1, iface = iface, prn = lambda x: handle_pkt_controller(x))
        sys.stdout.flush()

        # packet counter
        packet_counter += 1

        # print values every 50 packets incoming
        if (packet_counter % 20) == 0:
            print("********************************************")
            print("Packet counter received in the controller = %d:" % packet_counter)
            for s in [s1, s2, s3, s4, s5, s6]:
                print("In %s: cache size now is: -%d-, and total -%d- hit counts in switch cache." % (s.name_str, len(s.cache), sum(s.threshold_hit.values())))            
            print("********************************************")
        
    ################################################################################################################ Ending main

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