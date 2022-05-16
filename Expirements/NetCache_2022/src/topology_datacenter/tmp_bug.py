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
import threading    
from time import sleep

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

THRESHOLD_HIT_AGG = 2
THRESHOLD_HIT_CONTROLLER = 2
CACHE_SIZE = 8
TIME_OUT = 3
policy_csv_path = "../tests_dependencies/policy.csv"
path_to_expiriment = "../../results/Expiriment1/"

policy_rules = {}                   # { policy_id: ['IP ADDR', MASK] } 
controller_miss_record = {}


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

        # TODO BUG
        return table_entry # for deletion

    def check_and_insert_rule_to_cache(self, rule_id, wanted_sw_exit_port):

        # get rule to insert
        global policy_rules
        address   = policy_rules[rule_id]                # get rule address
        mask      = 32

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


######################################################################################################################################## MAIN

"""MAIN"""

if __name__ == '__main__':

    try:
        CACHE_SIZE    = int(sys.argv[1])
        THRESHOLD_HIT = int(sys.argv[2])
    except:
        pass

    print("\n********************************************")
    print("Starting Controller Program")
    print("Cache size is %d." % CACHE_SIZE )
    print("Threshold aggrigation HIT size is %d." % THRESHOLD_HIT_AGG )
    print("Threshold controller HIT size is %d." % THRESHOLD_HIT_CONTROLLER )
    print("Policy is read from file: %s." % policy_csv_path )
    print("********************************************")

    ################################################################################################################ load policy rules

    with open(policy_csv_path) as csvfile:
        policies_csv = csv.reader(csvfile, quotechar='|')
        for policy in policies_csv:
            policy_rules[policy[0]] = policy[1] # { policy_id: ['IP ADDR', MASK] } 
        policy_rules.pop("", None)

    print("Successfully uploaded %d rules for traffic." % len(policy_rules))
    print("********************************************")

    ################################################################################################################ Connect Switches to controller - p4runtime

    ## Retriving information about the envirunment:
    bmv2_file_path, p4info_helper = p4runtime_init()
    print("Uploaded p4-runtime system parameters.")

    ## connect to switches s1-s6
    s1 = CacheSwitch(name= 's1', localhost_port= 50052, device_id=1, helper_localhost_port=50058, helper_device_id=7)

    print("Connected to all switches in the topology.")
    print("********************************************")

    ################################################################################################################ Insert basic forwarding rules

    ## TOR switches
    # s1 to s4 and s5

    
    r1 = s1.insert_rule(dst_ip_addr="192.0.0.1",   mask=32, sw_exit_port=3)
    r2 = s1.insert_rule(dst_ip_addr="192.0.0.2", mask=32, sw_exit_port=4)
    r3 = s1.insert_rule(dst_ip_addr="192.0.0.3", mask=32, sw_exit_port=4)
    r4 = s1.insert_rule(dst_ip_addr="192.0.0.4", mask=32, sw_exit_port=4)

    
    s1.read_tables()

    s1.obj.DeleteTableEntry(r1)

    s1.read_tables()

    s1.obj.DeleteTableEntry(r3)

    s1.read_tables()

    s1.obj.DeleteTableEntry(r2)

    s1.read_tables()








    ################################################################################################################ Ending main

    # close the connection
    ShutdownAllSwitchConnections()
    exit(1)
    # finish threads
    for idNum in [idNum1, idNum2, idNum3, idNum4, idNum5, idNum6]:
        idNum.join()
    print("\nController Program Terminated.")  