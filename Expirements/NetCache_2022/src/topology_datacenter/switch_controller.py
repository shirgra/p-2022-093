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

# default
THRESHOLD_HIT_AGG = 2
THRESHOLD_HIT_CONTROLLER = 2
CACHE_SIZE = 10
policy_csv_path = "../tests_dependencies/policy.csv"
path_to_expiriment = "../../results/"

TOT_PKTS = 10000
TIME_OUT = 8                    # should be 2
TIME_OUT_AGG = 4                # should be 2 or < 5

# Expiriment 1: OPT
THRESHOLD_HIT_CONTROLLER = 20   # should be 22 pps = 
THRESHOLD_HIT_AGG = 10          # should be 11 pps = 
CACHE_SIZE_TOR = 15             # should be 10
CACHE_SIZE_AGG = 15             # should be 10


"""
# Expiriment 2: BASE
THRESHOLD_HIT_AGG = 3           # should be 3
THRESHOLD_HIT_CONTROLLER = 7    # should be 7
CACHE_SIZE_TOR = 20             # should be 20
CACHE_SIZE_AGG = 10             # should be 10

# Expiriment 3: BASE
THRESHOLD_HIT_AGG = 5           # should be 5
THRESHOLD_HIT_CONTROLLER = 5    # should be 5

# Expiriment 4: SHIR
THRESHOLD_HIT_AGG = 3           # should be 5
THRESHOLD_HIT_CONTROLLER = 5    # should be 8

THRESHOLD_HIT_AGG = 1            
THRESHOLD_HIT_CONTROLLER = 1           

# Expiriment NoCache
THRESHOLD_HIT_AGG = 5000           
THRESHOLD_HIT_CONTROLLER = 5000    
CACHE_SIZE_TOR = 1           
CACHE_SIZE_AGG = 1              
TIME_OUT = 1                    
TIME_OUT_AGG = 1               
"""

# Expiriment 1.5: 
THRESHOLD_HIT_CONTROLLER = 7   # should be 22 pps = 
THRESHOLD_HIT_AGG = 3          # should be 11 pps = 
CACHE_SIZE_TOR = 15             # should be 10
CACHE_SIZE_AGG = 15             # should be 10



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
        self.rules = {}
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
        try:
            self.obj.WriteTableEntry(table_entry)
            #print 'Added a new rule in %s:  %s / %d.' % (self.name_str, dst_ip_addr, mask)
        except:
            print 'P4runtime error - in WriteTableEntry'
            print dst_ip_addr
            self.read_tables()

        return table_entry # for deletion

    def check_and_insert_rule_to_cache(self, rule_id, wanted_sw_exit_port, cache_sz = CACHE_SIZE_AGG):

        

        # get rule to insert
        global policy_rules
        address   = policy_rules[rule_id]                # get rule address
        mask      = 32

        # update LRU
        if rule_id in self.cache.keys():
            # update LRU
            for i in self.cache.keys():
                if self.cache[i] < self.cache[rule_id]:
                    self.cache[i] = self.cache[i] + 1
            # set lru 
            self.cache[rule_id] = 0
            return None

        if len(self.cache) < cache_sz:
            # if we have enough room for rule:

            # update LRU
            for i in self.cache.keys():
                self.cache[i] = self.cache[i] + 1

            # add the new rule
            self.cache[rule_id] = 0


        elif len(self.cache) >= cache_sz:
            # if cache is full and rule not in cache-> evict LRU rule

            # update LRU and get rule we want to delete
            rule_to_del = self.cache.keys()[self.cache.values().index(max(list(self.cache.values())))] 
            self.cache.pop(rule_to_del, None) # delete LRU rule

            for i in self.cache.keys():
                self.cache[i] = self.cache[i] + 1

            # set lru 
            self.cache[rule_id] = 0

            # delete LRU rule
            tmp_ = self.rules[rule_to_del]
            try:
                self.obj.DeleteTableEntry(tmp_)
                #print("Deleted a rule in %s:    %s / 32" % (self.name_str, policy_rules[rule_to_del]))
            except:
                print 'P4runtime error - in DeleteTableEntry'
                # close the connection
                ShutdownAllSwitchConnections()

        # insert new rule
        tmp = self.insert_rule(dst_ip_addr=address, mask=mask, sw_exit_port=wanted_sw_exit_port)
        self.rules[rule_id] = tmp

    def only_update_lru(self, rule_id):
        if rule_id in self.cache.keys():
            # update LRU
            for i in self.cache.keys():
                if self.cache[i] < self.cache[rule_id]:
                    self.cache[i] = self.cache[i] + 1
            # set lru 
            self.cache[rule_id] = 0
        else:
            print "Err in 193 - rule_id=%s given is not in cache" % rule_id


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
    # search for rule in policy:
    for pol in policy_rules.keys():
        addr = policy_rules[pol] 
        if addr == wanted_addr: 
            return pol       # return policy_id
    # if rule not found
    return False
    print("THIS IS A BUG - LINE 219")

def write_hits_to_file(data , file):
    hits_file = open(file, 'a')
    hits_file.write(data)
    hits_file.write("\n")

# what is done when receiving a packet
def handle_pkt_controller(pkt):

    global controller_miss_record, s6, start_time

    # parse packet 
    lookup_ip_request   = pkt[IP].dst # the request for an unknown destination
    sys.stdout.flush()

    # check if the address metch our rules
    rule_id = get_rule(lookup_ip_request)

    if rule_id is not False:

        # update threshold miss count
        try:
            controller_miss_record[rule_id] += 1
        except:
            controller_miss_record[rule_id]  = 1
        # update threshold hit count
        try:
            s6.threshold_hit[rule_id] += 1
        except:
            s6.threshold_hit[rule_id] = 1

        # insert rule to switch s6 cache
        s6.check_and_insert_rule_to_cache(rule_id=rule_id, wanted_sw_exit_port=4)

        #s6.read_tables()

        #  to file:
        sw_pps_file = open(path_to_expiriment + 's0_hit_count.txt', "a")
        sw_pps_file.writelines([str(['s0', lookup_ip_request, time.time() - start_time, time.time(), 'hit']), '\n'])
        sw_pps_file.close()

""" LISTENING TO SWITCHES FUNCTIONS (THREADS) """

def thread_TOR_switch(switch, iface):

    global s1, s2, s3

    print("Started thread function - listener (helper) for switch - %s." % switch.name_str)

    # all TOR switches has 3 sons - h1 h2 h3
    hit_counts = { 's1': {}, 's2': {}, 's3': {} }

    # open file to every switch
    if switch == s1:
        name_file = path_to_expiriment + 's1_hit_count.txt'
        sw_hits_file = open(name_file, 'w')
    elif switch == s2:
        name_file = path_to_expiriment + 's2_hit_count.txt'
        sw_hits_file = open(name_file, 'w')
    else:
        name_file = path_to_expiriment + 's3_hit_count.txt'
        sw_hits_file = open(name_file, 'w')

    # start time for every switch to hits file
    start_thread = time.time() 

    def handle_pkt(pkt):

        # parse packet 
        lookup_ip_request   = pkt[IP].dst # the request for an unknown destination
        source_ip_address   = pkt[IP].src # the request source ipv4 address
        
        sys.stdout.flush()

        # check if the address metch our rules - ip source
        rule_id = get_rule(lookup_ip_request)

        if   source_ip_address == '10.0.1.1':
            sw = s1
        elif source_ip_address == '10.0.2.2':
            sw = s2
        elif source_ip_address == '10.0.3.3':
            sw = s3  
        
        try:
            sw = sw # check if assigned
        except:
            print "ERR in 413: source_ip_address not found: %s" % source_ip_address
            return None

        # update counter
        try:
            hit_counts[switch.name_str][rule_id] += 1
        except:
            hit_counts[switch.name_str][rule_id]  = 1

        # write data to file [switch,timestemp,'hit']
        write_hits_to_file(str([switch.name_str,lookup_ip_request, time.time() - start_thread , time.time(), "hit"]),name_file)
        switch.only_update_lru(rule_id)

        # update records in switch
        try:
            sw.threshold_hit[rule_id] += 1
        except:
            sw.threshold_hit[rule_id] = 1


    # listen to traffic
    while True:
        sniff(count = 1, iface = iface, prn = lambda pkt: handle_pkt(pkt))
        sys.stdout.flush()

def thread_low_aggrigation_switches(switch, iface):

    global s1, s2, s3 , interval_time

    print("Started thread function - listener (helper) for switch - %s." % switch.name_str)

    # all AGG switches has 3 sons - h1 h2 h3
    hit_counts = { 's1': {}, 's2': {}, 's3': {} }

    # open hit file to every switch
    if switch == s4:
        name_file = path_to_expiriment + 's4_hit_count.txt'
        sw_hits_file = open(name_file, 'w')
    else:
        name_file = path_to_expiriment + 's5_hit_count.txt'
        sw_hits_file = open(name_file, 'w')

    # start time for every switch to hits file
    start_thread = time.time()

    def handle_pkt(pkt):

        # parse packet 
        lookup_ip_request   = pkt[IP].dst # the request for an unknown destination
        source_ip_address   = pkt[IP].src # the request source ipv4 address
        sys.stdout.flush()

        # check if the address metch our rules - ip source
        rule_id = get_rule(lookup_ip_request)

        if   source_ip_address == '10.0.1.1':
            sw = s1
        elif source_ip_address == '10.0.2.2':
            sw = s2
        elif source_ip_address == '10.0.3.3':
            sw = s3

        try:
            sw = sw # check if assigned
        except:
            print "ERR in 413: source_ip_address not found: %s" % source_ip_address
            return None

        # update counter
        try:
            hit_counts[sw.name_str][rule_id][0] += 1
        except:
            start_time = time.time()
            hit_counts[sw.name_str][rule_id]  = [1, start_time]

        #stop clock to check if timeout
        interval_time = time.time() - hit_counts[sw.name_str][rule_id][1]

        if rule_id in switch.cache.keys():
            switch.only_update_lru(rule_id)

        # if we crossed the miss threshold for this rule
        if hit_counts[sw.name_str][rule_id][0] >= THRESHOLD_HIT_AGG and interval_time < TIME_OUT_AGG:

            # insert rule to switch s6 cache
            sw.check_and_insert_rule_to_cache(rule_id=rule_id, wanted_sw_exit_port=2, cache_sz = CACHE_SIZE_TOR) # 2 listener (HIT)
            
            # TODO BUG
            # delete rule from switch

            # reset threshold count
            hit_counts[sw.name_str].pop(rule_id, None)

        # reset the all varibles and start counting again
        elif interval_time >= TIME_OUT_AGG:
            hit_counts[sw.name_str][rule_id][0]  = 1
            hit_counts[sw.name_str][rule_id][1]  = start_time = time.time()

        # write data to file [switch,destination ,timestemp,'hit']
        write_hits_to_file(str([switch.name_str,lookup_ip_request, time.time() - start_thread , time.time(), "hit"]),name_file)
        # update records in switch
        try:
            sw.threshold_hit[rule_id] += 1
        except:
            sw.threshold_hit[rule_id] = 1

    
    
    # listen to traffic
    while True:
        sniff(count = 1, iface = iface, prn = lambda pkt: handle_pkt(pkt))
        sys.stdout.flush()

def thread_high_aggrigation_switches(switch, iface):

    global s4, s5

    # s60 listening
    # 192  .0.0.0/12 GOTO s4
    # 192.240.0.0/12 GOTO s5

    print("Started thread function - listener (helper) for switch - %s." % switch.name_str)

    # all high_aggrigation switches has 2 sons - h4 h5
    hit_counts = { 's4': {}, 's5': {}}

    # open hit file to every switch
    name_file = path_to_expiriment + 's6_hit_count.txt'
    sw_hits_file = open(name_file, 'w')

    # start time for every switch to hits file
    start_thread = time.time()

    # keep record according to destIP address range
    def handle_pkt(pkt):

        # parse packet 
        lookup_ip_request   = pkt[IP].dst # the request for an unknown destination
        sys.stdout.flush()

        # check if the address metch our rules
        rule_id = get_rule(lookup_ip_request)

        if longestCommonPrefix(lookup_ip_request, '192.240.0.0') >= 12:
            sw = s5
        else:
            sw = s4

        # update counter
        try:
            hit_counts[sw.name_str][rule_id][0] += 1
        except:
            start_time = time.time()
            hit_counts[sw.name_str][rule_id]  = [1, start_time]

        #stop clock to check if timeout
        interval_time = time.time() - hit_counts[sw.name_str][rule_id][1]
        

        if rule_id in switch.cache.keys():
            switch.only_update_lru(rule_id)


        # if we crossed the miss threshold for this rule
        if hit_counts[sw.name_str][rule_id][0] >= THRESHOLD_HIT_CONTROLLER and interval_time < TIME_OUT:

            # insert rule to switch s6 cache
            sw.check_and_insert_rule_to_cache(rule_id=rule_id, wanted_sw_exit_port=4) # 4 listener (HIT)

            # TODO BUG
            # delete rule from switch

            # reset threshold count
            hit_counts[sw.name_str].pop(rule_id, None)

        # reset the all varibles and start counting again
        elif interval_time >= TIME_OUT:
            hit_counts[sw.name_str][rule_id][0]  = 1
            hit_counts[sw.name_str][rule_id][1]  = start_time = time.time()
    
        # write data to file [switch,destination ,timestemp,'hit']
        write_hits_to_file(str([switch.name_str,lookup_ip_request, time.time() - start_thread , time.time(), "hit"]),name_file)
        # update records in switch
        try:
            sw.threshold_hit[rule_id] += 1
        except:
            sw.threshold_hit[rule_id] = 1
    
    # listen to traffic
    while True:
        sniff(count = 1, iface = iface, prn = lambda pkt: handle_pkt(pkt))
        sys.stdout.flush()

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
    print("Cache size TOR is %d." % CACHE_SIZE_TOR )
    print("Cache size AGG is %d." % CACHE_SIZE_AGG )
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

    if "connect to switches":

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

    if "insert rules":

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

    if "open threads":

        # opening new 6 threads
        idNum1 = threading.Thread(target=thread_TOR_switch, args=(s1, 's1-eth2'))
        idNum2 = threading.Thread(target=thread_TOR_switch, args=(s2, 's2-eth2'))
        idNum3 = threading.Thread(target=thread_TOR_switch, args=(s3, 's3-eth2'))
        idNum4 = threading.Thread(target=thread_low_aggrigation_switches, args=(s4, 's4-eth4'))
        idNum5 = threading.Thread(target=thread_low_aggrigation_switches, args=(s5, 's5-eth4'))
        idNum6 = threading.Thread(target=thread_high_aggrigation_switches, args=(s6, 's6-eth4'))

        # starting threads
        for idNum in [idNum1, idNum2, idNum3, idNum4, idNum5, idNum6]:
            idNum.start()
        sleep(2)

        print("Opened threads for listening to hit-count.")
        print("********************************************")
    
    ################################################################################################################ Listen to s0-p1 incomint messages to controller

    if "listern":

        iface = 's0-eth1'
        time_tmp = time.time()
        packet_counter = 0
        sw0_file = open(path_to_expiriment + 's0_hit_count.txt', 'w')
        start_time = time.time()
         
        print("Starting listening to port-1 on controller - incoming requests...")

        flagWhile = 1
        while flagWhile:  

            # sniffing
            sniff(count = 1, iface = iface, prn = lambda x: handle_pkt_controller(x))

            # packet counter
            packet_counter += 1
            sys.stdout.flush()


        """

        while True:
            if time.time() - time_tmp > 20:
                time_tmp = time.time()
                # print values every 10 seconds
                print("********************************************")
                print("Packet counter received in the controller = %d:" % packet_counter)
                for s in [s1, s2, s3, s4, s5, s6]:
                    print("In %s: cache size now is: -%d-, and total -%d- hit counts in switch cache." % (s.name_str, len(s.cache), sum(s.threshold_hit.values())))            
                print("********************************************")
        
        """

    ################################################################################################################ Ending main

    # close the connection
    ShutdownAllSwitchConnections()
    exit(1)
    # finish threads
    for idNum in [idNum1, idNum2, idNum3, idNum4, idNum5, idNum6]:
        idNum.join()
    print("\nController Program Terminated.")  