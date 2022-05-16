#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep
# Import P4Runtime lib from parent utils dir Probably there's a better way of doing this.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),'../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper
import time # using time module
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


"""HELP FUNCTIONS"""

def writeBasicSwitchRules(p4info_helper, src_sw, host_eth_addr, host_ip_addr,
    sw_port_2_eth_addr, sw_port_2_ip_addr,
    sw_port_3_eth_addr, sw_port_3_ip_addr):
    
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (host_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": host_eth_addr,
            "port": 1
        })
    src_sw.WriteTableEntry(table_entry)

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (sw_port_2_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": sw_port_2_eth_addr,
            "port": 2
        })
    src_sw.WriteTableEntry(table_entry)

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (sw_port_3_ip_addr, 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": sw_port_3_eth_addr,
            "port": 3
        })
    src_sw.WriteTableEntry(table_entry)

    print "Installed basic topology rules on %s" % src_sw.name

def writeStaticRule(p4info_helper, src_sw, dst_ip_addr, mask=32, 
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
    print 'Added a new rule - %s/%d -> %s' % (dst_ip_addr, mask, action)
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

"""MAIN"""

if __name__ == '__main__':

    print "Starting Controller Program"
    time_start = time.time()

    ## Retriving information about the envirunment:
    if True:
        parser = argparse.ArgumentParser(description='P4Runtime Controller')
        parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                            type=str, action="store", required=False,
                            default='./build_dependencies/net_cache.p4.p4info.txt')
        parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                            type=str, action="store", required=False,
                            default='./build_dependencies/net_cache.json')
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

    print "Uploaded p4-runtime system parameters"


    ## Set initial definition the the smart switches
    try:
        # Create a switch connection object;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='hat_topology/logs/s1-p4runtime-requests.txt') # TODO configuration file
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='hat_topology/logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='hat_topology/logs/s3-p4runtime-requests.txt')
        # Send master arbitration update message to establish this controller as
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        
        print "Installed P4 Program using SetForwardingPipelineConfig on all switches."

        # Write the beasic rules - triangle topology
        writeBasicSwitchRules(p4info_helper, src_sw=s1,
                        host_eth_addr="08:00:00:00:01:11", host_ip_addr="10.0.1.1",
                        sw_port_2_eth_addr="08:00:00:00:02:00", sw_port_2_ip_addr="10.0.2.2",
                        sw_port_3_eth_addr="08:00:00:00:03:00", sw_port_3_ip_addr="10.0.3.3")
        writeBasicSwitchRules(p4info_helper, src_sw=s2,
                        host_eth_addr="08:00:00:00:02:22", host_ip_addr="10.0.2.2",
                        sw_port_2_eth_addr="08:00:00:00:01:00", sw_port_2_ip_addr="10.0.1.1",
                        sw_port_3_eth_addr="08:00:00:00:03:00", sw_port_3_ip_addr="10.0.3.3")
        writeBasicSwitchRules(p4info_helper, src_sw=s3,
                        host_eth_addr="08:00:00:00:03:33", host_ip_addr="10.0.3.3",
                        sw_port_2_eth_addr="08:00:00:00:01:00", sw_port_2_ip_addr="10.0.1.1",
                        sw_port_3_eth_addr="08:00:00:00:02:00", sw_port_3_ip_addr="10.0.2.2")
        
        print 'Instlled Basic rules to forward packets normally to hosts in the topology.'
        
        # install default rules - all unknown addresses goto h1
        writeStaticRule(p4info_helper, s1, "192.0.0.0", mask=8, 
                    action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:01:11", sw_exit_post=1)
        writeStaticRule(p4info_helper, s2, "192.0.0.0", mask=8, 
                    action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:01:11", sw_exit_post=2)
        writeStaticRule(p4info_helper, s3, "192.0.0.0", mask=8, 
                    action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:01:11", sw_exit_post=2)

        print 'Installed default route for unknown address to be sent to h1 (inside controller)' # TODO fix-controller-bug
        

        # prepare main work of the controller
        f = open("rules.txt", "r")
        rules_keeper = {}

        # start receiving thread to listen to rules come in
        # Thread that listen/snif


        # listen to packets incoming ...
        ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
        print ifaces


        iface = ifaces[1]
        print "Sniffing on %s - ready." % iface
        sys.stdout.flush()

        # for every packet comming in we handle_pkt --- stuck here untill ctrl + c (listening...)
        while True:
            # please notice - can only handle one packet at a time... may miss some packets in overloads...
            sniff(count = 1, iface = iface, prn = lambda x: x.show2())
        # if user press ctrl + z -> exit
        print("\nController Program Terminated.")  
        exit(0)






        """
        # read from file
        tmp = f.read()
        if tmp:
            # if read somthing new - split to rule format
            rules_ = tmp.split('\n')
            for rule in rules_:
                if rule:
                    print(rule)
                    # parse rule "['W', '192.10.10.25', 32]"
                    action = rule[2] # either 'W' 'D'
                    address = rule[7:19] # '192.10.10.25'
                    mask = int(rule[22:24]) # 32
                     MAKE ACTION 
                    if (action == 'W') and ((address, mask) not in rules_keeper.keys()):
                        # write rule to switch
                        print("Write rule to switch")
                        # write rule
                        table_entry = writeStaticRule(p4info_helper, s2, address, mask=mask, action="MyIngress.drop")
                        # add to local tracking of rules
                        rules_keeper[(address, mask)] = table_entry
                    elif action == 'D':
                        # delete rule from switch
                        print("Delete rule from switch")
                        # get the table entry and remove it
                        table_entry = rules_keeper.get((address, mask))
                        rules_keeper.pop((address, mask))
                        # delete rule
                        s2.DeleteTableEntry(table_entry)
                    # readTableRules(p4info_helper, s2)
        sleep(0.1) # not to jem the hole VM - todo
        """
            





    ## ending the program
    except KeyboardInterrupt:
        print " Shutting down."
    # close the connection
    ShutdownAllSwitchConnections()   



"""
# STOPPED HERE - TODO
# install test rules - all unknown addresses goto h1
table_entry_tst = writeStaticRule(p4info_helper, s2, "192.168.1.1", mask=32, action="MyIngress.drop")
print '\nInstalled Cache rule'
readTableRules(p4info_helper, s2)
sleep(20)
# delete the rule
s2.DeleteTableEntry(table_entry_tst)
print '\nDeleted Cache rule to drop'
readTableRules(p4info_helper, s2)

sleep(1)
t = time.time()
print(t-time_start)
"""