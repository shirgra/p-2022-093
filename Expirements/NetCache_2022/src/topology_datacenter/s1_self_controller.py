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


print "Starting Controller Program"

######################## P4runtime definitions  ##############

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




## Retriving information about the envirunment:
bmv2_file_path, p4info_helper = p4runtime_init()
print "Uploaded p4-runtime system parameters"


""" POC 08-05-2022 """
s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s10',
        address='127.0.0.1:50055',
        device_id=4,
        proto_dump_file='logs/s1-p4runtime-requests.txt') # TODO configuration file

# Send master arbitration update message to establish this controller as
s1.MasterArbitrationUpdate()
# Install the P4 program on the switches
s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
writeRule(p4info_helper, s1, "192.0.0.0", mask=8, action="MyIngress.drop", dst_host_eth_addr="08:00:00:00:00:00", sw_exit_post=4)


""""""