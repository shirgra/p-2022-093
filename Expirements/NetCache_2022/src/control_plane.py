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
        print "MyIngress.ipv4_forward"
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
        print "MyIngress.drop"
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
    """
    Reads the table entries from all tables on the switch.
    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            table_name = p4info_helper.get_tables_name(entry.table_id)
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            
            print 'Table %s; ' % (table_name),
            for m in entry.match:
                print '%s' % p4info_helper.get_match_field_name(table_name, m.field_id),
                # print address ipv4
                str_tmp = list((p4info_helper.get_match_field_value(m),)[0][0]) #'\n\x00\x02\x02'
                for s in str_tmp:
                    print '%s.' % ord(s),
            print '->', action_name, ':',
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '=', 
                print '%r' % p.value,
                print ';',
            print 

"""MAIN"""

if __name__ == '__main__':

    ## Retriving information about the envirunment:
    if True:
        parser = argparse.ArgumentParser(description='P4Runtime Controller')
        parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                            type=str, action="store", required=False,
                            default='./build_dependencies/basic_tunnel.p4.p4info.txt')
        parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                            type=str, action="store", required=False,
                            default='./build_dependencies/basic_tunnel.json')
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

    ## Set initial definition the the smart switches
    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')
        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        print "\nInstalled P4 Program using SetForwardingPipelineConfig on all switches."

        # loading after 10 seconds
        print '\nWaiting 10 seconds before installing the basic rules...'
        #sleep(10)
        
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
        print 'Instlled Basic rules.'

        
        # install default rules - all unknown addresses goto h1
        writeStaticRule(p4info_helper, s1, "192.0.0.0", mask=8, 
                    action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:01:11", sw_exit_post=1)
        writeStaticRule(p4info_helper, s2, "192.0.0.0", mask=8, 
                    action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:01:11", sw_exit_post=2)
        writeStaticRule(p4info_helper, s3, "192.0.0.0", mask=8, 
                    action="MyIngress.ipv4_forward", dst_host_eth_addr="08:00:00:00:01:11", sw_exit_post=2)
        print 'Installed default Cache rules'
        

        # install test rules - all unknown addresses goto h1
        table_entry_tst = writeStaticRule(p4info_helper, s2, "192.168.1.1", mask=32, action="MyIngress.drop")
        print '\nInstalled Cache rule to drop'
        readTableRules(p4info_helper, s2)
        sleep(20)
        # delete the rule
        # STOPPED HERE - TODO
        s2.DeleteTableEntry(table_entry_tst)
        print '\nDeleted Cache rule to drop'
        readTableRules(p4info_helper, s2)


        # Print the tunnel counters every 2 seconds
        while True:
            print '\n----- Reading Data -----'
            readTableRules(p4info_helper, s1)
            readTableRules(p4info_helper, s2)
            readTableRules(p4info_helper, s3)
            sleep(10)


    ## ending the program
    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        print "gRPC Error:", e.details()
    ShutdownAllSwitchConnections()   