#!/usr/bin/env python
import argparse, grpc, sys, os, socket, random, struct, time

from time import sleep
import time
import Queue
import socket
import struct
from scapy.all import *
import thread
import csv
from fcntl import ioctl
import IN


def flow_gen(dst_ip, size):
    print("Starting thread with ip: ")
    print(dst_ip)
    flow_dst_ip = dst_ip
    flow_size = size + "K"
    packet_lenght = "0.015625K"
    bw = "10K"
    # if Packet Lenght is 1 KBytes and BW is 50 Kbits/sec then 
    # BW is 2.5 packets/sec
    cmd = "iperf -u -c "
    cmd += dst_ip
    cmd += " -n "
    cmd += size
    cmd += " -l "
    cmd += packet_lenght
    cmd += " -b "
    cmd += bw
    os.system(cmd)


def main(name_csv='flows.csv'):
    total_size = 0
    count = 0
    with open(name_csv) as csvfile:
        flows = csv.reader(csvfile, quotechar='|')
        for flow in flows:
            if count > 0:
                if count > 1:
                    if flow[0] != 'EOF':
                        thread.start_new_thread(flow_gen, (str(prev_flow[1]), str(prev_flow[2])))
                        sleep((float(flow[3]) - float(prev_flow[3])))
                        prev_flow = flow
                    else:
                        print(prev_flow)
                        thread.start_new_thread(flow_gen, (str(prev_flow[1]), str(prev_flow[2])))
                else:
                    prev_flow = flow
                    count += 1
            else:
                count += 1
    while True:
        sleep(10000)
    # if user pressed ctrl + c
    print("Sender Terminated")


if __name__ == '__main__':
    # expects program to run like this:   tg.py flow.csv
    print("Name of file: "+str(sys.argv))
    try:
	main(str(sys.argv[1]))  # pass as argument the csv file that contains the traffic info
    except:
	main()  		# pass default - flows.csv
