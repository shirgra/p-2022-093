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




""" main function """
if __name__ == '__main__':

    # listen to packets incoming ...
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    print ifaces


    iface = ifaces[2]
    print "Sniffing on %s - ready." % iface
    sys.stdout.flush()

    # for every packet comming in we handle_pkt --- stuck here untill ctrl + c (listening...)
    while True:
        # please notice - can only handle one packet at a time... may miss some packets in overloads...
        sniff(count = 1, iface = iface, prn = lambda x: x.show2())
    # if user press ctrl + z -> exit
    print("\nController Program Terminated.")  
    exit(0)
