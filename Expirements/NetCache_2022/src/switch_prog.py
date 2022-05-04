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

  


# what is done when receiving a packet
def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234 and bytes(pkt[IP].dst) == '10.0.2.2': #TODO CHANGE FOR HOST
        new_rule = bytes(pkt[TCP].payload)
        sys.stdout.flush()
        insert_cache(new_rule = new_rule)







""" threads and main functions """

def thread_receiver():
    print("Receiver Thread is starting")
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[1]
    #print "sniffing on %s" % iface
    sys.stdout.flush()
	# for every packet comming in we handle_pkt --- stuck here untill ctrl + c (listening...)
	while True:
    	# please notice - can only handle one packet at a time... may miss some packets in overloads...
    	sniff(count = 1, iface = iface, prn = lambda x: x.show2())
    print("Receiver Thread finished")




if __name__ == '__main__':

	print("Staring  Controller") # TODO change name of host

    # start receiving thread to listen to rules come in
    # Thread that listen/snif
    receiver = threading.Thread(target=thread_receiver)
    receiver.start()
    time.sleep(3)


    # Create a socket object
	c = socket.socket()        
	 
	# Define the port on which you want to connect
	port = 9998           
	 
	# connect to the server on local computer
	c.connect(('127.0.0.1', port))
	 
	# receive data from the server and decoding to get the string.
	print (c.recv(1024).decode())

	# send a thank you message to the client. encoding to send byte type.
	c.send('No, Thank you'.encode())

	# close the connection
	c.close()    

    



    # end Thread that listen/snif
    receiver.join()
    print("Finished Program Sucsessfully.")
    
