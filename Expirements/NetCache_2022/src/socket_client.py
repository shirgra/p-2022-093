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

         
 
# Create a socket object
s = socket.socket()        
 
# Define the port on which you want to connect
port = 9998           
 
# connect to the server on local computer
s.connect(('127.0.0.1', port))
 
# receive data from the server and decoding to get the string.
print (s.recv(1024).decode())

# send a thank you message to the client. encoding to send byte type.
s.send('No, Thank you'.encode())

# close the connection
s.close()    
     