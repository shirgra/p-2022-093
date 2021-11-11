"""
    This .py file is generating the flow csv file that has 1,000 flows of traffic.
    after generated, the file should be the input of some host h and run with the command: ty.py flow_name.csv

    @ Shirg
"""

import random
import pandas as pd

def create_add():
    """ :return: IPv4 address as a string  """
    return str(int(random.randint(3, 216))) + "." + str(int(random.randint(0, 255))) + "." + str(int(random.randint(0, 255))) + "." + str(int(random.randint(0, 255)))

def create_size():
    return str(int(random.randint(50, 1500)))

def create_packets_number():
    return str(int(random.randint(15, 500)))

def create_duration():
    return str(random.randint(0, 20)+random.random())

def create_arrival_times_list(packets_num):
    curr_time = 0                            # starting in time 0
    times_arr = [curr_time]                  # initial is always 0
    for i in range(packets_num):
        curr_time += random.random()         # add value < 1 to next packet
        times_arr.append(curr_time)          # add the time to the list
    return times_arr                         # return list at length of packets_num for the flow

if __name__ == '__main__':
    # create 1,000 records of: [Source,	Destination, Size, Arrival Time, Flow ID, Packets, Duration(sec), Arrival Time/1.8]
    arrival_times = create_arrival_times_list(1000)  # creating a logical set of arrival times
    que_list = [[create_add(), create_add(), create_size(), arrival_times[i], i, create_packets_number(), create_duration(), arrival_times[i]/1.8] for i in range(1000)]
    df = pd.DataFrame(que_list, columns =["Source","Destination", "Size", "Arrival Time", "Flow ID", "Packets", "Duration(sec)", "Arrival Time/1.8"])
    df.to_csv('flow_generated.csv', index=False)