#!/usr/bin/env python3
# python 3.5

import matplotlib.pyplot as plt
import numpy as np
import sys

# initial uploading for traffic flows
if len(sys.argv)<2:
    print('Need to pass a folder name')
    exit(1)
graph_name = folder = sys.argv[1]

res_Tor = []
res_agg = []
res_core = []
res_controler = []

# defines
x_points = np.arange(0, 200, 1)

for s in range(0, 7):
    res = []
    name = r'' + folder + '/s' + str(s) + '_hit_count.txt'
    switch_hit_file = open(name, 'r')
    alllines = switch_hit_file.readlines()
    for line in alllines:
        tmp = [line[1:-2].split(", ")[i][0:-1] for i in range(4)]
        res.append(float(tmp[2]))

    if  s == 1 or s == 2 or s == 3:
        res_Tor.extend(res)
    elif s == 0:
        res_controler.extend(res)    
    elif s == 4 or s == 5:
        res_agg.extend(res)
    elif s == 6:
        res_core.extend(res)

    y_points = [0 for i in list(range(len(x_points)))]

    # fill points for switch
    for hit in res:
        for beg in range(len(x_points)):
            if x_points[beg] <= hit <= x_points[beg] + 1:
                y_points[beg] += 1

# new type graph
total_min = 9 ** 10
tot_pckt = 0 
res = []
# find start point
for h in range(1, 4):
    try:
        name = r'' + folder + '/h' + str(h) + '_pps.txt'
        pps_file = open(name, 'r')
        alllines = pps_file.readlines()
        min_time = float(alllines[0].split()[0])
        if min_time < total_min:
            total_min = min_time
    except:
        pass

for h in range(1, 4):
    try:
        name = r'' + folder + '/h' + str(h) + '_pps.txt'
        pps_file = open(name, 'r')
        alllines = pps_file.readlines()
        tmp = 0
        for line in alllines:
            t = float(line.split()[0])
            # tmp = float(line.split()[1])
            tmp += 70
            res.append([t - total_min, 70])
            tot_pckt+=70
    except:
        pass

# get average p/s
my_points = [0 for i in list(range(len(x_points)))]

# get the average for a second
for pps in res:
    for beg in range(len(x_points)):
        try:
            if x_points[beg] <= pps[0] <= x_points[beg + 1]:
                my_points[beg] += pps[1]
        except:
            pass

import itertools

my_points = list(itertools.accumulate(my_points))

fig, ax = plt.subplots()
for res, name, color, linestyle in zip([res_core, res_agg, res_Tor], ["Core Switch", "Aggregation Switches", "TOR Switches"], ["Black", "Cyan", "Green"], ['--', '-', '-.']):
    # build slices
    y_points = [0 for i in list(range(len(x_points)))]
    # fill points for switch
    for hit in res:
        for beg in range(len(x_points)):
            if x_points[beg] <= hit <= x_points[beg] + 1:
                try:
                    y_points[beg] += 1
                except:
                    y_points[beg] = 1
    # plot
    ax.plot(my_points, y_points, color=color, linestyle=linestyle, linewidth=2.0, label=name)
title = graph_name
plt.title("Hit-in-Cache hit count per Second. Exp.#" + title)
ax.legend()
ax.grid(True)
plt.xlabel("Average Packets so far")
plt.ylabel("Hit-in-cache count per Second")
# plt.show()
#plt.savefig(title + "_func_of_pkts.png")
fig.set_size_inches(10, 5)
plt.savefig(title + "_per_pkts.png")
plt.clf()




### second graph


x_points = [0, 1, 2, 3] # [s123, s45, s6, s0]


tot_tor = len(res_Tor)  # no. of total hits in s123
tot_agg = len(res_agg)  # no. of total hits in s45
tot_core = len(res_core)  # no. of total hits in s6
tot_controller = len(res_controler)  # no. of total hits in s0

# tot pckts sent


print((tot_tor+tot_agg+tot_core+tot_controller)/tot_pckt, " %", " of pakcets sent.")

y_points = [tot_tor/tot_pckt, tot_agg/tot_pckt, tot_core/tot_pckt, tot_controller/tot_pckt]
#print(y_points)
#print(tot_pckt)
#print(sum(y_points))


labels = ["TOR Switches", "Aggregation Switch", "Core Switches", "Controller"]


x = np.arange(len(labels))  # the label locations

#width = 0.35  # the width of the bars

fig, ax = plt.subplots()
rects1 = ax.bar(x, y_points, label='Men')

# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('%' + " of Total packets sent")
ax.set_title('Average Number of hops')
ax.set_xticks(x)
#ax.legend()


plt.show()



print("Done.")
