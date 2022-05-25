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
res_cont = []

# build slices
x_points = np.arange(0, 200, 1)

for s in range(1, 7):
    res = []
    name = r'' + folder + '/s' + str(s) + '_hit_count.txt'
    switch_hit_file = open(name, 'r')
    alllines = switch_hit_file.readlines()
    for line in alllines:
        tmp = [line[1:-2].split(", ")[i][0:-1] for i in range(4)]
        res.append(float(tmp[2]))

    if s < 4:
        res_Tor.extend(res)
    elif s == 4 or s == 5:
        res_agg.extend(res)
    elif s == 6:
        res_cont.extend(res)

    y_points = [0 for i in list(range(len(x_points)))]

    # fill points for switch
    for hit in res:
        for beg in range(len(x_points)):
            if x_points[beg] <= hit <= x_points[beg] + 1:
                y_points[beg] += 1

    # plot
    # ax.plot(x_points, y_points, linewidth=2.0, label="s" + str(s))
    # ax.set(xlim=(0, 8), xticks=np.arange(1, 8),
    #        ylim=(0, 8), yticks=np.arange(1, 8))

# title = graph_name
# plt.title(title)
# ax.legend()
# ax.grid(True)
# plt.xlabel("Time [seconds]")
# plt.ylabel("Hit-in-cache count")
# # plt.show()
# # plt.savefig(title + ".jpg")
# plt.clf()

fig, ax = plt.subplots()
for res, name in zip([res_agg, res_Tor, res_cont], ["Aggregation Switches", "TOR Switches", "Controller Switch"]):
    # build slices
    y_points = [None for i in list(range(len(x_points)))]
    # fill points for switch
    for hit in res:
        for beg in range(len(x_points)):
            if x_points[beg] <= hit <= x_points[beg] + 1:
                try:
                    y_points[beg] += 1
                except:
                    y_points[beg] = 1
    # plot
    ax.plot(x_points, y_points, linewidth=2.0, label=name)
title = graph_name
plt.title(title)
ax.legend()
ax.grid(True)
plt.xlabel("Time [seconds]")
plt.ylabel("Hit-in-cache count")
# plt.show()
plt.savefig("../" + title + "_func_of_time.png")
plt.clf()


# new type graph
total_min = 9 ** 10
res = []
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
for res, name in zip([res_agg, res_Tor, res_cont], ["Aggregation Switches", "TOR Switches", "Controller Switch"]):
    # build slices
    y_points = [None for i in list(range(len(x_points)))]
    # fill points for switch
    for hit in res:
        for beg in range(len(x_points)):
            if x_points[beg] <= hit <= x_points[beg] + 1:
                try:
                    y_points[beg] += 1
                except:
                    y_points[beg] = 1
    # plot
    ax.plot(my_points, y_points, linewidth=2.0, label=name)
title = graph_name
plt.title(title)
ax.legend()
ax.grid(True)
plt.xlabel("Packets so far")
plt.ylabel("Hit-in-cache count")
# plt.show()
plt.savefig("../" + title + "_func_of_pkts.png")
plt.clf()



print("Done.")
