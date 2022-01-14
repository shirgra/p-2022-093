#!/bin/sh

# guilad defines
THRESHOLD=20
CACHE_SIZE=8
RANDOM_RULES_NUM=2
RUN_TIME=600
PORT=50105
EVICTION_THRESHOLD=6
READ_COUNTER_INTERVAL=1

# shir defines
BUILD_DIR=build_dependencies

# Step 0: Clean previous processes
sudo mn -c 2> /dev/null
echo "Cleaned Mininet envirunment."

# Step 1: Create *.json and *.p4info
# cd /$BUILD_DIR && make -t
# make > /dev/null
echo "Running make"
cd $BUILD_DIR
/bin/bash makestart.sh
cd ..

# Step 2: Assign those deps to ../../lib/main.py
#       - topology.json
#       - *.p4.json
#       - "simple_switch_grpc"
#echo "Compiling (python) settings envirunment..."
#sudo python ../utils/run_environment.py \
#    --topo $BUILD_DIR/topology.json \
#    --switch_json $BUILD_DIR/topology_configuration_file.json \
#    --behavioral-exe simple_switch_grpc

#    --threshold $THRESHOLD \
#    --cache_size $CACHE_SIZE \
#    --random_rules_num $RANDOM_RULES_NUM \
#    --run_time $RUN_TIME \
#    --port $PORT \
#    --eviction_threshold $EVICTION_THRESHOLD \
#    --read_counter_interval $READ_COUNTER_INTERVAL

