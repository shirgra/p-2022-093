## project p-2022-093
# Distributed Caching-based Acceleration Mechanisms in Datacenter Networks

## The bases for creating the basic topology:
### The base topology: 
Link for the topology: p4lang/tutorials/exercises/basic_tunnel/ [https://github.com/p4lang/tutorials/tree/master/exercises/basic_tunnel].
Including origin files:
1. Makefile
2. README.md
3. basic_tunnel.p4
4. myTunnel_header.py:         
A python file that open a scappy tunnel.
5. receive.py, send.py
6. sX-runtime.json (X=1,2,3)
7. topology.json


## The Topology structure:

![topology](./topo.png)

TODO add the explenation for the topology 



## TODOs and Tests:
1. change s2,s3-runtime.json to smart switches. 
this can happen using https://github.com/p4lang/tutorials/tree/master/exercises/calc 
2. change the p4 file - > also use calc...
3. map gilads code parts...
4. add guilad's code parts




## Run our code:

1. In your shell, run:
   ```bash
   make run
   ``` 
   This will:
   * compile `basic_tunnel.p4`, and
   * start a Mininet instance with three switches (`s1`, `s2`, `s3`) configured
     in a triangle, each connected to one host (`h1`, `h2`, and `h3`).
   * The hosts are assigned IPs of `10.0.1.1`, `10.0.2.2`, and `10.0.3.3`.

2. You should now see a Mininet command prompt. Open two terminals for `h1` and
`h2`, respectively: 
  ```bash
  mininet> xterm h1 h2
  ```


> sine note





===================================================================================================Makefile
all: run

run: build
        sudo python $(../utils/run_envirunment.py) -t $($(triangle-topology)/topology.json) $(-j $($(build_dependencies)/$(basic_tunnel.json)) -b $(simple_switch_grpc))

stop:
        sudo mn -c

build: dirs $(basic_tunnel.json)

%.json: %.p4
        $(p4c-bm2-ss) --p4v 16 $(--p4runtime-files $(build_dependencies)/$(basename $@).p4.p4info.txt) -o $(build_dependencies)/$@ $<

dirs:
        mkdir -p $(build_dependencies) $(pcaps) $(logs)

clean: stop
        rm -f *.pcap
        rm -rf $(build_dependencies) $(pcaps) $(logs)



===================================================================================================start.sh
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
TOPO_DIR=triangle-topology

# Step 0: Clean previous processes
sudo mn -c 2> /dev/null
echo "Cleaned Mininet envirunment."

# Step 1: Create *.json and *.p4info
echo "Running make"
cd $BUILD_DIR
/bin/bash makestart.sh
cd ..

# Step 2: Assign those deps to ../../lib/main.py
#       - topology.json
#       - *.p4.json
#       - "simple_switch_grpc"
echo "Compiling (python) settings envirunment..."
sudo python ../utils/run_environment.py \
    --topo $BUILD_DIR/topology.json \
    --switch_json $BUILD_DIR/topology_configuration_file.json \
    --behavioral-exe simple_switch_grpc

# TODO LATER:
#    --threshold $THRESHOLD \
#    --cache_size $CACHE_SIZE \
#    --random_rules_num $RANDOM_RULES_NUM \
#    --run_time $RUN_TIME \
#    --port $PORT \
#    --eviction_threshold $EVICTION_THRESHOLD \
#    --read_counter_interval $READ_COUNTER_INTERVAL

===================================================================================================makestart.sh
#!/bin/sh

# Step 1: Create *.json and *.p4info
make > /dev/null
echo "Created *.json and *.p4info files."

===================================================================================================Makefile
all: topology_configuration_file

topology_configuration_file: topology_configuration_file.p4
        p4c-bm2-ss --std p4-16 \
                --target bmv2 --arch v1model \
                -o topology_configuration_file.json \
                --p4runtime-file topology_configuration_file.p4info \
                --p4runtime-format text topology_configuration_file.p4 \
                --Wdisable

# check what about   --p4runtime-format text topology_configuration_file.p4 \

XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
        Expirementing:


{
sudo python ../utils/run_environment.py \
    --topo $BUILD_DIR/topology.json \
    --switch_json $BUILD_DIR/topology_configuration_file.json \
    --behavioral-exe simple_switch_grpc
}
=? V
{
sudo python $(../utils/run_envirunment.py) -t $($(triangle-topology)/topology.json) $(-j $($(build_dependencies)/$(basic_tunnel.json)) -b $(simple_switch_grpc))
}

Trnsition to my files (compare, then rename):
build_dependencies/basic_tunnel.json          -> build_dependencies/topology_configuration_file.json
build_dependencies/basic_tunnel.p4.p4info.txt -> topology_configuration_file.p4info
basic_tunnel.p4                               -> topology_configuration_file.p4


{
%.json: %.p4
        $(p4c-bm2-ss) --p4v 16 $(--p4runtime-files $(build_dependencies)/$(basename $@).p4.p4info.txt) -o $(build_dependencies)/$@ $<

}
=?
{

all: topology_configuration_file

topology_configuration_file: topology_configuration_file.p4
        p4c-bm2-ss --std p4-16 \
                --target bmv2 --arch v1model \
                -o topology_configuration_file.json \
                --p4runtime-file topology_configuration_file.p4info \
                --p4runtime-format text topology_configuration_file.p4 \
                --Wdisable


}