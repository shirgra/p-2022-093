### Makefile - different for each topology

# topo vars
TOPO_NAME = hat
TOPO_DIR = hat_topology

# same for all topos
PCAP_DIR=pcaps
LOG_DIR= logs
RUN_SCRIPT_PATH=../../utils/run_envirunment.py
BUILD_NAME=../build_dependencies/net_cache



all: mkdir compile build

mkdir:
	mkdir -p $(PCAP_DIR) $(LOG_DIR)

build: 
	sudo python $(RUN_SCRIPT_PATH) -t topology.json -j $(BUILD_NAME).json -b simple_switch_grpc

compile:
	p4c-bm2-ss --std p4-16 \
		--target bmv2 --arch v1model \
		-o $(BUILD_NAME).json \
		--p4runtime-files $(BUILD_NAME).p4.p4info.txt \
		--p4runtime-format text $(BUILD_NAME).p4


clean: stop
	sudo mn -c
	rm -f *.pcap
	rm -rf $(PCAP_DIR) $(LOG_DIR)