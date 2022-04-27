#!/bin/sh
# To run an expirement run: ./build.sh <topo-topology> <cache_size> <threshold_size>

# directories defines
SRC=src
BUILD_DIR=${SRC}/build_dependencies
EXP_DIR=${SRC}/experiments_depansencies
RES_DIR=${SRC}/experiments_results

# Step 0: 
echo "\nWelcome to NetCache expirement"
echo "\nBuilding Envirunment..."

# Experiments defines - defaults
TOPO_DIR=${SRC}/hat_topology
CACHE_SIZE=8
THRESHOLD=10

# take arguments from command line
if [ $# -eq 3 ]
then
	echo "Received Parameters: $1 $2 $3.".
	TOPO_DIR=$1
	CACHE_SIZE=$2
	THRESHOLD=$3
elif [ $# -eq 1 ] 
then
	TOPO_DIR=$1
	CACHE_SIZE=$2
	THRESHOLD=$3
elif [ $# -eq 2 ] 
then
	TOPO_DIR=$1
	CACHE_SIZE=$2
else
	echo "Did not received Parameters, you can insert parameters:"
	echo "./build.sh <topo_topology> <cache_size> <threshold_size>"
	echo "Default is set to be: ./build.sh hat_topology 8 10\n"
fi

# Step 1: Clean previous processes
sudo mn -c 2> /dev/null
echo "Cleaned Mininet envirunment."

# Step 2: Create *.json and *.p4info
echo "Running Makefile in $TOPO_DIR."
cd $TOPO_DIR && make -s # >> Running Makefile in silent mode