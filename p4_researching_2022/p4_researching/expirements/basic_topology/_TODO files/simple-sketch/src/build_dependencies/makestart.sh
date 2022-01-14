#!/bin/sh

# Step 1: Create *.json and *.p4info
# cd /$BUILD_DIR && make -t
make > /dev/null
echo "Created *.json and *.p4info files."
