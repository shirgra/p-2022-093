## project p-2022-093
# Distributed Caching-based Acceleration Mechanisms in Datacenter Networks


## Run our code:
### initial settings
1. In the project folder, `NetCache2022/` open a terminal, run:
   ```bash
   chmod +x build.sh
   chmod +x src/host_controller.py
   chmod +x src/host_traffic_generator.py
   chmod +x src/outside_controller.py
   pip install tqdm
   
   ``` 

### running the expiremint:
1. In the project folder, `NetCache2022/` open a terminal, run:
   ```bash
   ./build.sh
   ``` 
   This will: 
   * compile `net_cache.p4`, and
   * start a Mininet instance with three switches (`s1`, `s2`, `s3`) configured
     in a triangle, each connected to one host.
   * The hosts are assigned IPs of `10.0.1.1`, `10.0.2.2`, and `10.0.3.3`.
2. In the Mininet terminal, run:
   ```bash
   mininet> pingall
   ```
   This will check that the besic routing is working, then run.
   ```bash
   mininet> xterm h1 h2
   ```
3. If the proccess is successfull, hosts terminals opened. In Host-1 run:
   ```bash
   cd ..
   ./host_controller.py expirements_dependencies/policy.csv
   ```
   This will start the host-coltroller program and initiate a new rules empty file.
4. Open a new terminal, in `NetCache2022/src` and run:
   ```bash
   ./outsidecontroller.py
   ```
   This will start the outsode control to the system.
6. In Host-2 run:
   ```bash
   cd ..
   ./host_traffic_generator.py expirements_dependencies/flow_tst.csv
   ```
   This will start sending rules outside.



## The bases for creating the basic topology:
### The base topology: 
Link for the topology: p4lang/tutorials/exercises/basic_tunnel/ [https://github.com/p4lang/tutorials/tree/master/exercises/basic_tunnel].
Including origin files:
1. Makefile
2. basic_tunnel.p4
3. myTunnel_header.py: A python file that open a scappy tunnel.
4. receive.py, send.py
5. sX-runtime.json (X=1,2,3)
6. topology.json
### The addition to connect with the data plaine 
Link for the topology: p4lang/tutorials/exercises/p4runtime/ [https://github.com/p4lang/tutorials/tree/master/exercises/p4runtime].


## The Topology structure:
![topology](./topo.png)
