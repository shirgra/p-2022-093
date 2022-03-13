## project p-2022-093
# Distributed Caching-based Acceleration Mechanisms in Datacenter Networks


## Run our code:
# initial settings

# running the expiremint:
1. In the project, `NetCache/` open a terminal, run:
   ```bash
   make
   ``` 
   This will:
   * compile `basic_tunnel.p4`, and
   * start a Mininet instance with three switches (`s1`, `s2`, `s3`) configured
     in a triangle, each connected to one host (`h1`, `h2`, and `h3`).
   * The hosts are assigned IPs of `10.0.1.1`, `10.0.2.2`, and `10.0.3.3`.
2. In the Mininet terminal, run:
   ```bash
   pingall
   ```
   This will check that the besic routing is working.

2. You should now see a Mininet command prompt. Open two terminals for `h1` and
`h2`, respectively: 
  ```bash
  mininet> xterm h1 h2
  ```


> sine note


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
1. mycontroller.py -> control_plaine.py
2. advanced_tunnel.p4 -> to be applied to basic_tunnel.p4


## The Topology structure:

![topology](./topo.png)

TODO add the explenation for the topology 

## TODOs and Tests:
1. change s2,s3-runtime.json to smart switches. 
this can happen using https://github.com/p4lang/tutorials/tree/master/exercises/calc 
2. change the p4 file - > also use calc...
3. map gilads code parts...
4. add guilad's code parts
5. change the makefile
6. change the control plane
