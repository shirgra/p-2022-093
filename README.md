## project p-2022-093
# Distributed Caching-based Acceleration Mechanisms in Datacenter Networks
Communication Systems engineering - 4th year project.


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
Link for the topology: ![p4lang/tutorials/exercises/basic_tunnel/](https://github.com/p4lang/tutorials/tree/master/exercises/basic_tunnel)
Including origin files:
1. Makefile
2. README.md
3. basic_tunnel.p4
4. myTunnel_header.py:         
A python file that open a scappy tunnel.
5. receive.py, send.py
6. sX-runtime.json (X=1,2,3)
7. topology.json
### The addition to connect with the data plaine 
Link for the topology: p4lang/tutorials/exercises/p4runtime/ [https://github.com/p4lang/tutorials/tree/master/exercises/p4runtime].
1. mycontroller.py -> control_plaine.py
2. advanced_tunnel.p4 -> to be applied to basic_tunnel.p4


## The Topology structure:
![topology](./p-2022-093/p4_researching_2022/p4_researching/expirements/basic_topology/topo.png)
> TODO add the explenation for the topology 


## Trnsition to files (compare, then rename):
build_dependencies/basic_tunnel.json          -> build_dependencies/topology_configuration_file.json
build_dependencies/basic_tunnel.p4.p4info.txt -> topology_configuration_file.p4info
basic_tunnel.p4                               -> topology_configuration_file.p4


## TODOs and Tests:
1. change s2,s3-runtime.json to smart switches. 
this can happen using https://github.com/p4lang/tutorials/tree/master/exercises/calc 
2. change the p4 file - > also use calc...
3. map gilads code parts...
4. add guilad's code parts
5. change running ./start.sh with the redirected Makefile
6. change files:
Trnsition to my files (compare, then rename):
build_dependencies/basic_tunnel.json          -> build_dependencies/topology_configuration_file.json
build_dependencies/basic_tunnel.p4.p4info.txt -> topology_configuration_file.p4info
basic_tunnel.p4                               -> topology_configuration_file.p4
7. The ping failed because each switch is programmed according to multicast.p4, which drops all packets on arrival. Your job is to extend this file so it forwards packets. [https://github.com/p4lang/tutorials/blob/1fc826aa43b489426610312166554e51fbd7b861/exercises/multicast/README.md#:~:text=The%20ping%20failed%20because%20each%20switch%20is%20programmed%20according%20to%20multicast.p4%2C%20which%20drops%20all%20packets%20on%20arrival.%20Your%20job%20is%20to%20extend%20this%20file%20so%20it%20forwards%20packets.]


## Simulation in the network - new layout:
![image](https://user-images.githubusercontent.com/62025130/140291037-6c740e58-2c86-44a2-963f-cf9afa6babf1.png)



> Any changes in the P4 program that add or rename tables, keys, or actions will need to be reflected in these sX-runtime.json files.
