## project p-2022-093
# Distributed Caching-based Acceleration Mechanisms in Datacenter Networks
***Communication Systems Engineering, 4th Year Engineering Project.***

**Students:** Anna Axalrod and Shir Granit.

**Advisors:** Prof Chen Avin, Dr Gabriel Scalosub.

### Abstract Information
Due to high data flow through a data center network, switches in the network face a problem of storing an enormous amount of traffic rules which are necessary for correctly transferring packets in the network. Those rules are usually stored in an external device to which the access slows the network’s performance. The purpose of the project is to find a solution that prevents multiple access to the external device, leading to a significant speedup of the routing process in the network. 

In our project, we will develop a distributed solution for the problem presented which will be based on a previous solution that uses caches. 
Our proposed method includes creating a network with several switches which send queries to each other to get forwarding rules. In case of missing information, we will request the forwarding rule from the external device (the controller), which keeps all the forwarding rules and holds the switch's cache memory.

## Envirunment Setup:
1. Download P4 VM from [here](https://drive.google.com/file/d/13NHWkkmn69W90dJGQUC7m7i4USeMTegF/view) (Use your post.bgu account to gain access).
2. If you don't have [VirtualBox](https://www.virtualbox.org/), install VirtualBox and run this VM.
3. Clone the repo to the vm that you’ve just downloaded.
4. In the repository, `p-2022-093/` open a terminal, run:
```
   cd Expirements
   chmod 777 pip_install.sh
   ./pip_install.sh
``` 
5. Good to go!

## Expiriments:
TODO detail the topologies

TODO how to run the expiriments

In the Mininet terminal, run:
   ```bash
   mininet> pingall
   mininet> xterm h1 h2
   ```
   This will check that the besic routing is working.

> sine note


## General Notes:
### Origin work: 
1. Our topology is based on the combination of [p4lang tutorials](https://github.com/p4lang/tutorials).
* [basic](https://github.com/p4lang/tutorials/tree/master/exercises/basic)
* [basic_tunnel](https://github.com/p4lang/tutorials/tree/master/exercises/basic_tunnel)
* [p4runtime](https://github.com/p4lang/tutorials/tree/master/exercises/p4runtime)
2. Traffic protocol is based on scapy python package.
