## project p-2022-093

### running the expiremint:
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
3. You should now see a Mininet command prompt. Open two terminals for `h1` and
`h2`, respectively: 
  ```bash
  mininet> xterm h1 h2
  ```

### Notes
> The traffic packets of the TCP protocol (using scapy) use **flags = 3** whan want to signal to the switch to drop the packet, because it is in the cache.
> The traffic passing as in a data-center has a prefix of 192.0.0.0/8.
> 

