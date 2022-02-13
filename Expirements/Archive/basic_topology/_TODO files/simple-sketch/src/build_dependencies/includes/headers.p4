#ifndef __HEADERS__
#define __HEADERS__

#include "codex/enum.p4"
#include "codex/l2.p4"
#include "codex/l3.p4"
#include "codex/l4.p4"
#include "codex/l567.p4"
#include <v1model.p4>


#define CPU_PORT 255

// packet in 
@controller_header("packet_in")
header packet_in_header_t {
    bit<16>  ingress_port;
}

// packet out 
@controller_header("packet_out")
header packet_out_header_t {
    bit<16> egress_port;
    bit<16> mcast_grp;
}

// header struct for packet
struct headers_t {
    packet_out_header_t     packet_out;
    packet_in_header_t      packet_in;
    ethernet_t              ethernet;
    arp_t					arp;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    udp_t                   udp;
    vxlan_t                 vxlan;
    ethernet_t              inner_ethernet;
    ipv4_t                  inner_ipv4;
}

// metadata inside switch pipeline
struct metadata_t {
    bit<24> vxlan_vni;
    bit<32> dst_ip;
    bit<32> vtepIP;
    // from /p4/p4c/build/p4-researching/p4-researching/src/experiment/simple-sketch/includes
    bit<16> l4_srcPort;
    bit<16> l4_dstPort;
    bit<32> flow_id;
    bit<32> flow_count_val;
    bit<48> last_seen_val;
}

#endif
