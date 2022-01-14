// edited by shir at 16.12.2021

#ifndef __PARSER__
#define __PARSER__

#include "headers.p4"

// From Gulied code:
#define UDP_PORT_VXLAN 4789
#define UDP_PROTO 17


// Parser
parser basic_tutor_switch_parser(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    state start {
        transition select(standard_metadata.ingress_port){
            //CPU_PORT: parse_packet_out; //from orig
            default: parse_ethernet;
        }
    }

// from origin file:
/*
    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }
*/

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP:  parse_arp; // addition guilad
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            //PROTO_TCP: parse_tcp; //from orig
            //PROTO_UDP: parse_udp; //from orig
            UDP_PROTO: parse_udp;
            default: accept;
        }
    }
// from origin file:

    state parse_tcp {
        packet.extract(hdr.tcp);
        metadata.l4_srcPort = hdr.tcp.srcPort;
        metadata.l4_dstPort = hdr.tcp.dstPort;
        transition accept;
    }


    state parse_arp { // addition guilad
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        //metadata.l4_srcPort = hdr.udp.srcPort;
        //metadata.l4_dstPort = hdr.udp.dstPort;
        //transition accept;
        transition select(hdr.udp.dstPort) {
            UDP_PORT_VXLAN: parse_vxlan;
            default: accept;
         }
    }

// addition from guilad:
    state parse_vxlan {
        packet.extract(hdr.vxlan);
        transition parse_inner_ethernet;
    }

    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition accept;
    }

}



// Deparser
control basic_tutor_switch_deparser(
    packet_out packet,
    in headers_t hdr
){
    apply {
        //packet.emit(hdr.packet_in);//guilad remove
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp); // guilad add
        //packet.emit(hdr.tcp);//guilad remove
        packet.emit(hdr.udp);
	//guilad add:
        packet.emit(hdr.vxlan);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.inner_ipv4);
    }
}

#endif
