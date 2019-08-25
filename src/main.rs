extern crate lib_sendpacket;
extern crate pnet;
extern crate pnet_base;

use lib_sendpacket::*;
use lib_sendpacket::payload::PayloadData;
use pnet::packet::icmp::{IcmpTypes};
//use pnet::packet::arp::{MutableArpPacket};
use pnet::packet::Packet;
use pnet_base::MacAddr;
use std::env;

//const ARP_HEADER_LEN: usize = 28;

fn main() {

    //trace_macros!(true);
    let if_name = env::args().nth(1)
        .expect("Usage: ./sendpacket <interface name>");

    let mut pkt_buf = [0u8; 1500];
    let pkt2 = packet_builder!(
         pkt_buf,
         ether({set_source => MacAddr(10,1,1,1,1,1)}) / 
         ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
         //test_udp({set_source => 53, set_destination => 5353}) /
         //tcp({set_source => 53, set_destination => 8443}) /
         icmp_dest_unreach({set_icmp_type => IcmpTypes::DestinationUnreachable}) / 
         ipv4({set_source => ipv4addr!("10.8.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
         udp({set_source => 53, set_destination => 5353}) /
         payload({"hello".to_string().into_bytes()})
    );
 
    let (mut sender, _receiver) = build_channel!(if_name);
    sender.send_to(pkt2.packet(), None).unwrap().unwrap();

    println!("Sent");

//    let rcv_pkt = packet.recv(&session);
//    println!("Received: {:?}", rcv_pkt);
}

