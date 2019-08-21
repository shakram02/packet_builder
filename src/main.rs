extern crate lib_sendpacket;
extern crate pnet;
extern crate pnet_base;

use lib_sendpacket::*;
use pnet::packet::icmp::{IcmpTypes};
//use pnet::packet::arp::{MutableArpPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::Packet;
use pnet_base::MacAddr;
use std::env;
//use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;

//const ARP_HEADER_LEN: usize = 28;



fn main() {

    let if_name = env::args().nth(1)
        .expect("Usage: ./sendpacket <interface name>");

    let pkt2 = packet_builder2!(
         ether({set_source => MacAddr(10,1,1,1,1,1)}) / 
         ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
         //test_udp({set_source => 53, set_destination => 5353}) /
  //       tcp({set_source => 53, set_destination => 8834}) /
         icmp_dest_unreach({set_icmp_type => IcmpTypes::DestinationUnreachable}) / 
         ipv4({set_source => ipv4addr!("10.8.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
         udp({set_source => 53, set_destination => 5353}) /
         payload({"hello".to_string().into_bytes()})
    );
 
    let (mut sender, _receiver) = build_channel!(if_name);
    // TODO use just a slice of the packet up to packet size and then we can use just one buffer
    // for the whole packet
    sender.send_to(pkt2.packet(), None).unwrap().unwrap();

    println!("Sent");

//    let rcv_pkt = packet.recv(&session);
//    println!("Received: {:?}", rcv_pkt);
}

