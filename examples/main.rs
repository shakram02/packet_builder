extern crate packet_builder;
extern crate pnet;
extern crate pnet_base;

use packet_builder::*;
use packet_builder::payload::PayloadData;
use pnet::packet::icmp::{IcmpTypes};
//use pnet::packet::arp::{MutableArpPacket};
use pnet::packet::Packet;
use pnet_base::MacAddr;
use std::env;
use pnet::packet::tcp::TcpFlags;

//const ARP_HEADER_LEN: usize = 28;

fn main() {

    //trace_macros!(true);
    let if_name = env::args().nth(1)
        .expect("Usage: ./sendpacket <interface name>");

    let (mut sender, _receiver) = build_channel!(if_name);

    {
        // Generate a destination unreachable ICMP packet
        let mut pkt_buf = [0u8; 1500];
        let pkt = packet_builder!(
             pkt_buf,
             ether({set_source => MacAddr(10,1,1,1,1,1)}) / 
             ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
             icmp_dest_unreach({set_icmp_type => IcmpTypes::DestinationUnreachable}) / 
             ipv4({set_source => ipv4addr!("10.8.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
             udp({set_source => 53, set_destination => 5353}) /
             payload({"hello".to_string().into_bytes()})
        );
     
        sender.send_to(pkt.packet(), None).unwrap().unwrap();
    }
    {
        // Generate a TCP PSH|ACK packet with data
        let mut pkt_buf = [0u8; 1500];
        let pkt = packet_builder!(
             pkt_buf,
             ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) / 
             ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
             tcp({set_source => 43455, set_destination => 80, set_flags => (TcpFlags::PSH | TcpFlags::ACK)}) /
             payload({"hello".to_string().into_bytes()})
        );
     
        sender.send_to(pkt.packet(), None).unwrap().unwrap();
    }
    {
        // Generate a UDP packet with data
        let mut pkt_buf = [0u8; 1500];
        let pkt = packet_builder!(
             pkt_buf,
             ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) / 
             ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
             udp({set_source => 12312, set_destination => 143}) /
             payload({"hello".to_string().into_bytes()})
        );
     
        sender.send_to(pkt.packet(), None).unwrap().unwrap();
    }
    {
        // Generate an ICMP echo request
        let mut pkt_buf = [0u8; 1500];
        let pkt = packet_builder!(
             pkt_buf,
             ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) / 
             ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
             icmp_echo_req({set_icmp_type => IcmpTypes::EchoRequest}) / 
             payload({"hello".to_string().into_bytes()})
        );
     
        sender.send_to(pkt.packet(), None).unwrap().unwrap();
    }


//    let rcv_pkt = packet.recv(&session);
//    println!("Received: {:?}", rcv_pkt);
}

