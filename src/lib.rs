#![macro_use]
#![allow(unused_macros)]

extern crate derive_new;
extern crate ipnetwork;
extern crate pnet;

pub mod icmp;
pub mod tcp;
pub mod udp;
pub mod ethernet;
pub mod ipv4;

use pnet::packet::ipv4::{MutableIpv4Packet};
/*
use pnet::packet::{Packet};
use pnet::packet::ethernet::{EtherType, EtherTypes};
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{self, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket};

use std::num::ParseIntError;
use std::ops::Div;
use pnet::datalink;
use std::str::FromStr;
*/

pub trait L4Checksum {
  fn checksum_ipv4(&mut self, packet : &MutableIpv4Packet) -> ();
}

pub struct PayloadData {
  pub data: Vec<u8>,
}

// Implement the pnet Packet trait so we can use the same interface in the macro for getting the
// data.
impl pnet_macros_support::packet::Packet for PayloadData {
    fn packet(& self) -> & [u8] { &self.data[..] }
    fn payload(& self) -> & [u8] { &self.data[..] }
}

#[macro_export]
macro_rules! payload {
   ($value:expr, $len:expr, $protocol:expr ) => {{
     let pdata =  PayloadData {
       data : $value,
     };
     println!("building payload");
     // The protocol element of the tuple is not actually used but the compiler requires us to
     // provide a type.
//     $pkt_layers.push(PacketTypes::Payload(pdata));
     (pdata, None as Option<&u16>)
   }};
   ($value:expr) => {{
     let pdata =  PayloadData {
       data : $value,
     };
     (pdata, None as Option<&u16>)
   }};
}


#[macro_export]
macro_rules! build_channel {
  ($ifname:expr) => {{
    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == $ifname)
        .unwrap();

    let (sender, receiver) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(pnet_datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };
    (sender, receiver)
  }};
}


#[macro_export]
macro_rules! sub_builder {
    ($build_macro:ident($args:tt) $(/ $rem_macros:ident($rem_args:tt))+ ) => {{
      let (mut payload_pkt, _payload_proto) = sub_builder!($($rem_macros($rem_args) )/ * );
      //let payload_pkt = $pkt_layers.last().unwrap();
      let (pkt, proto) = $build_macro!($args, payload_pkt, _payload_proto);
//      let pkt = $pkt_layers.last_mut().unwrap();
      //pkt.set_payload(payload_pkt.packet());
      (pkt, proto)
    }};
   ( $build_macro:ident($args:tt)) => {{
      $build_macro!($args)
   }};
}

// Call the sub builder so we can return just the packet rather than the tuple that gets returned
// by the sub builder for use during the recursion.
#[macro_export]
macro_rules! packet_builder2 {
   ($( $rem_macros:ident($rem_args:tt))/ * ) => {{
//    let mut pkt_layers : Vec<PacketTypes> = Vec::new();
    let (pkt, _proto) = sub_builder!($( $rem_macros($rem_args) )/ *);
    pkt
   }};
}

