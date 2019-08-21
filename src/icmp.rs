

use pnet::packet::ipv4::{MutableIpv4Packet};
use pnet::packet::util::checksum as generic_checksum;
use pnet::packet::Packet;
use L4Checksum;

macro_rules! icmp_pkt_macro_generator {
  ($($name:ident => $icmp_type:ty), *) => {
    $(
      #[macro_export]
      macro_rules! $name {
        ($args:tt, $payload_pkt:expr, $proto:expr) => {{
          icmp!($args, $payload_pkt, $icmp_type) 
        }};
        ($args:tt) => {{
          icmp!($args, $icmp_type) 
        }}; 
      }
    )*
  };
}

macro_rules! icmp_checksum_func_gen {
  ($($icmp_type:ty),*) => {
    $(
      impl <'p>L4Checksum for $icmp_type {
        fn checksum_ipv4(&mut self, _packet : &MutableIpv4Packet) {
          // ICMP checksum is the same as IP
          self.set_checksum(generic_checksum(&self.packet(), 1)); 
        }
      }
    )*
  };
}

icmp_checksum_func_gen!(pnet::packet::icmp::echo_reply::MutableEchoReplyPacket<'p>, 
                        pnet::packet::icmp::echo_request::MutableEchoRequestPacket<'p>, 
                        pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket<'p>, 
                        pnet::packet::icmp::time_exceeded::MutableTimeExceededPacket<'p>); 

icmp_pkt_macro_generator!(icmp_echo_req => pnet::packet::icmp::echo_request::MutableEchoRequestPacket,
                          icmp_echo_reply => pnet::packet::icmp::echo_reply::MutableEchoReplyPacket,
                          icmp_dest_unreach => pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket,
                          icmp_time_exceed => pnet::packet::icmp::time_exceeded::MutableTimeExceededPacket);

#[macro_export]
macro_rules! icmp {
   ({$($func:ident => $value:expr), *}, $icmp_type:ty) => {{
      let total_len = <$icmp_type>::minimum_packet_size();
      let buf = vec![0u8; total_len];
      let mut pkt = <$icmp_type>::owned(buf).unwrap();
      pkt.set_icmp_type(IcmpTypes::EchoRequest);
      $(
        pkt.$func($value);
      )*
      (pkt, IpNextHeaderProtocols::Icmp)
   }};
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $icmp_type:ty) => {{
      let total_len = <$icmp_type>::minimum_packet_size() + $payload_pkt.packet().len();
      let buf = vec![0u8; total_len];
      let mut pkt = <$icmp_type>::owned(buf).unwrap();
      pkt.set_icmp_type(IcmpTypes::EchoRequest);
      $(
        pkt.$func($value);
      )*
      pkt.set_payload($payload_pkt.packet());
      (pkt, IpNextHeaderProtocols::Icmp)
   }};
}


