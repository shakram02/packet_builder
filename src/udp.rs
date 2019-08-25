use pnet::packet::udp::{MutableUdpPacket};
use pnet::packet::udp::ipv4_checksum as ipv4_udp_checksum;
use std::net::Ipv4Addr;
use L4Checksum;


impl <'p>L4Checksum for MutableUdpPacket<'p> {
  fn checksum_ipv4(&mut self, source: &Ipv4Addr, destination: &Ipv4Addr) -> () {
    self.set_checksum(ipv4_udp_checksum(&self.to_immutable(), source, destination));
  }
}

#[macro_export]
macro_rules! udp {
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $protocol:expr, $buf:expr) => {{
      const UDP_HEADER_LEN: usize = 8;
      let total_len = UDP_HEADER_LEN + $payload_pkt.packet().len();
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::udp::MutableUdpPacket::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_length(total_len as u16);
      pkt.set_destination(53);
      pkt.set_source(12345);
      $(
        pkt.$func($value);
      )*
      (pkt, pnet::packet::ip::IpNextHeaderProtocols::Udp)
   }};
}

