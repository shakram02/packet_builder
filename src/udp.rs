use pnet::packet::udp::{MutableUdpPacket};
use pnet::packet::udp::ipv4_checksum as ipv4_udp_checksum;
use pnet::packet::ipv4::{MutableIpv4Packet};
use L4Checksum;


impl <'p>L4Checksum for MutableUdpPacket<'p> {
  fn checksum_ipv4(&mut self, packet : &MutableIpv4Packet) {
    self.set_checksum(ipv4_udp_checksum(&self.to_immutable(), &packet.get_source(), &packet.get_destination())); 
  }
}

#[macro_export]
macro_rules! udp {
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $protocol:expr) => {{
      const UDP_HEADER_LEN: usize = 8;
      let total_len = UDP_HEADER_LEN + $payload_pkt.packet().len();
      let buf = vec![0u8; total_len];
      let mut pkt = pnet::packet::udp::MutableUdpPacket::owned(buf).unwrap();
      pkt.set_length(total_len as u16);
      pkt.set_destination(53);
      pkt.set_source(12345);
      $(
        pkt.$func($value);
      )*
//      $pkt_layers.push(PacketTypes::UdpPkt(pkt));
      pkt.set_payload($payload_pkt.packet());
      (pkt, IpNextHeaderProtocols::Udp)
   }};
}

