use pnet::packet::tcp::{MutableTcpPacket};
use pnet::packet::tcp::ipv4_checksum as ipv4_tcp_checksum;
use pnet::packet::ipv4::{MutableIpv4Packet};
use L4Checksum;

impl <'p>L4Checksum for MutableTcpPacket<'p> {
  fn checksum_ipv4(&mut self, packet : &MutableIpv4Packet) {
    self.set_checksum(ipv4_tcp_checksum(&self.to_immutable(), &packet.get_source(), &packet.get_destination())); 
  }
}

#[macro_export]
macro_rules! tcp {
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $protocol:expr) => {{
      const TCP_HEADER_LEN: usize = 32;
      let total_len = TCP_HEADER_LEN + $payload_pkt.packet().len();
      let buf = vec![0u8; total_len];
      let mut pkt = pnet::packet::tcp::MutableTcpPacket::owned(buf).unwrap();
      pkt.set_data_offset(8);
      pkt.set_flags(pnet::packet::tcp::TcpFlags::SYN);
      pkt.set_window(65535);
      $(
        pkt.$func($value);
      )*
//      $pkt_layers.push(PacketTypes::UdpPkt(pkt));
      pkt.set_payload($payload_pkt.packet());
      (pkt, IpNextHeaderProtocols::Tcp)
   }};
}

