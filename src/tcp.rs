use pnet::packet::tcp::{MutableTcpPacket};
use pnet::packet::tcp::ipv4_checksum as ipv4_tcp_checksum;
use std::net::Ipv4Addr;
use L4Checksum;

impl <'p>L4Checksum for MutableTcpPacket<'p> {
  fn checksum_ipv4(&mut self, source: &Ipv4Addr, destination: &Ipv4Addr) -> () {
    self.set_checksum(ipv4_tcp_checksum(&self.to_immutable(), source, destination));
  }
}

#[macro_export]
macro_rules! tcp {
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $protocol:expr, $buf:expr) => {{
      const TCP_HEADER_LEN: usize = 32;
      let total_len = TCP_HEADER_LEN + $payload_pkt.packet().len();
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::tcp::MutableTcpPacket::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_data_offset(8);
      pkt.set_flags(pnet::packet::tcp::TcpFlags::SYN);
      pkt.set_window(65535);
      $(
        pkt.$func($value);
      )*
      (pkt, pnet::packet::ip::IpNextHeaderProtocols::Tcp)
   }};
}

#[cfg(test)]
mod tests {
   use pnet::packet::Packet;
   use ::payload;
   use payload::PayloadData;
   use tcp;

   #[test]
   fn macro_tcp_basic() {
      let mut buf = [0; 37];
      let (pkt, proto) = tcp!({set_source => 53, set_destination => 5353},
        payload!({"hello".to_string().into_bytes()}, buf).0, None, buf);
      assert_eq!(proto, pnet::packet::ip::IpNextHeaderProtocols::Tcp);

      let buf_expected = vec![0; 37];
      let mut pkt_expected = pnet::packet::tcp::MutableTcpPacket::owned(buf_expected).unwrap();
      pkt_expected.set_destination(5353); 
      pkt_expected.set_source(53); 
      pkt_expected.set_data_offset(8);
      pkt_expected.set_payload(&"hello".to_string().into_bytes()); 
      pkt_expected.set_flags(pnet::packet::tcp::TcpFlags::SYN);
      pkt_expected.set_window(65535);
      assert_eq!(pkt_expected.packet(), pkt.packet());
   }
}

