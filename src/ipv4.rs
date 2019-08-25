use pnet::packet::ipv4::{MutableIpv4Packet};


pub fn init_ipv4_pkt(pkt: &mut MutableIpv4Packet, len: u16) -> () {
  pkt.set_version(4);
  pkt.set_header_length(5);
  pkt.set_total_length(len);
  pkt.set_ttl(128);
}


#[macro_export]
macro_rules! ipv4 {
   ({$($func:ident => $value:expr), *}, $l4_pkt:expr, $protocol:expr, $buf:expr) => {{
      const IPV4_HEADER_LEN: usize = 20;
      const DEFAULT_SOURCE: std::net::Ipv4Addr = std::net::Ipv4Addr::new(127,0,0,1);
      const DEFAULT_DESTINATION: std::net::Ipv4Addr = std::net::Ipv4Addr::new(127,0,0,1);

      let total_len = IPV4_HEADER_LEN + $l4_pkt.packet().len();
      let mut source = DEFAULT_SOURCE;
      let mut dest = DEFAULT_DESTINATION;
      // Get the source/destination IP addresses so we can set the L4 checksum before
      // creating the MutableIpv4Packet which is another mutable reference to the packet buffer.
      // Once the MutableIpv4Packet is created we can't use $l4_pkt or we will get borrow errors.
      $(
        match stringify!($func) {
          "set_source" => source = $value,
          "set_destination" => dest = $value,
          _ => (),
        }
      )*
      $l4_pkt.checksum_ipv4(&source, &dest);
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::ipv4::MutableIpv4Packet::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_next_level_protocol($protocol);
      // TODO make the ID a random value
      pkt.set_identification(256);
      pkt.set_flags(pnet::packet::ipv4::Ipv4Flags::DontFragment);
      ipv4::init_ipv4_pkt(&mut pkt, total_len as u16);
      $(
        pkt.$func($value);
      )*
      pkt.set_checksum(pnet::packet::ipv4::checksum(&pkt.to_immutable()));

      (pkt, pnet::packet::ethernet::EtherTypes::Ipv4)
   }};
  /* ({$($func:ident => $value:expr), *}) => {{
      let total_len = IPV4_HEADER_LEN;
      let buf = vec![0u8; total_len];
      let mut pkt = MutableIpv4Packet::owned(buf).unwrap();
      init_ipv4_pkt(&mut pkt, total_len as u16);
      $(
        pkt.$func($value);
      )*
      pkt.set_checksum(ipv4_checksum(&pkt.to_immutable()));
//      $pkt_layers.push(PacketTypes::Ipv4Pkt(pkt));
      (pkt, EtherTypes::Ipv4)
   }};
   */
}


#[macro_export]
macro_rules! ipv4addr {
  ($addr_str:expr) => {{
    $addr_str.parse().unwrap()
  }};
}

