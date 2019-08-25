
#[macro_export]
macro_rules! ether {
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $protocol:expr, $buf:expr ) => {{
      const ETHERNET_HEADER_LEN: usize = 14;
      let total_len = ETHERNET_HEADER_LEN + $payload_pkt.packet().len();
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::ethernet::MutableEthernetPacket::new(&mut $buf[buf_len - total_len..]).unwrap();
      pkt.set_ethertype($protocol);       
      $(
        pkt.$func($value);
      )*
//      $pkt_layers.push(PacketTypes::EtherPkt(pkt));
      //pkt.set_payload($payload_pkt.packet());
      // The protocol element of the tuple is not actually used but the compiler requires us to
      // provide a type.
     (pkt, None as Option<&u16>)
   }};
   ({$($func:ident => $value:expr), *}, $buf:expr) => {{
      const ETHERNET_HEADER_LEN: usize = 14;
      let buf_len = $buf.len();
      let mut pkt = pnet::packet::ethernet::MutableEthernetPacket::new(&mut $buf[buf_len - ETHERNET_HEADER_LEN..]).unwrap();
      $(
        pkt.$func($value);
      )*
      // The protocol element of the tuple is not actually used but the compiler requires us to
      // provide a type.
     (pkt, None as Option<&u16>)
   }};
}

