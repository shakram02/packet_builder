
#[macro_export]
macro_rules! ether {
   ({$($func:ident => $value:expr), *}, $payload_pkt:expr, $protocol:expr ) => {{
      const ETHERNET_HEADER_LEN: usize = 14;
      let buf = vec![0u8; ETHERNET_HEADER_LEN + $payload_pkt.packet().len()];
      let mut pkt = pnet::packet::ethernet::MutableEthernetPacket::owned(buf).unwrap();
      pkt.set_ethertype($protocol);       
      $(
        pkt.$func($value);
      )*
//      $pkt_layers.push(PacketTypes::EtherPkt(pkt));
      pkt.set_payload($payload_pkt.packet());
      // The protocol element of the tuple is not actually used but the compiler requires us to
      // provide a type.
     (pkt, None as Option<&u16>)
   }};
}

