# packet_builder
[![Crates.io - packet_builder](https://img.shields.io/crates/v/packet_builder.svg)](https://crates.io/crates/packet_builder)
[![Build Status](https://travis-ci.org/hughesac/packet_builder.svg?branch=master)](https://travis-ci.org/hughesac/packet_builder) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-green.svg)](http://www.apache.org/licenses/LICENSE-2.0)

[packet_builder](https://github.com/hughesac/packet_builder) is a high-level rust library for low-level networking that makes use of macros to provide a "kwargs-like" interface a-la python's dpkt/scapy.

With `packet_builder` you can construct and modify arbitrary packet data and attempt to send it via a NIC, which uses `libpnet` under the covers.

[sendpacket](https://github.com/Metaswitch/sendpacket) wasn't being maintained so as an exercise in learning Rust I forked it to make `packet_builder`.  Sane defaults are used for fields that aren't set by the caller and checksums are calculated for you.  Currently the following protocols are supported:
* Ethernet
* IPv4
* ICMP
* UDP
* TCP

## Examples
All the macros are essentially wrappers around the packet structures and functions in libpnet so all the set functions for the various packet types within libpnet are valid.  See the examples directory for complete examples.

Generate a destination unreachable ICMP packet and send it
```rust
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

let if_name = env::args().nth(1)
    .expect("Usage: ./packet_builder <interface name>");
let (mut sender, _receiver) = build_channel!(if_name);
sender.send_to(pkt.packet(), None).unwrap().unwrap();
```
Generate a TCP PSH|ACK packet with data
```rust
let mut pkt_buf = [0u8; 1500];
let pkt = packet_builder!(
     pkt_buf,
     ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) / 
     ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
     tcp({set_source => 43455, set_destination => 80, set_flags => (TcpFlags::PSH | TcpFlags::ACK)}) /
     payload({"hello".to_string().into_bytes()})
);
```
Generate a TCP SYN packet with mss and wscale options specified
```rust     
let mut pkt_buf = [0u8; 1500];
let pkt = packet_builder!(
   pkt_buf,
   ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) / 
   ipv4({set_source => ipv4addr!("192.168.1.1"), set_destination => ipv4addr!("127.0.0.1") }) /
   tcp({set_source => 43455, set_destination => 80, set_options => &[TcpOption::mss(1200), TcpOption::wscale(2)]}) /
   payload({"hello".to_string().into_bytes()})
);
```
Generate a UDP packet with data
```rust
let mut pkt_buf = [0u8; 1500];
let pkt = packet_builder!(
     pkt_buf,
     ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) / 
     ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
     udp({set_source => 12312, set_destination => 143}) /
     payload({"hello".to_string().into_bytes()})
);
```
Generate an ICMP Echo Request packet
```rust
let mut pkt_buf = [0u8; 1500];
let pkt = packet_builder!(
     pkt_buf,
     ether({set_destination => MacAddr(1,2,3,4,5,6), set_source => MacAddr(10,1,1,1,1,1)}) / 
     ipv4({set_source => ipv4addr!("127.0.0.1"), set_destination => ipv4addr!("127.0.0.1") }) /
     icmp_echo_req({set_icmp_type => IcmpTypes::EchoRequest}) / 
     payload({"hello".to_string().into_bytes()})
);
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
