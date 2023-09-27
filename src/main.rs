mod ping;
mod util;
mod portscan;
use std::net::Ipv6Addr;

use util::{get_gateway_ip,get_mac_with_ip};
use pnet::datalink;
use ping::{ICMPv4Ping,ICMPv6Ping};
use portscan::{TCPIPv6PortPinger,PortScanner};
fn main() {
    println!("{:?}",get_mac_with_ip(&get_gateway_ip().unwrap()));
    let target: Ipv6Addr = "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(); // @ Sorry
    let mut scanner = TCPIPv6PortPinger::new(target, "enp34s0", 8000);
    scanner.scan(0.01);
}
