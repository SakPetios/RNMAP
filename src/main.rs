mod portscan;
mod util;
use util::{get_gateway_ip,get_mac_with_ip};
use pnet::datalink;
use portscan::{ICMPv4Ping,ICMPv6Ping};
fn main() {
    println!("{:?}",get_mac_with_ip(&get_gateway_ip().unwrap()));
    let mut scanner = ICMPv6Ping::new("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap());
    scanner.ping();
}
