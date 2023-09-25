mod ping;
mod util;
mod portscan;
use util::{get_gateway_ip,get_mac_with_ip};
use pnet::datalink;
use ping::{ICMPv4Ping,ICMPv6Ping};
fn main() {
    println!("{:?}",get_mac_with_ip(&get_gateway_ip().unwrap()));
    let mut scanner = ICMPv6Ping::new();
    scanner.ping("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap());
}
