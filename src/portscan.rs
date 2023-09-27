use std::net::{IpAddr, Ipv6Addr};

use crate::util::{self, get_gateway_ip, get_mac_with_ip};
use log::{debug, error};
use pnet::{
    datalink::{self, Channel::Ethernet, DataLinkReceiver, DataLinkSender, NetworkInterface},
    packet::{
        ethernet::{EtherTypes, MutableEthernetPacket, EthernetPacket},
        ip::{self, IpNextHeaderProtocols},
        ipv6::{MutableIpv6Packet, Ipv6Packet}, tcp::{MutableTcpPacket, TcpFlags, ipv6_checksum as tcp_ipv6_checksum, TcpPacket}, Packet,
    },
    util::MacAddr,
};
use std::thread::sleep;
use std::time::Duration;

pub trait PortScanner {
    fn ping(&mut self, port: u16) -> bool;
    fn scan(&mut self, delay: f32) -> Vec<u16> {
        let mut ports: Vec<u16> = Vec::new();
        for port in 0..u16::MAX {
            let open = self.ping(port);
            if open {
                ports.push(port);
            }
            sleep(Duration::from_secs_f32(delay))
        }
        ports
    }
}

pub struct TCPIPv6PortPinger {
    myip: Ipv6Addr,
    target_ip: Ipv6Addr,
    gateway_mac: MacAddr,
    iface: NetworkInterface,
    sport:u16,
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
}

impl TCPIPv6PortPinger {
    pub fn new(target_ip: Ipv6Addr, interface_name: &str, sport:u16) -> TCPIPv6PortPinger {
        let ifaces = datalink::interfaces();
        let iface = ifaces // @ Netowrk Interface
            .iter()
            .find(|face| face.is_running() && face.is_up() && !face.is_loopback());
        if iface == None {
            error!("No Interface matching the name {} found", interface_name);
        }
        let iface = iface.unwrap();

        let gateway_ip = get_gateway_ip();
        if gateway_ip == None {
            error!("No Gateway IP found. Check /proc/net/route")
        }
        let gateway_mac = get_mac_with_ip(&gateway_ip.unwrap());
        if gateway_mac == None {
            error!("No Gateway MAC found. Check /proc/net/arp")
        }
        let gateway_mac = gateway_mac.unwrap().parse().unwrap();

        let ipv6 = iface.ips.iter().find(|ip| ip.is_ipv6());
        if ipv6 == None {
            error!("No IPV6 found")
        }
        let ip = match ipv6.unwrap().ip() {
            IpAddr::V4(_) => panic!("Impossible Error. Well Done"),
            IpAddr::V6(ip) => ip,
        };
        let (tx, rx) = match datalink::channel(iface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };
        TCPIPv6PortPinger {
            myip: ip,
            target_ip,
            gateway_mac,
            iface: iface.clone(),
            sport,
            tx,
            rx,
        }
    }
}

impl PortScanner for TCPIPv6PortPinger {
    fn ping(&mut self, port: u16) -> bool {
        println!("Pinging port: {}",port);
        let mut ether_buffer = [0u8; 128];
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ether_buffer).unwrap();

        ethernet_packet.set_destination(self.gateway_mac);
        ethernet_packet.set_source(self.iface.mac.unwrap());
        ethernet_packet.set_ethertype(EtherTypes::Ipv6);

        let mut ip_buffer = [0u8; 112];
        let mut ip_packet = MutableIpv6Packet::new(&mut ip_buffer).unwrap();
        ip_packet.set_version(6);
        ip_packet.set_traffic_class(0);
        ip_packet.set_flow_label(0);
        ip_packet.set_payload_length(72); // Length of your ICMPv6 packet
        ip_packet.set_next_header(IpNextHeaderProtocols::Tcp);
        ip_packet.set_hop_limit(64);
        ip_packet.set_source(self.myip);
        ip_packet.set_destination(self.target_ip);

        let mut tcp_buffer = [0u8; 72];
        let mut tcp_packet =
            MutableTcpPacket::new(&mut tcp_buffer).expect("Failed to create TCP packet");
        tcp_packet.set_source(self.sport);
        tcp_packet.set_destination(port);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_checksum(0); // Will be calculated later
        // Calculate the TCP checksum
        let checksum = tcp_ipv6_checksum(&tcp_packet.to_immutable(), &self.myip, &self.target_ip);
        tcp_packet.set_checksum(checksum);
        ip_packet.set_payload(tcp_packet.packet());
        ethernet_packet.set_payload(ip_packet.packet());
        self.tx.send_to(ethernet_packet.packet(), None);
        for _ in 0..30 {
            let pack = self.rx.next();
            let pack = match pack {
                Ok(pack) => pack,
                Err(er) => {
                    error!("Error Reciving the packets");
                    debug!("Error message: {}",er);
                    continue;
                }
            };
            let ethpak = EthernetPacket::new(pack);
            if ethpak == None {
                continue;
            }
            let ethernet_packet = ethpak.unwrap();
            let ip_pack = Ipv6Packet::new(ethernet_packet.payload());
            if ip_pack == None {
                continue;
            }
            let ip_packet = ip_pack.unwrap();
            if ip_packet.get_source() == self.target_ip {
                println!("{}",port);
                return true;
            }
            sleep(Duration::from_secs_f32(0.1))
        };
        false
    }
}
