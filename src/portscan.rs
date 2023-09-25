use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::util::{get_gateway_ip,get_mac_with_ip};
use log::error;
use pnet::{
    datalink::{self, Channel::Ethernet, NetworkInterface},
    packet::{
        icmp::{checksum as icmpv4_checksum, IcmpTypes, MutableIcmpPacket},
        icmpv6::checksum as icmpv6_checksum,
        icmpv6::{Icmpv6Types, MutableIcmpv6Packet, Icmpv6Code, echo_reply::Icmpv6Codes},
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
        ipv6::{Ipv6Packet, MutableIpv6Packet},
        MutablePacket, Packet, ethernet::{MutableEthernetPacket, EtherTypes},
    },
};

/// FIXME
pub struct ICMPv4Ping {
    target: Ipv4Addr,
    interface: NetworkInterface,
}

impl ICMPv4Ping {
    pub fn new(target: Ipv4Addr) -> ICMPv4Ping {
        let ifaces = datalink::interfaces();
        let iface = ifaces
            .iter()
            .find(|face| !face.is_loopback() && face.is_running() && face.is_up())
            .expect("No suitable intefaces found");
        println!("Using Iface: {}", iface.name);
        let scanner = ICMPv4Ping {
            target,
            interface: iface.clone(),
        };
        scanner
    }
    pub fn ping(&mut self) {
        // ! FIX THIS
        let source_ip = match self
            .interface
            .ips
            .iter()
            .find(|ip| ip.is_ipv4())
            .unwrap()
            .ip()
        {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => panic!("how"),
        };
        println!("Source ip: {:?}", source_ip);
        let mut ip_buffer = [0u8; 36];
        let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length(64);
        ip_packet.set_ttl(64);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(self.target);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

        let mut icmp_buffer = [0u8; 16];
        let mut icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_checksum(icmpv4_checksum(&icmp_packet.to_immutable()));
        icmp_packet.set_payload("Hello World".as_bytes());
        ip_packet.set_payload(icmp_packet.packet_mut());
        let (mut tx, mut _rx) = match datalink::channel(&self.interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };
        tx.send_to(ip_packet.packet(), None);
    }
}

pub struct ICMPv6Ping {
    target: Ipv6Addr,
    interface: NetworkInterface,
}

impl ICMPv6Ping {
    pub fn new(target: Ipv6Addr) -> ICMPv6Ping {
        let ifaces = datalink::interfaces();
        let iface = ifaces
            .iter()
            .find(|face| !face.is_loopback() && face.is_running() && face.is_up())
            .expect("No suitable intefaces found");
        println!("Using Iface: {}", iface.name);
        let scanner = ICMPv6Ping {
            target,
            interface: iface.clone(),
        };
        scanner
    }
    pub fn ping(&mut self) {
        let source_ip = match self
            .interface
            .ips
            .iter()
            .find(|ip| ip.is_ipv6())
            .unwrap()
            .ip()
        {
            IpAddr::V4(_) => panic!("how"),
            IpAddr::V6(ip) => ip,
        };
        
        println!("Source ip: {:?}", source_ip);
        let gateway_ip = get_gateway_ip();
        if gateway_ip == None {
            error!("No gateway IP found");
        };
        let gateway_mac = get_mac_with_ip(&gateway_ip.unwrap());
        if gateway_mac == None {
            error!("No gateway MAC found")
        }
        let gateway_mac = gateway_mac.unwrap();

        let mut ether_buffer = [0u8;80];
        let mut etherpacket = MutableEthernetPacket::new(&mut ether_buffer).unwrap();
        etherpacket.set_ethertype(EtherTypes::Ipv6);
        etherpacket.set_source(self.interface.mac.unwrap());
        etherpacket.set_destination(gateway_mac.parse().unwrap());
        // etherpacket.set_destination(self.interface.);
        let mut ip_buffer = [0u8; 64];
        let mut ip_packet = MutableIpv6Packet::new(&mut ip_buffer).unwrap();
        ip_packet.set_version(6);
        ip_packet.set_traffic_class(0);
        ip_packet.set_flow_label(0);
        ip_packet.set_payload_length(16); // Length of your ICMPv6 packet
        ip_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ip_packet.set_hop_limit(64);
        ip_packet.set_source(source_ip);
        ip_packet.set_destination(self.target);

        let mut icmp_buffer = [0u8; 16];
        let mut icmp_packet = MutableIcmpv6Packet::new(&mut icmp_buffer).unwrap();
        icmp_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        icmp_packet.set_icmpv6_code(Icmpv6Codes::NoCode);
        icmp_packet.set_payload("Hello World".as_bytes());
        icmp_packet.set_checksum(icmpv6_checksum(&icmp_packet.to_immutable(), &source_ip, &self.target));

        ip_packet.set_payload(icmp_packet.packet());
        etherpacket.set_payload(ip_packet.packet());
        let (mut tx, mut _rx) = match datalink::channel(&self.interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };
        println!("{:?}",etherpacket.packet().len());
        tx.send_to(etherpacket.packet(), None);
    }
}
