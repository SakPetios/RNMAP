use log::{debug, error};
use std::{
    fs::File,
    io::{BufRead, BufReader}, net::Ipv4Addr,
};
pub fn get_gateway_ip() -> Option<String> {
    let file = match File::open("/proc/net/route") {
        Ok(file) => file,
        Err(er) => {
            error!("Error Opening /proc/net/route");
            debug!("Error Message: {}", er);
            return None;
        }
    };
    let reader = BufReader::new(file);
    for line in reader.lines().skip(1) {
        let line = match line {
            Ok(ln) => ln,
            Err(er) => {
                error!("Error Reading line");
                debug!("Error Message: {}", er);
                continue;
            }
        };
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let dest = parts[1];
        let gateway = parts[2];
        if dest != "00000000" {
            continue;
        };
        let gt_ip = u32::from_str_radix(gateway, 16).ok().map(|ip| {
            format!(
                "{}.{}.{}.{}",
                (ip & 0xFF) as u8,
                ((ip >> 8) & 0xFF) as u8,
                ((ip >> 16) & 0xFF) as u8,
                ((ip >> 24) & 0xFF) as u8
            )
        });
        if gt_ip == None {
            continue;
        }
        return gt_ip;
    }
    None
}

pub fn get_mac_with_ip(gip: &str) -> Option<String> {
    let file = match File::open("/proc/net/arp") {
        Ok(fl) => fl,
        Err(er) => {
            error!("/proc/net/arp not found!",);
            debug!("Error message: {}",er);
            return None;
        }
    };
    let reader = BufReader::new(file);
    for line in reader.lines().skip(1) {
        let line = match line {
            Ok(ln) => ln,
            Err(er) => {
                error!("Error reading line");
                debug!("Error message: {}",er);
                continue;
            }
        };
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {continue;}
        let ip = parts[0];
        if ip == gip {
            let mac = parts[3];
            return Some(mac.to_string());
        }
    }
    None
}
