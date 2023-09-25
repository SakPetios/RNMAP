pub trait PortScanner {
    fn ping(&mut self, port:u16) -> bool;
    fn scan(&mut self) -> Vec<u16> {
        let mut ports: Vec<u16> = Vec::new();
        for port in 0..u16::MAX {
            let open = self.ping(port);
            if open {
                ports.push(port);
            }
        }
        ports
    }
}