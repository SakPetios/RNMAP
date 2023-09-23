# Rust Nmap Clone

## Description

This project is a Rust-based clone of the popular network scanning tool Nmap. It aims to provide similar functionality for network discovery and security auditing in a Rust programming language context.

## Features

- **Network Scanning**: Conduct comprehensive network scans to discover live hosts, open ports, and service information.
- **OS Detection**: Attempt to identify the operating systems of discovered hosts.
- **Service Version Detection**: Detect and report on the versions of services running on open ports.
- **Scriptable**: Implement custom scripts for specific network tasks and security checks.
- **Fast and Efficient**: Designed to be fast and efficient, making use of Rust's performance capabilities.

## Installation

1. Clone the repository:

   `git clone https://github.com/SakPetios/RNMAP.git`
   `cd RNMAP`

2. Build the project:

   `cargo build --release`

3. Run the Rust Nmap Clone:

   `cargo run -- [scan options]`

## Usage

To use the Rust Nmap Clone, you can specify various scan options to tailor your network scanning needs. Here are some basic examples:

- Basic TCP SYN scan:

  `cargo run -- -sS target_ip`

- OS detection:

  `cargo run -- -O target_ip`

- Service version detection:

  `cargo run -- -sV target_ip`

- Custom scripts:

  `cargo run -- -sC target_ip`

Please refer to the documentation and source code for more advanced usage and customization options.

## Contributing

Contributions to this project are welcome! If you'd like to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bugfix: `git checkout -b feature/new-feature`.
3. Make your changes and commit them with clear messages.
4. Push your changes to your fork: `git push origin feature/new-feature`.
5. Create a pull request to the main repository's `master` branch.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

This project is inspired by the original Nmap tool and aims to provide a Rust-based alternative for network scanning and security auditing.
