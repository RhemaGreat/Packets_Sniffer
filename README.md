# Packet Sniffer

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-success)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview

Packet Sniffer is a Python-based network analysis tool that captures and inspects network packets using the Scapy library.

The project demonstrates how packets traverse a network by allowing users to observe protocols, source and destination addresses, and payload information in real time. It serves as an educational tool for learning network protocols and packet analysis techniques.

This project is intended for cybersecurity education, defensive research, and authorized network monitoring.

---

## Features

- Capture live network packets
- Display packet information
- Inspect protocol headers
- Analyze source and destination addresses
- Lightweight implementation
- Built with Scapy

---

## Technologies

- Python 3
- Scapy
- Linux

---

## Repository Structure

```
Packets_Sniffer/
│
├── packet_sniffer.py
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.9+
- Scapy
- Root/Administrator privileges

Install dependencies:

```bash
pip install -r requirements.txt
```

or

```bash
pip install scapy
```

---

## Usage

Run the sniffer:

```bash
sudo python3 packet_sniffer.py
```

Captured packets will be displayed in the terminal as they are received.

---

## Learning Objectives

This project demonstrates:

- Packet sniffing fundamentals
- Network protocol analysis
- TCP/IP packet structures
- Scapy packet manipulation
- Real-time traffic monitoring
- Cybersecurity research techniques

---

## Supported Protocols

Depending on the implementation, captured packets may include:

- Ethernet
- ARP
- IPv4
- IPv6
- ICMP
- TCP
- UDP
- DNS
- HTTP

---

## Example Output

```
Source: 192.168.1.5
Destination: 8.8.8.8
Protocol: UDP
Length: 78 bytes
```

---

## Ethical Use

This project is intended only for:

- Educational purposes
- Authorized penetration testing
- Defensive cybersecurity research
- Laboratory environments

Do not capture or inspect traffic on networks without proper authorization.

---

## Future Improvements

- Protocol filtering
- Interface selection
- Packet logging
- PCAP export
- Colorized terminal output
- Command-line arguments
- Statistics dashboard
- Unit tests

---

## Contributing

Contributions are welcome through pull requests or issue reports.

---

## Author

**Rhema Great**

GitHub: https://github.com/RhemaGreat

---

## License

Licensed under the MIT License.
