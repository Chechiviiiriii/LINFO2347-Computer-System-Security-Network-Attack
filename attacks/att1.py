#!/usr/bin/env python3
"""
Network Scan Attack
Attacker: internet (10.2.0.2)
Target: DMZ network (10.12.0.0/24)
Techniques: ICMP sweep + TCP SYN scan
"""
from scapy.all import IP, ICMP, TCP, sr1, send, conf

conf.verb = 0

TARGETS = ["10.12.0.10", "10.12.0.20", "10.12.0.30", "10.12.0.40"]
PORTS = [21, 22, 53, 80, 123, 443, 5353]

def icmp_sweep():
    print("[*] ICMP sweep")
    alive = []

    for ip in TARGETS:
        pkt = IP(dst=ip) / ICMP()
        ans = sr1(pkt, timeout=1)

        if ans is not None:
            print(f"[+] Host alive: {ip}")
            alive.append(ip)
        else:
            print(f"[-] No reply: {ip}")

    return alive

def syn_scan(hosts):
    print("\n[*] TCP SYN scan")

    for ip in hosts:
        print(f"\nTarget {ip}")

        for port in PORTS:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            ans = sr1(pkt, timeout=1)

            if ans is None:
                print(f"  {port}/tcp filtered or no response")

            elif ans.haslayer(TCP):
                flags = ans[TCP].flags

                if flags == 0x12:  # SYN-ACK
                    print(f"  {port}/tcp OPEN")
                    rst = IP(dst=ip) / TCP(dport=port, flags="R")
                    send(rst)

                elif flags == 0x14:  # RST-ACK
                    print(f"  {port}/tcp closed")

if __name__ == "__main__":
    alive_hosts = icmp_sweep()
    syn_scan(alive_hosts)
