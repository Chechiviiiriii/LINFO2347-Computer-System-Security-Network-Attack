#!/usr/bin/env python3
"""
Attack 1: Network Scan
Discovers reachable DMZ hosts with an ICMP sweep, then probes a small list
of TCP ports with SYN packets to identify open services.

Uses Scapy for packet crafting -- no external attack tools.

Usage (from mininet CLI):
    internet python3 attacks/attack_1.py
"""

from scapy.all import ICMP, IP, TCP, conf, send, sr1

conf.verb = 0

TARGETS = ["10.12.0.10", "10.12.0.20", "10.12.0.30", "10.12.0.40"]
PORTS = [21, 22, 53, 80, 123, 443, 5353]
TIMEOUT = 1


def icmp_sweep():
    """
    Send one ICMP Echo Request to each DMZ host.
    Returns the list of hosts that answered.
    """
    print("[*] ICMP sweep")
    alive_hosts = []

    for target in TARGETS:
        reply = sr1(IP(dst=target) / ICMP(), timeout=TIMEOUT, verbose=False)

        if reply is not None:
            print(f"[+] Host alive: {target}")
            alive_hosts.append(target)
        else:
            print(f"[-] No reply: {target}")

    return alive_hosts


def syn_scan(hosts):
    """Probe common TCP service ports with half-open SYN packets."""
    print("\n[*] TCP SYN scan")

    for host in hosts:
        print(f"\n[*] Target {host}")

        for port in PORTS:
            reply = sr1(
                IP(dst=host) / TCP(dport=port, flags="S"),
                timeout=TIMEOUT,
                verbose=False,
            )

            if reply is None:
                print(f"  {port}/tcp filtered or no response")
                continue

            if not reply.haslayer(TCP):
                print(f"  {port}/tcp unexpected reply")
                continue

            flags = reply[TCP].flags

            if flags == 0x12:  # SYN-ACK: port is open.
                print(f"  {port}/tcp OPEN")

                # Close the half-open connection created by the SYN scan.
                send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=False)
            elif flags == 0x14:  # RST-ACK: port is closed.
                print(f"  {port}/tcp closed")
            else:
                print(f"  {port}/tcp unexpected TCP flags: {flags}")


def main():
    alive_hosts = icmp_sweep()
    syn_scan(alive_hosts)


if __name__ == "__main__":
    main()
