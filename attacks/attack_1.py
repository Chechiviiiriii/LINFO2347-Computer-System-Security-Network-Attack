#!/usr/bin/env python3
"""
Attack 1: Network Scan
Discovers reachable DMZ hosts with an ICMP sweep, then probes a list of TCP
ports with SYN packets to identify open services. Packets are sent in short
bursts to model a fast reconnaissance phase and to make rate-limit based
protections visible during the demonstration.

Uses Scapy for packet crafting -- no external attack tools.

Usage (from mininet CLI):
    internet python3 attacks/attack_1.py
"""

from scapy.all import ICMP, IP, TCP, conf, send, sr

conf.verb = 0

TARGETS = ["10.12.0.10", "10.12.0.20", "10.12.0.30", "10.12.0.40"]
PORTS = [21, 22, 53, 80, 123, 443, 5353]
ICMP_PROBES_PER_HOST = 3
TIMEOUT = 2


def icmp_sweep():
    """
    Send ICMP Echo Requests to each DMZ host in a short burst.
    Returns the list of hosts that answered.
    """
    print("[*] ICMP sweep")

    packets = [
        IP(dst=target) / ICMP(id=0x1001, seq=seq)
        for target in TARGETS
        for seq in range(ICMP_PROBES_PER_HOST)
    ]

    print(f"[*] Sending {len(packets)} ICMP probes in burst")
    answered, _ = sr(packets, timeout=TIMEOUT, retry=0, inter=0.001, verbose=False)

    alive_hosts = {
        received[IP].src
        for _, received in answered
        if received.haslayer(ICMP) and received[ICMP].type == 0
    }

    for target in TARGETS:
        if target in alive_hosts:
            print(f"[+] Host alive: {target}")
        else:
            print(f"[-] No reply: {target}")

    return sorted(alive_hosts)


def syn_scan():
    """Probe common TCP service ports with a burst of half-open SYN packets."""
    print("\n[*] TCP SYN scan")

    packets = [
        IP(dst=host) / TCP(sport=40000 + index, dport=port, flags="S")
        for index, (host, port) in enumerate(
            (host, port) for host in TARGETS for port in PORTS
        )
    ]

    print(f"[*] Sending {len(packets)} TCP SYN probes in burst")
    answered, _ = sr(packets, timeout=TIMEOUT, retry=0, inter=0.001, verbose=False)

    results = {
        (host, port): "filtered or no response"
        for host in TARGETS
        for port in PORTS
    }

    for sent, received in answered:
        host = sent[IP].dst
        port = sent[TCP].dport

        if not received.haslayer(TCP):
            results[(host, port)] = "filtered or unexpected reply"
            continue

        flags = int(received[TCP].flags)

        if flags == 0x12:  # SYN-ACK: port is open.
            results[(host, port)] = "OPEN"

            # Close the half-open connection created by the SYN scan.
            send(
                IP(dst=host)
                / TCP(
                    sport=sent[TCP].sport,
                    dport=port,
                    flags="R",
                    seq=received[TCP].ack,
                ),
                verbose=False,
            )
        elif flags == 0x14:  # RST-ACK: port is closed.
            results[(host, port)] = "closed"
        else:
            results[(host, port)] = f"unexpected TCP flags: {received[TCP].flags}"

    for host in TARGETS:
        print(f"\n[*] Target {host}")
        for port in PORTS:
            print(f"  {port}/tcp {results[(host, port)]}")


def main():
    icmp_sweep()
    syn_scan()


if __name__ == "__main__":
    main()
