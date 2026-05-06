#!/bin/sh
#
# Apply Protection 3: ARP Anti-Spoofing
#
# Usage from Mininet CLI:
#   ws2 sh protection/protection_3_apply.sh 10.1.0.1
#   r1  sh protection/protection_3_apply.sh 10.1.0.2
#
# The argument is the IP address that this host should trust. The script reads
# the current legitimate MAC from the neighbor table and installs an nftables
# ARP rule that drops replies where that IP is claimed by any other MAC.

set -eu

PROTECTED_IP="${1:-}"

if [ -z "$PROTECTED_IP" ]; then
    echo "Usage: $0 <trusted-ip>"
    exit 1
fi

# Ensure a neighbor entry exists before reading the trusted MAC.
ping -c 1 -W 1 "$PROTECTED_IP" >/dev/null 2>&1 || true

TRUSTED_MAC="$(ip neigh show "$PROTECTED_IP" | awk '/lladdr/ { print $5; exit }')"

if [ -z "$TRUSTED_MAC" ]; then
    echo "[-] Could not resolve MAC for $PROTECTED_IP"
    exit 1
fi

cat >/tmp/protection_3_generated.nft <<EOF
table arp arp_spoofing_protection {
    chain input_arp_guard {
        type filter hook input priority -300; policy accept;

        arp operation reply arp saddr ip $PROTECTED_IP arp saddr ether != $TRUSTED_MAC drop
    }
}
EOF

nft -f /tmp/protection_3_generated.nft

echo "[+] ARP anti-spoofing enabled"
echo "[+] Trusted binding: $PROTECTED_IP -> $TRUSTED_MAC"
