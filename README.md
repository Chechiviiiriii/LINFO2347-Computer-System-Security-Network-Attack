# LINFO2347 -- Project 2: Network Attacks

## Overview

This project implements a basic enterprise network protection using nftables firewall rules on a Mininet-simulated network, along with network attack scripts and their corresponding defenses.

---

## Network Topology

```
            10.1.0.0/24                10.12.0.0/24                10.2.0.0/24
   +-----------------------+   +----------------------------+   +-----------------+
   |  Workstation LAN      |   |           DMZ              |   |    Internet     |
   |                       |   |                            |   |                 |
   |  ws2  10.1.0.2        |   |  http  10.12.0.10          |   |  internet       |
   |  ws3  10.1.0.3        |   |  dns   10.12.0.20  :5353   |   |   10.2.0.2      |
   |                       |   |  ntp   10.12.0.30          |   |                 |
   |        (gw .1)        |   |  ftp   10.12.0.40          |   |     (gw .1)     |
   +-----------+-----------+   |  (gw r1=.1, r2=.2)         |   +--------+--------+
               |               +------+----------------+----+            |
               | s1                   | s2             |                 |
               |                      |                |                 |
          +----+---- r1 --------------+                +-------- r2 -----+
          r1-eth0 (10.1.0.1)                            r2-eth0 (10.2.0.1)
          r1-eth12 (10.12.0.1)                          r2-eth12 (10.12.0.2)
```

**Services running in the DMZ:**
- `http` -- Apache2 (port 80), sshd (port 22)
- `dns` -- dnsmasq (port 5353)
- `ntp` -- OpenNTPD (port 123), sshd (port 22)
- `ftp` -- vsftpd (port 21), sshd (port 22)

---

## Base Firewall (`firewall-rules.nft`)

### Three-zone policy

| Source zone | Can initiate connections to |
|---|---|
| Workstations (10.1.0.0/24) | DMZ + Internet + other workstations |
| DMZ (10.12.0.0/24) | Nothing -- reply traffic only |
| Internet (10.2.0.0/24) | DMZ only (never workstations) |

Return traffic for established/related connections is always allowed.

### How to run

```bash
sudo mn -c
cd ~/LINFO2347/project-network-attacks
sudo -E python3 topo.py
```

From the Mininet CLI:

```
r1 nft -f firewall-rules.nft
r2 nft -f firewall-rules.nft
```

### Baseline connectivity tests

```
ws2 ping -c 2 10.12.0.10         # WS -> DMZ       : 0% loss
ws2 ping -c 2 10.2.0.2           # WS -> Internet  : 0% loss
internet ping -c 2 10.12.0.10    # Internet -> DMZ : 0% loss
http ping -c 2 -W 2 10.1.0.2     # DMZ -> WS       : 100% loss (blocked)
http ping -c 2 -W 2 10.2.0.2     # DMZ -> Internet : 100% loss (blocked)
internet ping -c 2 -W 2 10.1.0.2 # Internet -> WS  : 100% loss (blocked)
```

---

## Attacks and Protections

---

### Attack 2 -- FTP Brute-Force

#### The attack (`attacks/attack_2.py`)

The script performs a brute-force attack against the FTP server (`ftp`, 10.12.0.40) by trying 200 username/password combinations (10 usernames x 20 passwords).

The FTP protocol is implemented from scratch using Python's `socket` standard library -- no external dependencies. The exchange follows the plaintext FTP authentication flow:

```
Client -> Server : USER <username>
Server -> Client : 331 Password required
Client -> Server : PASS <password>
Server -> Client : 230 Login successful   (or 530 Login incorrect)
```

The script distinguishes three outcomes per attempt:
- `SUCCESS` -- server returned 230 (valid credentials found)
- `rejected` -- server returned 530 (wrong credentials, connection worked)
- `blocked/timeout` -- connection timed out or was refused (rate-limit active)

**Run the attack (no protection):**

```
r1 nft -f firewall-rules.nft
r2 nft -f firewall-rules.nft
internet python3 attacks/attack_2.py 10.12.0.40
```

Expected output: 199 `rejected`, 1 `SUCCESS` (`mininet:mininet`).

#### The protection (`protection/protection_2.nft`)

The protection limits new TCP connections to port 21 to **4 per minute per source IP** (with an initial burst of 3). A brute-force that opens dozens of connections per second is stopped after the first burst; a legitimate user opening 1-2 FTP sessions is unaffected.

**How it does not break the base firewall:**

`protection_2.nft` is additive -- it does not modify or flush the base firewall. It adds a new nftables chain (`ftp_brute_protection`) at hook priority -10, which is evaluated before the base `forward` chain (priority 0). The chain only handles new TCP connections to port 21; all other traffic falls through to the base firewall unchanged.

- `iifname "r2-eth0"` -- rate-limit applies only for Internet-side traffic on r2
- `iifname "r1-eth0"` -- rate-limit applies only for workstation-side traffic on r1

This means the six baseline ping tests are unaffected (ICMP, not TCP port 21).

**Apply the protection on top of the base firewall:**

```
r1 nft -f firewall-rules.nft
r2 nft -f firewall-rules.nft
r1 nft -f protection/protection_2.nft
r2 nft -f protection/protection_2.nft
```

**Run the attack with protection active:**

```
internet python3 attacks/attack_2.py 10.12.0.40
```

Expected output: 3 `rejected` (burst), 197 `blocked/timeout`.

**Inspect the meter:**

```
r2 nft list meters
```

**Verify baseline tests still pass:**

```
ws2 ping -c 2 10.12.0.10
ws2 ping -c 2 10.2.0.2
internet ping -c 2 10.12.0.10
http ping -c 2 -W 2 10.1.0.2
http ping -c 2 -W 2 10.2.0.2
internet ping -c 2 -W 2 10.1.0.2
```

---

### Attack 3 -- ARP Cache Poisoning (Man-in-the-Middle)

#### The attack (`attacks/attack_3.py`)

ARP (Address Resolution Protocol) operates at Layer 2 and has no authentication mechanism: any host can send an ARP reply claiming to own any IP address. The script exploits this by continuously sending forged ARP replies to two targets, inserting the attacker into the middle of their communication.

The script is implemented with Scapy only -- no external attack tools. The core logic:

1. **Resolve real MACs** -- `getmacbyip()` sends an ARP request to learn the genuine MAC of each target before poisoning begins.
2. **Forge ARP replies** -- two packets are built per round:
   - To target2: "target1's IP is at attacker's MAC"
   - To target1: "target2's IP is at attacker's MAC"
3. **Send periodically** -- `sendp()` delivers the forged replies directly at Layer 2 (Ethernet frame with explicit destination MAC), bypassing the OS routing stack.
4. **Restore on exit** -- on Ctrl+C or normal termination, the real MAC mappings are sent to both victims (repeated 5 times) to undo the poisoning.

The attack must be launched from a host on the same LAN segment as both targets (ARP is not routed). In this topology, ws3 attacks the ws2 -- r1 pair on the 10.1.0.0/24 segment.

**Important:** ARP poisoning only updates an existing cache entry. Trigger initial communication between the targets first so their ARP caches are populated, then the forged replies overwrite those entries.

**Run the attack (no protection):**

```
r1 nft -f firewall-rules.nft
r2 nft -f firewall-rules.nft
ws3 python3 attacks/attack_3.py --target1 10.1.0.2 --target2 10.1.0.1 --verbose > /tmp/ataque.log 2>&1 &
```

Force initial ARP resolution on both targets:

```
ws2 ping -c 1 10.1.0.1
r1 ping -c 1 10.1.0.2
```

Verify the ARP caches have been poisoned (both should show ws3's MAC):

```
ws2 ip neigh show
r1 ip neigh show
```

Confirm traffic interception -- ws2's packets to the DMZ pass through ws3:

```
ws3 tcpdump -i any -n icmp -w /tmp/intercept.pcap &
ws2 ping -c 5 10.12.0.10
ws3 kill %2
ws3 tcpdump -r /tmp/intercept.pcap -n
```

Evidence of interception: ICMP Redirect messages (`From 10.1.0.3: Redirect Host`) appear in ws2's ping output, confirming packets reached ws3 before being forwarded.

#### The protection (`protection/protection_3.nft`)

> Protection not yet implemented.

---

## File Structure

```
project-network-attacks/
|-- topo.py                  # Mininet topology (provided by the course)
|-- firewall-rules.nft       # Base three-zone enterprise firewall
|-- attacks/
|   |-- attack_2.py          # FTP brute-force (Python stdlib, no dependencies)
|   `-- attack_3.py          # ARP cache poisoning MITM (Scapy)
|-- protection/
|   `-- protection_2.nft     # FTP rate-limiting (additive nftables chain)
`-- README.md
```
