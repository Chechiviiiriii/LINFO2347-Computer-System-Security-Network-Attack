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

### Attack 1 -- Network Scan

#### The attack (`attacks/attack_1.py`)

The script performs reconnaissance against the DMZ from the Internet host. It first sends ICMP Echo Requests to discover reachable DMZ hosts, then sends TCP SYN packets to a small set of common service ports to identify which services are open.

The attack is implemented with Scapy only -- no external scanning tools. It probes the four DMZ servers (`http`, `dns`, `ntp`, `ftp`) and checks ports `21`, `22`, `53`, `80`, `123`, `443`, and `5353`.

**Run the attack (no protection):**

```
r1 nft -f firewall-rules.nft
r2 nft -f firewall-rules.nft
internet python3 attacks/attack_1.py
```

Expected output: the script lists alive DMZ hosts and reports open TCP ports such as HTTP on `80/tcp`, FTP on `21/tcp`, SSH on `22/tcp`, and DNS on `5353/tcp` if the service responds over TCP.

#### The protection (`protection/protection_1.nft`)

The protection rate-limits scan-like traffic from the Internet towards the DMZ. ICMP sweep traffic is limited to `2/second` with a burst of 2 packets, and TCP SYN scan traffic is limited to `5/second` with a burst of 3 packets.

**How it does not break the base firewall:**

`protection_1.nft` is additive -- it adds a separate chain at hook priority `-1` and does not flush the base firewall. It only limits ICMP and new TCP SYN packets from `10.2.0.0/24` to `10.12.0.0/24`; other traffic continues to be handled by the base rules.

**Apply the protection on top of the base firewall:**

```
r1 nft -f firewall-rules.nft
r2 nft -f firewall-rules.nft
r2 nft -f protection/protection_1.nft
```

**Run the attack with protection active:**

```
internet python3 attacks/attack_1.py
```

Expected output: the scan becomes incomplete or slower because excess ICMP/SYN probes are dropped, while legitimate low-rate access remains possible.

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

### Attack 4 -- Reflected DNS Flood

#### The attack (`attacks/attack_4.py`)

The script performs a reflected DNS flood using IP spoofing. It runs from the Internet host and sends DNS requests to the DMZ DNS server (`dns`, `10.12.0.20:5353`) while forging the source IP as the victim workstation (`ws2`, `10.1.0.2`). The DNS server then sends its replies to the victim, reflecting traffic through a legitimate DMZ service.

The attack is implemented with Scapy only -- no external attack tools. Each packet is a UDP DNS query for `example.com` with:

- source IP: `10.1.0.2` (victim)
- destination IP: `10.12.0.20` (DNS reflector)
- destination port: `5353`

**Run the attack (no protection):**

```
r1 nft -f firewall-rules.nft
r2 nft -f firewall-rules.nft
ws2 timeout 8 tcpdump -i any -n "udp and src host 10.12.0.20 and port 5353" -c 10 > /tmp/attack_4.log 2>&1 &
internet python3 attacks/attack_4.py
ws2 cat /tmp/attack_4.log
```

Expected output: `ws2` captures DNS replies from `10.12.0.20`, even though `ws2` did not send the DNS queries itself.

#### The protection (`protection/protection_4.nft`)

The protection implements ingress anti-spoofing on `r2`. Packets entering from the Internet-facing interface (`r2-eth0`) are dropped if they claim to come from internal enterprise ranges (`10.1.0.0/24` or `10.12.0.0/24`).

**How it does not break the base firewall:**

`protection_4.nft` is additive -- it creates a separate `inet` table with a `prerouting` chain and does not flush the base firewall. Legitimate Internet traffic has source `10.2.0.0/24`, so normal Internet-to-DMZ access is unaffected.

**Apply the protection on top of the base firewall:**

```
r1 nft -f firewall-rules.nft
r2 nft -f firewall-rules.nft
r2 nft -f protection/protection_4.nft
```

**Run the attack with protection active:**

```
ws2 timeout 8 tcpdump -i any -n "udp and src host 10.12.0.20 and port 5353" -c 5 > /tmp/attack_4_protected.log 2>&1 &
internet python3 attacks/attack_4.py
ws2 cat /tmp/attack_4_protected.log
```

Expected output: `ws2` should not receive reflected DNS replies because the spoofed packets are dropped before reaching the DNS server.

**Inspect the protection counter:**

```
r2 nft list ruleset
```

The drop counter in `protection_4.nft` should increase while the attack runs.

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

## File Structure

```
project-network-attacks/
|-- topo.py                  # Mininet topology (provided by the course)
|-- firewall-rules.nft       # Base three-zone enterprise firewall
|-- attacks/
|   |-- attack_1.py          # Network scan (Scapy)
|   |-- attack_2.py          # FTP brute-force (Python stdlib, no dependencies)
|   `-- attack_4.py          # Reflected DNS flood (Scapy)
|-- protection/
|   |-- protection_1.nft     # ICMP/SYN scan rate-limiting
|   |-- protection_2.nft     # FTP rate-limiting (additive nftables chain)
|   `-- protection_4.nft     # Anti-spoofing for reflected DNS flood
`-- README.md
```
