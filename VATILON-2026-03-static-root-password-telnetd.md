# VATILON-2026-03 — telnetd runs unconditionally with a static root password compiled into the firmware image

|         |                                                                                           |
| ------------- | ----------------------------------------------------------------------------------------------- |
| Identifier    | VATILON-2026-03                                                                                 |
| CVE           | requested, not yet assigned                                                                     |
| CWE           | CWE-798 (use of hard-coded credentials), CWE-1392 (use of default credentials)                  |
| CVSS v3.1     | **9.8 critical** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` for `V1.16.39-20250721` and earlier. Lower for `V1.18.09` — see *Partially addressed in current firmware*. |
| Status | Independent disclosure — the vendor was not contacted. Rationale in [README.md](README.md#disclosure-statement). Published 2026-09-29. |
| Fix available | **Partially.** `V1.18.09` hardens the credential's storage. The always-on telnetd and the static, owner-unchangeable password remain. |

## Summary

The firmware starts a BusyBox `telnetd` on port 2360 on every boot, with no setting to disable it, and the `root` password it authenticates against is compiled into the firmware image. Every unit on a given build shares it, nothing about it is per-device, and an owner cannot change it: `/etc` is a tmpfs rebuilt from a read-only SquashFS at each boot, so any change reverts on the next power cycle.

On `V1.16.39-20250721` the credential is stored as a traditional DES-crypt hash, which makes it recoverable in seconds. The password for that build is **`ipc5120`**. `V1.18.09` replaces that storage with salted SHA-512; the credential for current firmware is *not* published here and has not been recovered.

## Affected

| Brand / model                                           | Product code | Firmware            | SoC                   | Root hash       | Password   |
| ------------------------------------------------------- | ------------ | ------------------- | --------------------- | --------------- | ---------- |
| SIMICAM A314D / **Vatilon H80**                         | `P22H`       | `V1.16.39-20250721` | HiSilicon hi3516cv610 | `TXkQvmswnVBSQ` (DES-crypt) | `ipc5120`  |
| Vatilon **H80 / H82**                                   | `P22H`       | `V1.18.09` (current) | HiSilicon hi3516cv610 | `$6$` SHA-512 crypt, in `/etc/shadow` | not recovered; not attempted |
| Sibling Vatilon models (previously published by others) | —            | earlier builds      | —                     | `8dxMkZjXi01sk` | `ipc@hs66` |

The pattern — a telnetd on a nonstandard port with a static root password baked into the image — holds across the product family; the password differs per build. The `ipc@hs66` credential is prior work by others, cited to establish the pattern.

## Partially addressed in current firmware

This finding has two halves, and only one of them is fixed. Stating them separately because the distinction is the difference between an accurate advisory and an overclaim.

**Fixed in `V1.18.09`:** the credential is no longer trivially recoverable. `/etc/passwd` became `root:x:0:0::/root:/bin/sh` and a mode-0640 `/etc/shadow` appeared holding a salted SHA-512 (`$6$`) hash, dated 2026-01-16 in the image. DES-crypt's 8-character truncation is gone. No attempt was made to recover this credential and no claim is made about its strength beyond the algorithm change.

**Not fixed in `V1.18.09`:**

- `telnetd -p 2360 &` is still launched unconditionally from `run.sh`, with no setting to disable it.
- The password is still identical on every unit running a given build, still derived from nothing per-device.
- It still lives inside a read-only image, so an owner still cannot change it persistently.

So the design defect — CWE-798, a hard-coded credential on a permanently exposed remote shell — stands in current firmware. What changed is the cost of exploiting it: from "read the published password" to "crack a salted SHA-512 hash", which may never be practical. Anyone scoring this should score the two builds separately, and anyone still running `V1.16.39` or earlier should treat their root password as public.

## Description

`/etc/passwd` is in neither the writable configuration partition nor the application SquashFS. It lives in the kernel's built-in initramfs — an xz cpio inside the LZMA kernel inside the FIT image on `mtd1` — and reads:

```
root:TXkQvmswnVBSQ:0:0::/root:/bin/sh
```

On this build there is no `/etc/shadow`; the DES-crypt hash sits in the world-readable `passwd` file. Being inside the kernel image, it is fixed for the build — changing it requires reflashing the kernel partition. `V1.18.09` moved the hash to `/etc/shadow` and changed the algorithm, but it is still inside the same read-only kernel initramfs, so it is still fixed for the build.

Traditional DES crypt truncates at 8 characters, so the hash falls to brute force on a single consumer GPU in seconds — the choice of password is close to irrelevant. Treat any DES-crypt root hash recovered from a firmware image of this family as already public.

## Proof of concept

On `V1.16.39-20250721`: `telnet <target> 2360`, then log in as `root` with `ipc5120`. The session lands at a root shell.

On `V1.18.09` the same service is reachable at the same port, but the credential has not been recovered, so no working login is published for that build.

## How to tell which build you have

`V1.16.39-20250721` and earlier are the builds whose root password is public. Check the firmware version in the camera's web interface. If it is at or below `V1.16.39`, the root password on your camera is `ipc5120` and anyone can read that here.

## Impact

Interactive root on every unit of a given build, over the network, with a credential the owner cannot change. Unlike VATILON-2026-01 it needs no custom tooling — a telnet client is enough. On `V1.16.39` and earlier the credential is public, which makes this immediately exploitable by anyone; on `V1.18.09` exploitation additionally requires recovering a salted SHA-512 hash from the firmware image, which may not be practical.

The two combine badly: an attacker who does not know the static password can set one through the UDP 6789 backdoor and log in interactively anyway. Either way the service is reachable at every boot.

## Mitigation

The password cannot be persistently changed and telnetd cannot be disabled, on any build including the current one. Network isolation or replacing the firmware are the only options — see VATILON-2026-01. Updating to `V1.18.09` is worth doing if you are on an older build, because it removes the public credential, but it does not close the telnet service and it does not address VATILON-2026-01.

## Credit

Found and reported by [@eseverson](https://github.com/eseverson). The sibling-model `ipc@hs66` credential is prior work by others, cited above for context.

## References

* Prior documentation of the sibling models' telnet access and `8dxMkZjXi01sk` / `ipc@hs66`: <https://github.com/mtrakal/ipc-vatilon>
