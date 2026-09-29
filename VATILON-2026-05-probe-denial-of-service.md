# VATILON-2026-05 — A single service-version scan takes the camera off the air for minutes

| | |
| --- | --- |
| Identifier | VATILON-2026-05 |
| CVE | requested, not yet assigned |
| CWE | CWE-400 (uncontrolled resource consumption) |
| CVSS v3.1 | **7.5 high** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| Status | Independent disclosure — the vendor was not contacted. Rationale in [README.md](README.md#disclosure-statement). Published `<date>`. |
| Fix available | No. |

## Summary

All of the camera's network services are served by a single process. An `nmap -sV` version scan crashes it, taking every service down at once. No authentication is required, and the device recovers on its own after roughly four minutes — in one case about ten.

## Affected

SIMICAM A314D / **Vatilon H80**, product code `P22H`, firmware `V1.16.39-20250721`, HiSilicon hi3516cv610. Confirmed live on owned hardware.

Not tested on the Fullhan build, and **not tested on `V1.18.09`** — the research unit was reflashed before that image was obtained, so this finding cannot be re-confirmed on current firmware without another device. The single-process architecture that makes the whole device fail together is unchanged in `V1.18.09`, but that is an observation about the design, not a test of the crash. Treat current firmware as untested rather than unaffected.

## Description

Ports 80, 554, 2360, 9101 and 34567 are all served by the same `ipcam` process; they go down together and come back together.

Observed during testing:

- `nmap -sV` against the device reliably induced the crash.
- Rapid repeated telnet login attempts also induced it.
- Paced attempts — roughly one every three seconds — did not.

ICMP answers throughout, so the device looks healthy to ping monitoring while every service on it is gone. Observed three times in one session, recovery unattended each time.

The specific input that kills the process was not isolated; this advisory claims the reachable effect — an unauthenticated party reliably denying service across the whole device — not a particular parser bug.

## Proof of concept

```sh
nmap -sV -p 80,554,2360,9101,34567 <target>
```

All five ports then stop answering while ICMP continues; service returns without intervention in roughly four minutes.

## Impact

Anyone on the network can blind a security camera for minutes at a time with one commonplace scan, repeatably, with no credentials. For a monitoring device that is a direct availability failure.

It also means routine network inventory scanning will knock these cameras offline.

## Mitigation

None on the device. Network isolation limits who can reach the services; replacing the firmware removes the vendor application entirely. See VATILON-2026-01.

## Credit

Found and reported by [@eseverson](https://github.com/eseverson). Observed on hardware owned by the researcher during other testing.
