# Vatilon / `hi3516cv610` IP camera firmware — advisory set

Five defects in the IP camera firmware published under the **Vatilon** brand and resold under several others. The most serious is an undocumented service that gives anyone on the network root on the camera with a single UDP packet, and it is present unchanged in the vendor's current firmware release.

**Status: unpublished. CVE assignment is being requested; the advisories themselves are held.** No vendor embargo holds them back — see the disclosure statement below — but publication is a separately gated step and the CVE identifiers are not assigned yet. Publication venue is a public GitHub repository, to be created. See `disclosure-plan` on Paperclip task MEO-3.

## Who the vendor is

`vatilon.com` and `vatilon.cn` are both operated by **深圳市华天龙电子有限公司 — Shenzhen Huatianlong Electronics Co., Ltd.**, which is the company name in the title of every page on both sites, including their IPC firmware download pages (`vatilon.com/xflrjxz`, `vatilon.cn/ipcrjxz`). The build paths compiled into the firmware binaries carry an `htl` directory component, which matches. Existing NVD entries for this firmware family (CVE-2025-63667, CVE-2025-67159, CVE-2025-67160) are filed under "Shenzhen Vatilon Electronics", so the advisories keep that name for searchability and note the Huatianlong identity here.

What this establishes is that Huatianlong operates the Vatilon brand and publishes its firmware. It is **not** a claim about who wrote `system_wapper` — this is a white-label product with an unknown number of hands in its supply chain, and the ODM that authored the application stack has not been identified.

## The set

| Advisory | Subject | CVSS v3.1 | Fixed in current firmware? |
| --- | --- | --- | --- |
| [VATILON-2026-01](VATILON-2026-01-system-wapper-udp-rce.md) | `system_wapper` — unauthenticated root command execution on UDP 6789 | **9.8** | No — byte-identical binary |
| [VATILON-2026-02](VATILON-2026-02-no-authentication-on-network-services.md) | No authentication enforced on RTSP, ONVIF, DVRIP or the snapshot CGI; `rtsp_auth_enable` is inert | **9.1** | No — static signature unchanged |
| [VATILON-2026-03](VATILON-2026-03-static-root-password-telnetd.md) | telnetd always on, static root password compiled into the image | **9.8** (≤ V1.16.39) | Partially — credential storage hardened, service and static password remain |
| [VATILON-2026-04](VATILON-2026-04-unsigned-firmware-update.md) | Firmware accepted on CRC32 alone; no signature verification | **7.2** | No — obfuscation added, still no signature |
| [VATILON-2026-05](VATILON-2026-05-probe-denial-of-service.md) | A single service-version scan takes the camera off the air for minutes | **7.5** | Untested on current firmware |

## If you own one of these cameras

Read [VATILON-2026-01](VATILON-2026-01-system-wapper-udp-rce.md) first, and its *Mitigation* section before anything else. The short version:

1. **The firmware version in the web interface tells you whether a camera is affected.** The worst defect is present on every affected build regardless of settings, so a version match settles it, and the version string reports everything a network probe would. A service-version scan (`nmap -sV`) adds a cost the version check does not carry: that probe crashes the firmware and takes the device offline for minutes (VATILON-2026-05).
2. **Segment it or unplug it.** Put the camera where it can reach its recorder and nothing else, with no route to the internet. There is no configuration change on the camera that closes any of this.
3. **Changing the camera password does not help.** The worst defect needs no credential, and the administrator password is readable without one.
4. **Updating the firmware does not help** for the worst defect. It is present and identical in the current release. It does help for VATILON-2026-03 if you are on `V1.16.39` or earlier, whose root password is published here.
5. **Replacing the firmware is the only real fix.** OpenIPC supports this SoC and removes the vendor application stack entirely. Note that the published OpenIPC cv6xx image targets 16 MiB flash and will not fit the 8 MiB parts these cameras use.

## Disclosure statement

These findings are published as **independent disclosure**. The vendor was not contacted before publication, and there is no embargo. That is a deliberate decision, and the reasoning belongs on the record rather than left implied:

- **There is no vendor to coordinate with.** This is a white-label camera sold through AliExpress under whichever brand a reseller prints on the box. There is no support relationship and no published security contact anywhere on the vendor's sites or its listings.
- **No fix reaches the installed devices.** The cameras do not update themselves. The only route by which a corrected image could arrive is an owner finding a Chinese-language download page on the vendor's website, identifying the right product code, and flashing by hand — which essentially no owner of a $30 driveway camera will do. The current build on that page, `V1.18.09`, still contains the worst of these defects byte-identical to the build from twelve months earlier, so the route that does exist has not delivered a fix and there is no sign one is coming.
- **The defects are not oversights a report would help someone find.** A root shell bound to a UDP port with no authentication, a telnet daemon with no off switch, and firmware accepted on a CRC32 alone are negligent by construction. Nobody needs to be told these are there; they were built that way.

Withholding the findings would delay owners learning what is sitting on their network, and would buy no prospect of a fix in return. Owners can act today — segment the camera or replace the firmware — and that is the only remediation that exists.

**What this does not assert.** It is not a claim that nobody is building firmware. A build for this product code dated May 2026 exists, it is published on the vendor's own download page, and it still contains the worst of these defects unchanged (see `verification` on Paperclip task MEO-3). It is a judgment that a report would not produce a fix that reaches these cameras.

## Scope and method

All live testing was performed against a single camera owned by the researcher, on the researcher's own network. No device belonging to anyone else was touched, and no third-party infrastructure was tested.

Two further platforms were assessed **statically**, with no device involved: a publicly published firmware dump for the Fullhan `FH8852V201` build, and the vendor's own `V1.18.09` update image for our own product code. Where a finding rests on static analysis rather than execution, the advisory says so in its affected table. The brand names in those tables that came from other researchers' CVE affected-lists rather than from testing here are marked as leads, not confirmations.

**Provenance of the `V1.18.09` image.** `P22H_H82_H80_V1.18.09.zip` was downloaded from the vendor's own website, `https://vatilon.com/`. It parses as a genuine `HUFH` container for product code `P22H` and both of its internal CRC32s validate. Nothing in this set rests on an image from an unattributable source.

The camera used for this research now runs OpenIPC, so findings cannot be re-tested live. Every claim is either recorded as a live test in the working notes or re-derivable from the retained 8 MiB flash image, whose checksums are in `../stock-firmware/MD5SUMS`.

## Reproduction material

[`poc/vatilon_udp6789_rce.py`](poc/vatilon_udp6789_rce.py) is working exploit code for VATILON-2026-01, and it is **published with this set**.

The case against publishing it was that these cameras cannot be patched, so a ready-made attack tool helps an attacker more than the defender it is nominally for. The case that carried is that it is barely a tool: the `system_wapper` protocol is four lines of Python, anyone who reads the advisory reconstructs it in a minute, and withholding it buys an owner nothing while making the finding harder to verify and easier to dismiss.

Each advisory also carries a short check a defender can run against their own device. Run any of it only against hardware you own.

## License

This advisory set — the README, the five advisories, and the reproduction material — is licensed under the [Creative Commons Attribution 4.0 International License (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). See [`LICENSE`](LICENSE) for the full terms. You may share and adapt the material for any purpose, including commercially, provided you give appropriate credit to `@eseverson`.
