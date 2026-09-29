# VATILON-2026-02 — No authentication is enforced on any network service; `rtsp_auth_enable` has no effect

| | |
| --- | --- |
| Identifier | VATILON-2026-02 |
| CVE | requested, not yet assigned |
| CWE | CWE-306 (missing authentication for critical function), CWE-287 (improper authentication), CWE-1188 (insecure default initialization) |
| CVSS v3.1 | **9.1 critical** — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| Status | Independent disclosure — the vendor was not contacted. Rationale in [README.md](README.md#disclosure-statement). Published `<date>`. |
| Fix available | No. The RTSP defect's static signature is unchanged in the vendor's current release, `V1.18.09`. |

## Summary

This firmware does not enforce authentication on any of its media, management or discovery services. RTSP streams to any client; ONVIF answers unauthenticated requests for the account list and applies unauthenticated configuration writes; the DVRIP service issues a session to any credentials and discloses the administrator password; and a CGI endpoint returns a current JPEG frame to anyone who asks. The device's own `rtsp_auth_enable` and ONVIF `auth_enable` settings report as enabled and are never consulted.

Filed as one issue: one product behavior with one remediation, not one code path — see *Scope* below.

## Affected

| Brand / model | Product code | Firmware | SoC | Verification |
| --- | --- | --- | --- | --- |
| SIMICAM A314D / **Vatilon H80** | `P22H` | `V1.16.39-20250721` | HiSilicon hi3516cv610 | **Confirmed live** on owned hardware, plus static confirmation in the application binary |
| Vatilon **H80 / H82** | `P22H` | `V1.18.09` (current) | HiSilicon hi3516cv610 | RTSP defect's static signature **unchanged** — `rtsp_auth_enable` still appears exactly twice, `rtspAuth` / `rtspSendUnAuth` still present. ONVIF, DVRIP and the snapshot CGI were **not** re-tested on this build |
| KEVIEW H43 | `P05H` | `V1.14.92-20241120` | Fullhan FH8852V201 | RTSP defect **confirmed statically** in a public firmware dump; other services untested |

Brands observed shipping this firmware family: SIMICAM, VATILON, KEVIEW, ASECAM, JIENUO.

## Description

### RTSP (554/tcp) — streams to anyone, and the setting is decorative

`DESCRIBE` with no credentials returns the full SDP and the stream plays. A deliberately **wrong** password works as well as none: the server parses the credential and discards it rather than failing open on a missing header.

The setting is genuinely enabled across three independent surfaces, all ignored:

1. The web API reports `mod=rtsp` → `{"enable":1,"port":554,"auth_enable":1}`, and `rtsp_setting.js` shows the module accepts no other key.
2. The device's own exported configuration (`mod=system&cmd=export_config`, an `HCTH`-headered gzip tar) contains `ipcam.conf` with `rtsp_auth_enable=1` genuinely set on flash, not merely echoed by an API.
3. A hidden DVRIP configuration tree, `NetWork.RTSP`, exposes `Server.UserName`, `Server.Password` and `Anonymity` fields the web UI never shows. Writes return success and do not persist.

Statically, `rtspAuth` in the application binary returns its success value regardless of what its credential lookup yields, and the configuration flag is never read at request time. The same `rtsp_auth_enable` / `rtspAuth` / `rtspSendUnAuth` signature is present in the Fullhan build's `ipcam`.

### ONVIF (80/tcp) — unauthenticated reads *and* writes, and no token validation

| Request | Required by the ONVIF specification | Actual |
| --- | --- | --- |
| `GetUsers`, no credentials | `Sender/NotAuthorized` (Administrator level) | Returns the account list |
| `GetUsers`, deliberately wrong WS-Security password digest | `NotAuthorized` | Returns the same data |
| `GetNetworkInterfaces`, no credentials | `NotAuthorized` | Returns device and network configuration |
| `SetVideoEncoderConfiguration`, no credentials | `NotAuthorized` | **Succeeds and reconfigures the camera** |

`SetVideoEncoderConfiguration` with no credentials and a nonexistent configuration token returned success and applied the payload to the main encoder anyway, changing it from HEVC 3840x2160 to H.264 1280x720. The device was restored afterwards.

That is two defects: no authentication, and no validation of the configuration token on writes (CWE-20). The second survives any authentication fix.

### DVRIP / XMeye (34567/tcp) — a session for any credentials, and the admin password

Login with a wrong password, an empty password, or a username that does not exist all return `Ret: 100` and a usable session:

```
wrong pw    -> {'Ret': 100, 'SessionID': '0x00000002'}
empty pw    -> {'Ret': 100, 'SessionID': '0x00000003'}
bogus user  -> {'Ret': 100, 'SessionID': '0x00000004'}
```

With that session, message id 1472 returns the account table including the credential:

```json
{"Users": [{"Group":"admin","Name":"admin","Password":"nTBCS19C","AuthorityList":["ShutDown","SysUpgrade","Account","NetConfig","..."]}]}
```

`nTBCS19C` is the Xiongmai password hash — an 8-character lossy digest from the embedded XM SDK, public since 2017 and trivially reversed; here it is the hash of `123456`. Network configuration (`NetWork.NetCommon`: MAC, IP, gateway, port list, plus an `SSLPort 8443` and `UDPPort 34568` no interface mentions), NTP, DHCP and encoder settings read the same way.

Configuration *writes* over DVRIP do not land — `ConfigSet` (msgid 1040) returns `Ret: 100` but is a no-op. This service is unauthenticated disclosure, not unauthenticated write.

### `/cgi-bin/snapshot.cgi` (80/tcp) — a JPEG for anyone

Returns a full-resolution current frame with no credentials, while `/cgi-bin/web.cgi` on the same server correctly returns `401` with `WWW-Authenticate: Digest realm="CAMERA"`.

### The chain

The web UI is the one service that authenticates properly, and it does not help: the administrator password is readable unauthenticated from port 34567, so an attacker logs in legitimately and re-enables whatever an owner turned off. **Rotating the camera password does not mitigate any of this** — the new one is readable immediately.

## Proof of concept

Each service can be checked independently with ordinary tools. No custom script is required, and none is published here:

```sh
# RTSP: returns the full SDP with no credentials
curl -s -X DESCRIBE rtsp://<target>:554/stream1

# Snapshot: returns a JPEG with no credentials
curl -s -o frame.jpg http://<target>/cgi-bin/snapshot.cgi

# ONVIF: an unauthenticated GetUsers returns the account list rather than a
# Sender/NotAuthorized fault. Any ONVIF client will show this.
```

## Impact

Anyone with network access can watch both video streams, retrieve stills over plain HTTP, read the network configuration, recover the administrator password, and rewrite the camera's configuration — a complete loss of confidentiality and integrity on a physical-security device, not remediable by configuration.

## Scope — why four services, one entry

Four separately observable defects with one fix: the remediation is identical for all four. Scored alone, the RTSP and snapshot findings come out around 7.5 and understate the set, whose real reachable impact is an unauthenticated configuration write.

They are **not** four call sites of one function — the RTSP, ONVIF, DVRIP and CGI paths live in separate source subtrees (`onvif_server`, `xiongmai`, `weber`) and each makes its own decision. The consolidation is a counting judgment, not a claim of a single root cause.

## Mitigation

No fix is available and none is expected; the vendor's OTA bucket no longer resolves. Turning ONVIF off in the web UI does remove the unauthenticated configuration-write surface — `/onvif/device_service` stops answering — but an attacker can turn it back on with the administrator password they read off port 34567, and it does nothing for RTSP, DVRIP or the snapshot CGI.

The two effective measures are network isolation and replacing the firmware. See VATILON-2026-01 for detail.

## Credit

Found and reported by [@eseverson](https://github.com/eseverson). All live testing was performed against hardware owned by the researcher.

## References

- Previously published defects in this firmware family, on the `web.cgi` surface and distinct from the services above: CVE-2025-63667, CVE-2025-67159, CVE-2025-67160
