# VATILON-2026-04 — Firmware images are accepted on a CRC32 check alone; there is no signature verification

| | |
| --- | --- |
| Identifier | VATILON-2026-04 |
| CVE | requested, not yet assigned |
| CWE | CWE-347 (improper verification of cryptographic signature) |
| CVSS v3.1 | **7.2 high** — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| Status | Independent disclosure — the vendor was not contacted. Rationale in [README.md](README.md#disclosure-statement). Published 2026-09-29. |
| Fix available | No. `V1.18.09` adds payload obfuscation but still verifies no signature. |

## Summary

The firmware upgrade endpoint validates an uploaded image with a magic value, three identity strings, a version comparison and a CRC32. There is no signature, no public key, and no cryptographic verification anywhere in the code path. Anyone who can reach the endpoint with credentials — or who holds root via VATILON-2026-01 or VATILON-2026-03, neither of which needs credentials — can write arbitrary firmware to flash.

## Affected

SIMICAM A314D / **Vatilon H80**, product code `P22H`, firmware `V1.16.39-20250721`, HiSilicon hi3516cv610. Verified statically by reading the validator (`m_firmware_upgrade.c` logic) out of the shipped application binary.

Also **Vatilon H80 / H82**, `P22H`, firmware `V1.18.09` (current). That build adds an obfuscation layer over the image payload but still verifies no signature — see *Obfuscation added in V1.18.09*.

## Description

Images are delivered as a multipart POST of the `firmware` field to `/cgi-bin/upgrade`. The container is the vendor's own format:

```
0x00  "HUFH"          magic
0x04  crc32(file[8:])
0x0c  platform[16]    "hi3516cv610"
0x1c  appfs_ver
0x24  product[16]     "P22H"
0x3c  payload_size
0x40  crc32(payload)
0x44  partition table, 56 bytes per entry:
        name[8], "/dev/mtdblockN"[32], offset, size, version, flags
```

The validator checks, in order: the `HUFH` magic; `platform` against the device's SoC; `product` against its product code; the version against the running one; and the two CRC32s. That is all of it — CRC32 carries no secret, so an attacker recomputes it over their own payload.

The partition table is attacker-controlled, so the image chooses which MTD devices are written and at what offsets — including, if desired, `mtdblock0`, the bootloader. That is not hypothetical: the vendor's own `V1.18.09` image carries a three-entry table whose first entry is `uboot` → `/dev/mtdblock0`, so writing the bootloader is a supported operation of the update path rather than an abuse of it.

## Obfuscation added in V1.18.09

The current firmware release wraps the image payload in a layer that resembles encryption and provides nothing. The payload is XORed with a **static 16-byte key, repeating for the length of the image and identical in every image the vendor ships**.

Recovering it needs no device, no vendor cooperation and no key material. Firmware images contain long runs of constant plaintext, so a frequency count of 16-byte-aligned blocks yields the key directly; two independent known values — the SquashFS magic at the application partition's offset and the FIT header at the kernel's — then confirm the same key bytes. The whole exercise takes minutes.

The two CRC32 fields are computed over the obfuscated payload and remain the only integrity check. So an attacker who wants to ship their own firmware now XORs their payload with the same fixed key before computing the CRC32s. This is one extra line of code and no additional knowledge.

It is worth being precise about what this changes: the obfuscation raises the effort of *building* a modified image from trivial to slightly-less-trivial for someone who has never looked at the format, and it lowers nothing else. It is not a signature, it carries no secret, and it does not authenticate the image's origin. Its presence is not a fix.

The web API's `check auth failed` error reads like image authentication but is the session check on the HTTP request, not verification of the image contents.

## Proof of concept

Not published as a runnable exploit: the format above is enough to reproduce the finding, and a bad image bricks the device permanently.

Verified constructively — a vendor-format container carrying a third-party kernel and root filesystem was built and checked field-for-field against a genuine vendor image, with both CRC32s valid. No image was posted to the upgrade endpoint.

## Impact

Persistent, root-level compromise that survives a factory reset, since the attacker controls the filesystem the reset restores to. The realistic chain does not need the web credentials the CVSS vector assumes: VATILON-2026-01 gives unauthenticated root, and root writes the MTD partitions directly. The `PR:H` scores this defect in isolation, as the update mechanism it is.

The same property is what lets an owner install third-party firmware — but nothing distinguishes the owner from anyone else on the network.

## Mitigation

None on the device. Network isolation or replacing the firmware; see VATILON-2026-01.

## Credit

Found and reported by [@eseverson](https://github.com/eseverson). All analysis was performed against a firmware image dumped from hardware owned by the researcher.
