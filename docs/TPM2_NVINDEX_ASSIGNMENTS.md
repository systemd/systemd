---
title: TPM NV Index Assignments by systemd
category: Booting
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# TPM NV Index Assignments by systemd

The Trusted Computing Group (TCG) maintains a [Registry of Reserved TPM 2.0
Handles and Localities](https://trustedcomputinggroup.org/resource/registry/)
which assigns TPM 2.0 NV index ranges (among other things, see section 2.2) to
organizations (by convention only!). It has assigned the NV index range
**0x01D10200-0x01D105FF** to the Linux community. Subranges of this range are
delegated to individual projects by the [UAPI.19 Linux TPM NV Index
Registry](https://uapi-group.org/specifications/specs/linux_tpm_nvindex_registry/),
which delegated the NV index range **0x01D10200-0x01D10224** (i.e. 37 NV
indexes) to the systemd project. systemd uses this range as follows:

|              NV Index | Number | Use                                                                                   |
|-----------------------|--------|---------------------------------------------------------------------------------------|
|            0x01D10200 | 1      | NvPCR `hardware`: SMBIOS product UUID of the system                                   |
|            0x01D10201 | 1      | NvPCR `cryptsetup`: LUKS volume unlock mechanism used (TPM2, PKCS#11, FIDO2, …)       |
|            0x01D10202 | 1      | NvPCR `verity`: Signed Verity images activated (e.g. system/configuration extensions) |
|            0x01D10203 | 1      | NvPCR `login`: User records of users logging in                                       |
| 0x01D10204-0x01D1020C | 9      | Currently unused                                                                      |
| 0x01D1020D-0x01D10224 | 24     | `systemd-pcrlock` `PolicyAuthorizeNV` policy hashes                                   |

Each of the NvPCR indexes stores a single SHA256 hash, and is hence
expected to be 32 bytes in size. The `systemd-pcrlock` policy hashes
are stored as `TPMT_HA` structures, i.e. the hash is prefixed by the
16-bit hash algorithm identifier, hence these NV indexes are 34 bytes
in size.

NvPCRs are additional PCRs implemented in NV indexes of type `TPM2_NT_EXTEND`,
see [TPM2 PCR Measurements](/TPM2_PCR_MEASUREMENTS) for details. They are
statically assigned and shared between all Linux/systemd based OSes installed
on the same system. Their base NV index may be changed at build time via the
`-Dtpm2-nvpcr-base=` meson option, the table above lists the default
assignments.

The `systemd-pcrlock` policy hashes are allocated dynamically at OS
installation time, one for each installed OS that uses `systemd-pcrlock`-based
disk encryption policies. An NV index is picked randomly from the subrange
(retrying on collision), hence at most 24 such OSes can be installed on the same
system.

The unused range might be allocated later, for any purpose. Note that the NV
index immediately following the range delegated to systemd is assigned to a
different purpose by UAPI.19. Should systemd require additional NV indexes in
the future, a separate subrange has to be requested from UAPI.19.

## Relationship with UAPI.19

This document is referenced by the [UAPI.19 Linux TPM NV Index
Registry](https://uapi-group.org/specifications/specs/linux_tpm_nvindex_registry/)
for details about assignments of the NV index range delegated to the systemd
project. Hence, particular care should be taken that this page is not moved, and
its URL remains stable as
[`https://systemd.io/TPM2_NVINDEX_ASSIGNMENTS`](https://systemd.io/TPM2_NVINDEX_ASSIGNMENTS).
