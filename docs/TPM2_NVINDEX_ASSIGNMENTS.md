---
title: TPM2 NV Index Assignment by systemd
category: Booting
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# NV Index Assignments

The Trusted Computing Group (TCG) maintains a [Registry of Reserved TPM 2.0
Handles and Localities](https://trustedcomputinggroup.org/resource/registry/)
which assigns NV Index ranges (among ther things, see section 2.2) to
organizations (by convention only!). It has assigned the NV index range
0x01XXXXXX-0x01XXXXXX to the systemd project. This NV range is used by systemd
for the following purposes:

## As Storage for a Disk Encryption PolicyAuthorizeNV policy

*Scope*: Dynamic allocation at OS installation time, one for each installed
Linux/systemd based OS that uses `systemd-pcrlock` based disk encryption policies.

*Range*: 0x01XXXXXX-0x01XXXXXX

*Size*: Stores one policy hash. Under the assumption SHA256 policy hashes are used, this means 32 byte.

## As Storage for Additional PCRs Implemented in NV Indexes

*Scope*: Static allocation by the systemd project, one for each additional NV
Indexed based PCR (systemd calls these "NvPCRs"). These can be shared between
multiple Linux/systemd based OSes installed on the same system.

*Range*: 0x01XXXXXX-0x01XXXXXX

*Size*: Stores one PCR hash each (`TPMA_NT_EXTEND`). We'd expect that typically
SHA256 PCR hashes are used, hence this means 32byte.

*Detailed Assignments*:

|    NVIndex | Purpose                                             |
+------------+-----------------------------------------------------+
| 0x01XXXXXX | Used LUKS unlock mechanism (TPM2, PKCS11, FIDO2, …) |
| 0x01XXXXXX | Product UUID                                        |
| 0x01XXXXXX | System Extension Images applied to the host         |
| 0x01XXXXXX | Configuration Extension Images applied to the host  |

## Currently Unused Range

The following range is currently not used by the systemd project, but might be
allocated later.

# Relationship with TCG

This document is referenced by the aforementioned registry for details about
assignments of the NV Index range delegated to the systemd project. Hence,
particular care should be taken that this page is not moved, and its URL remains stable.
