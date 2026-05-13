---
title: Project IDs for Disk Quotas on Exec Directories
category: Exec directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Project IDs on systemd Systems

Project IDs are needed to enforce disk quotas for Exec Directories.
Project IDs are unsigned, 32-bit integers. For disk quota enforcement,
the range used is 2147483648 - 4294967294, which is the highest range
inspired from `UIDS-GUID.md`. The range is defined through `PROJ_ID_MIN`
and `PROJ_ID_MAX` in `exec-invoke.c`.
