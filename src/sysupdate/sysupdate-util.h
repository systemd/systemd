/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

int reboot_now(void);

#define SD_SYSUPDATE_OFFLINE  (UINT64_C(1) << 0)
#define SD_SYSUPDATE_FLAGS_ALL (SD_SYSUPDATE_OFFLINE)
