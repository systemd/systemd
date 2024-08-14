/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

int reboot_now(void);

typedef enum SysupdateFlags {
        SYSUPDATE_OFFLINE = 1 <<  0,
} SysupdateFlags;
