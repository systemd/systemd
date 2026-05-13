/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* exit codes as defined in fsck(8) */
enum {
        FSCK_SUCCESS                 = 0,
        FSCK_ERROR_CORRECTED         = 1 << 0,
        FSCK_SYSTEM_SHOULD_REBOOT    = 1 << 1,
        FSCK_ERRORS_LEFT_UNCORRECTED = 1 << 2,
        FSCK_OPERATIONAL_ERROR       = 1 << 3,
        FSCK_USAGE_OR_SYNTAX_ERROR   = 1 << 4,
        FSCK_USER_CANCELLED          = 1 << 5,
        FSCK_SHARED_LIB_ERROR        = 1 << 7,
};
