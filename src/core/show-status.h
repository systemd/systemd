/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "core-forward.h"

/* Manager status */

typedef enum ShowStatus {
        SHOW_STATUS_NO,         /* printing of status is disabled */
        SHOW_STATUS_ERROR,      /* only print errors */
        SHOW_STATUS_AUTO,       /* disabled but may flip to _TEMPORARY */
        SHOW_STATUS_TEMPORARY,  /* enabled temporarily, may flip back to _AUTO */
        SHOW_STATUS_YES,        /* printing of status is enabled */
        _SHOW_STATUS_MAX,
        _SHOW_STATUS_INVALID = -EINVAL,
} ShowStatus;

typedef enum ShowStatusFlags {
        SHOW_STATUS_ELLIPSIZE = 1 << 0,
        SHOW_STATUS_EPHEMERAL = 1 << 1,
} ShowStatusFlags;

typedef enum StatusUnitFormat {
        STATUS_UNIT_FORMAT_NAME,
        STATUS_UNIT_FORMAT_DESCRIPTION,
        STATUS_UNIT_FORMAT_COMBINED,
        _STATUS_UNIT_FORMAT_MAX,
        _STATUS_UNIT_FORMAT_INVALID = -EINVAL,
} StatusUnitFormat;

static inline bool show_status_on(ShowStatus s) {
        return IN_SET(s, SHOW_STATUS_TEMPORARY, SHOW_STATUS_YES);
}
DECLARE_STRING_TABLE_LOOKUP(show_status, ShowStatus);
int parse_show_status(const char *s, ShowStatus *ret);

DECLARE_STRING_TABLE_LOOKUP(status_unit_format, StatusUnitFormat);

int status_vprintf(const char *status, ShowStatusFlags flags, const char *format, va_list ap) _printf_(3,0);
int status_printf(const char *status, ShowStatusFlags flags, const char *format, ...) _printf_(3,4);
