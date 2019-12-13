/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "macro.h"

/* Manager status */

typedef enum ShowStatus {
        SHOW_STATUS_NO,
        SHOW_STATUS_AUTO,
        SHOW_STATUS_TEMPORARY,
        SHOW_STATUS_YES,
        _SHOW_STATUS_MAX,
        _SHOW_STATUS_INVALID = -1,
} ShowStatus;

typedef enum ShowStatusFlags {
        SHOW_STATUS_ELLIPSIZE = 1 << 0,
        SHOW_STATUS_EPHEMERAL = 1 << 1,
} ShowStatusFlags;

typedef enum StatusUnitFormat {
        STATUS_UNIT_FORMAT_NAME,
        STATUS_UNIT_FORMAT_DESCRIPTION,
        _STATUS_UNIT_FORMAT_MAX,
        _STATUS_UNIT_FORMAT_INVALID = -1,
} StatusUnitFormat;

ShowStatus show_status_from_string(const char *v) _const_;
const char* show_status_to_string(ShowStatus s) _pure_;
int parse_show_status(const char *v, ShowStatus *ret);

StatusUnitFormat status_unit_format_from_string(const char *v) _const_;
const char* status_unit_format_to_string(StatusUnitFormat s) _pure_;

int status_vprintf(const char *status, ShowStatusFlags flags, const char *format, va_list ap) _printf_(3,0);
int status_printf(const char *status, ShowStatusFlags flags, const char *format, ...) _printf_(3,4);
