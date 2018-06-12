/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>

#include "macro.h"

/* Manager status */

typedef enum ShowStatus {
        _SHOW_STATUS_UNSET = -2,
        SHOW_STATUS_AUTO = -1,
        SHOW_STATUS_NO = 0,
        SHOW_STATUS_YES = 1,
        SHOW_STATUS_TEMPORARY = 2,
} ShowStatus;

int parse_show_status(const char *v, ShowStatus *ret);

int status_vprintf(const char *status, bool ellipse, bool ephemeral, const char *format, va_list ap) _printf_(4,0);
int status_printf(const char *status, bool ellipse, bool ephemeral, const char *format, ...) _printf_(4,5);
