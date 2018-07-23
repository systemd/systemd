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

ShowStatus show_status_from_string(const char *v) _const_;
const char* show_status_to_string(ShowStatus s) _pure_;
int parse_show_status(const char *v, ShowStatus *ret);

int status_vprintf(const char *status, bool ellipse, bool ephemeral, const char *format, va_list ap) _printf_(4,0);
int status_printf(const char *status, bool ellipse, bool ephemeral, const char *format, ...) _printf_(4,5);
