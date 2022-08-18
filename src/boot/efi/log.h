/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi-string.h"

void log_wait(void);
_gnu_printf_(2, 3) EFI_STATUS log_internal(EFI_STATUS status, const char *format, ...);
#define log_error_status(status, ...) log_internal(status, __VA_ARGS__)
#define log_error(...) log_internal(EFI_INVALID_PARAMETER, __VA_ARGS__)
#define log_oom() log_internal(EFI_OUT_OF_RESOURCES, "Out of memory.")
#define log_trace() log_internal(EFI_SUCCESS, "%s:%i@%s", __FILE__, __LINE__, __func__)
