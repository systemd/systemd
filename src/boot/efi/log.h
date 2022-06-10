/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi-string.h"

_printf_(2, 3) EFI_STATUS log_internal(EFI_STATUS status, const char *format, ...);
#define log_error_status(status, ...) log_internal(status, __VA_ARGS__)
#define log_error(...) log_internal(EFI_INVALID_PARAMETER, __VA_ARGS__)
#define log_oom() log_internal(EFI_OUT_OF_RESOURCES, "Out of memory.")
