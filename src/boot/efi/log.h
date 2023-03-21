/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi-string.h"

#if defined __has_attribute
#  if __has_attribute(no_stack_protector)
#    define HAVE_NO_STACK_PROTECTOR_ATTRIBUTE
#  endif
#endif

#if defined(HAVE_NO_STACK_PROTECTOR_ATTRIBUTE) && \
    (defined(__SSP__) || defined(__SSP_ALL__) || \
    defined(__SSP_STRONG__) || defined(__SSP_EXPLICIT__))
#  define STACK_PROTECTOR_RANDOM 1
__attribute__((no_stack_protector, noinline)) void __stack_chk_guard_init(void);
#else
#  define STACK_PROTECTOR_RANDOM 0
#  define __stack_chk_guard_init()
#endif

_noreturn_ void freeze(void);
void log_wait(void);
_gnu_printf_(2, 3) EFI_STATUS log_internal(EFI_STATUS status, const char *format, ...);
#define log_error_status(status, ...) log_internal(status, __VA_ARGS__)
#define log_error(...) log_internal(EFI_INVALID_PARAMETER, __VA_ARGS__)
#define log_oom() log_internal(EFI_OUT_OF_RESOURCES, "Out of memory.")
#define log_trace() log_internal(EFI_SUCCESS, "%s:%i@%s", __FILE__, __LINE__, __func__)
