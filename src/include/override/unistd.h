/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <unistd.h>        /* IWYU pragma: export */

/* Defined since glibc-2.34.
 * Supported since kernel v5.9 (60997c3d45d9be4b19fbe0f2fa67f2e384429aad). */
int close_range_shim(unsigned first_fd, unsigned end_fd, unsigned flags);
#define close_range close_range_shim

int pivot_root_shim(const char *new_root, const char *put_old);
#define pivot_root pivot_root_shim
