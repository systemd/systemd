/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/stat.h>

/* musl's sys/stat.h does not include linux/stat.h, and unfortunately they conflict with each other.
 * Hence, some relatively new macros need to be explicitly defined here. */

#ifndef STATX_DIO_READ_ALIGN
#define STATX_DIO_READ_ALIGN    0x00020000U
#endif
