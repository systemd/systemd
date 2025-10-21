/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <sys/random.h>    /* IWYU pragma: export */

#include <assert.h>

/* Defined since glibc-2.32. */
#ifndef GRND_INSECURE
#  define GRND_INSECURE 0x0004
#else
static_assert(GRND_INSECURE == 0x0004, "");
#endif
