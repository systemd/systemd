/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/random.h> /* IWYU pragma: export */

#include "forward.h"

/* Defined since glibc-2.32. */
#ifndef GRND_INSECURE
#  define GRND_INSECURE 0x0004
#else
assert_cc(GRND_INSECURE == 0x0004);
#endif
