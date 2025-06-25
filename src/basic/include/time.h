/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <time.h>

/* glibc defines clock_adjtime() in time.h, but musl defines it in sys/timex.h.
 * glibc's time.h includes bits/time.h -> bits/timex.h, which defines struct timex,
 * but musl's time.h does not provide struct timex, and it is provided by sys/timex.h.
 * Hence, let's include sys/timex.h to make them defined even when building with musl. */
#include <sys/timex.h>
