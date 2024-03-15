/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <sys/timerfd.h>

#include "macro.h"

#ifndef TFD_TIMER_CANCEL_ON_SET
#  define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#else
assert_cc(TFD_TIMER_CANCEL_ON_SET == (1 << 1));
#endif
