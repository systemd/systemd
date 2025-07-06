/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <ftw.h>

/* musl does not define the macro. */
#ifndef FTW_CONTINUE
#define FTW_CONTINUE 0
#endif
