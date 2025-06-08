/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <utmpx.h>

/* for musl */
#ifndef ACCOUNTING
#define ACCOUNTING 9
#endif
#ifndef UTMPX_FILE
#define UTMPX_FILE _PATH_UTMP
#endif
#ifndef WTMPX_FILE
#define WTMPX_FILE _PATH_WTMP
#endif
