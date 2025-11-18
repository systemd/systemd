/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include_next <utmpx.h>

#ifndef UTMPX_FILE
#define UTMPX_FILE "/run/utmp"
#endif

#ifndef WTMPX_FILE
#define WTMPX_FILE "/var/log/wtmp"
#endif

#ifndef ACCOUNTING
#define ACCOUNTING 9
#endif
