/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "logind-forward.h"
#include "logind-session.h"

#define LOGIN_COUNTERS_PATH "/run/systemd/login-counters"
#define LOGIN_COUNTERS_VERSION UINT64_C(1)

/* This structure is kept in LOGIN_COUNTERS_PATH and is mapped by logind for its whole runtime. It contains
 * monotonic counters, which hence survive logind restarts, but not reboots. Native endian, not a stable
 * interface. */
typedef struct LoginCounters {
        uint64_t version;
        uint64_t n_sessions_started[_SESSION_CLASS_MAX];   /* indexed by SessionClass */
} LoginCounters;

int manager_map_counters(Manager *m);

void session_count_started(Session *s);
