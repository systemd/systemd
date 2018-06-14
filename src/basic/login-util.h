/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <stdbool.h>
#include <unistd.h>

bool session_id_valid(const char *id);

static inline bool logind_running(void) {
        return access("/run/systemd/seats/", F_OK) >= 0;
}
