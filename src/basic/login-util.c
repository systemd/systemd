/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "login-util.h"
#include "string-util.h"

bool session_id_valid(const char *id) {

        if (isempty(id))
                return false;

        return id[strspn(id, LETTERS DIGITS)] == '\0';
}

bool logind_running(void) {
        return access("/run/systemd/seats/", F_OK) >= 0;
}
