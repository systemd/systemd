/* SPDX-License-Identifier: LGPL-2.1+ */

#include "alloc-util.h"
#include "fd-util.h"
#include "network-util.h"
#include "strv.h"

bool network_is_online(void) {
        _cleanup_free_ char *state = NULL;
        int r;

        r = sd_network_get_operational_state(&state);
        if (r < 0) /* if we don't know anything, we consider the system online */
                return true;

        if (STR_IN_SET(state, "routable", "degraded"))
                return true;

        return false;
}
