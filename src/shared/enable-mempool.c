/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>

#include "env-util.h"
#include "mempool.h"
#include "process-util.h"

bool mempool_enabled(void) {
        static int cache = -1;

        if (!is_main_thread())
                return false;

        if (cache < 0)
                cache = getenv_bool("SYSTEMD_MEMPOOL") != 0;

        return cache;
}
