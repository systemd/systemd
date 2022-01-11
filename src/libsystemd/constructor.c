/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "log.h"
#include "macro.h"
#include "mempool.h"

/* Disable mempool. */
const bool mempool_use_allowed = false;

/* Parse log related environment variables. */
_constructor_ static void constructor_log_setup(void) {
        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_set_open_when_needed(true);
}
