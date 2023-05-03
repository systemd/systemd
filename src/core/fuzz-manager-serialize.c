/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "manager-serialize.h"
#include "manager.h"
#include "service.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(manager_freep) Manager *m = NULL;
        _cleanup_fclose_ FILE *f = NULL, *null = NULL;
        _cleanup_fdset_free_ FDSet *fdset = NULL;

        /* We don't want to fill the logs with messages about parse errors.
         * Disable most logging if not running standalone. */
        if (!getenv("SYSTEMD_LOG_LEVEL")) {
                log_set_max_level(LOG_CRIT);
                log_set_target(LOG_TARGET_NULL);
        }

        assert_se(manager_new(RUNTIME_SCOPE_SYSTEM, MANAGER_TEST_RUN_BASIC, &m) >= 0);
        /* Set log overrides as well to make it harder for a serialization file
         * to switch log levels/targets during fuzzing */
        manager_override_log_level(m, log_get_max_level());
        manager_override_log_target(m, log_get_target());
        assert_se(null = fopen("/dev/null", "we"));
        assert_se(fdset = fdset_new());
        assert_se(f = data_to_file(data, size));

        (void) manager_deserialize(m, f, fdset);
        (void) manager_serialize(m, null, fdset, true);
        (void) manager_serialize(m, null, fdset, false);

        return 0;
}
