/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald.h"
#include "journald-kmsg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        Server s;

        if (size == 0)
                return 0;

        /* We don't want to fill the logs with assert warnings.
         * Disable most logging if not running standalone */
        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        dummy_server_init(&s, data, size);
        dev_kmsg_record(&s, s.buffer, size);
        server_done(&s);

        return 0;
}
