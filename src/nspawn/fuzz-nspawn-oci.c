/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fd-util.h"
#include "fuzz.h"
#include "nspawn-oci.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(settings_freep) Settings *s = NULL;

        if (outside_size_range(size, 0, 65536))
                return 0;

        f = data_to_file(data, size);
        assert_se(f);

        /* We don't want to fill the logs with messages about parse errors.
         * Disable most logging if not running standalone */
        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        (void) oci_load(f, "/dev/null", &s);

        return 0;
}
