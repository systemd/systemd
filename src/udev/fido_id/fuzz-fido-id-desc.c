/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/hid.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "fido_id_desc.h"
#include "fuzz.h"
#include "log.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        /* We don't want to fill the logs with messages about parse errors.
         * Disable most logging if not running standalone */
        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        if (outside_size_range(size, 0, HID_MAX_DESCRIPTOR_SIZE))
                return 0;

        (void) is_fido_security_token_desc(data, size);

        return 0;
}
