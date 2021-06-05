/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-dump.h"
#include "bus-message.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ char *out = NULL; /* out should be freed after g */
        size_t out_size;
        _cleanup_fclose_ FILE *g = NULL;
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ void *buffer = NULL;
        int r;

        /* We don't want to fill the logs with messages about parse errors.
         * Disable most logging if not running standalone */
        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        r = sd_bus_new(&bus);
        assert_se(r >= 0);

        assert_se(buffer = memdup(data, size));

        r = bus_message_from_malloc(bus, buffer, size, NULL, 0, NULL, &m);
        if (r == -EBADMSG)
                return 0;
        assert_se(r >= 0);
        TAKE_PTR(buffer);

        if (getenv_bool("SYSTEMD_FUZZ_OUTPUT") <= 0)
                assert_se(g = open_memstream_unlocked(&out, &out_size));

        sd_bus_message_dump(m, g ?: stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        r = sd_bus_message_rewind(m, true);
        assert_se(r >= 0);

        return 0;
}
