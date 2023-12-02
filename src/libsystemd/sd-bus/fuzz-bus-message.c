/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-dump.h"
#include "bus-message.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fuzz.h"
#include "memstream-util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(memstream_done) MemStream ms = {};
        _cleanup_(sd_bus_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_free_ void *buffer = NULL;
        FILE *g = NULL;
        int r;

        fuzz_setup_logging();

        r = sd_bus_new(&bus);
        assert_se(r >= 0);

        assert_se(buffer = memdup(data, size));

        r = bus_message_from_malloc(bus, buffer, size, NULL, 0, NULL, &m);
        if (r == -EBADMSG)
                return 0;
        assert_se(r >= 0);
        TAKE_PTR(buffer);

        if (getenv_bool("SYSTEMD_FUZZ_OUTPUT") <= 0)
                assert_se(g = memstream_init(&ms));

        sd_bus_message_dump(m, g ?: stdout, SD_BUS_MESSAGE_DUMP_WITH_HEADER);

        r = sd_bus_message_rewind(m, true);
        assert_se(r >= 0);

        return 0;
}
