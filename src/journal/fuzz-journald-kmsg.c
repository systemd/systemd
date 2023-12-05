/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald.h"
#include "journald-kmsg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(server_freep) Server *s = NULL;

        if (size == 0)
                return 0;

        fuzz_setup_logging();

        assert_se(server_new(&s) >= 0);
        dummy_server_init(s, data, size);
        dev_kmsg_record(s, s->buffer, size);

        return 0;
}
