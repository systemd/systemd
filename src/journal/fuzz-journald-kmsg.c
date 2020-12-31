/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald.h"
#include "journald-kmsg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        Server s;

        if (size == 0)
                return 0;

        dummy_server_init(&s, data, size);
        dev_kmsg_record(&s, s.buffer, size);
        server_done(&s);

        return 0;
}
