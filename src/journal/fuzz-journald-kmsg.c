/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fuzz.h"
#include "fuzz-journald.h"
#include "journald-kmsg.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_(manager_freep) Manager *m = NULL;

        if (size == 0)
                return 0;

        fuzz_setup_logging();

        assert_se(manager_new(&m, NULL) >= 0);
        dummy_manager_init(m, data, size);
        dev_kmsg_record(m, m->buffer, size);

        return 0;
}
